import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from config import config
from src.alert_schema import SOURCE_TYPES, utc_iso


FAILURE_TYPES = ("parser", "schema", "unsupported")
INGESTION_HEALTH_SOURCES = ("WINDOWS_EVENT",)
MAX_PREVIEW_CHARS = 512
MAX_REASON_CHARS = 500
_SECRET_NAME = r"password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie"
_SECRET_KEY = re.compile(_SECRET_NAME, re.IGNORECASE)
_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_ASSIGNMENT = re.compile(
    rf"(?i)\b({_SECRET_NAME})(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&<]+)"
)
_XML_DATA = re.compile(
    rf"(?is)(Name=[\"'](?:{_SECRET_NAME})[\"'][^>]*>).*?(<)"
)
_XML_TAG = re.compile(
    rf"(?is)(<(?:{_SECRET_NAME})\b[^>]*>).*?(</(?:{_SECRET_NAME})\s*>)"
)
_URL_CREDENTIALS = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS ingestion_failures (
    failure_id TEXT PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    source_type TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    failure_type TEXT NOT NULL CHECK(failure_type IN ('parser', 'schema', 'unsupported')),
    reason TEXT NOT NULL,
    payload_preview TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ingestion_failures_occurred_at
ON ingestion_failures(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ingestion_failures_type
ON ingestion_failures(failure_type, occurred_at DESC);

CREATE TABLE IF NOT EXISTS ingestion_health (
    source_type TEXT PRIMARY KEY,
    events_received INTEGER NOT NULL DEFAULT 0,
    events_normalized INTEGER NOT NULL DEFAULT 0,
    events_rejected INTEGER NOT NULL DEFAULT 0,
    events_deduplicated INTEGER NOT NULL DEFAULT 0,
    processing_seconds REAL NOT NULL DEFAULT 0,
    collector_last_seen_at TEXT
);
"""


def _redact_text(value) -> str:
    text = str(value)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", text)
    text = _XML_DATA.sub(r"\1[REDACTED]\2", text)
    text = _XML_TAG.sub(r"\1[REDACTED]\2", text)
    return _URL_CREDENTIALS.sub(r"\1[REDACTED]@", text)


def _redact(value):
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SECRET_KEY.search(str(key)) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return _redact_text(value) if isinstance(value, str) else value


def _preview(payload) -> str:
    try:
        text = json.dumps(_redact(payload), ensure_ascii=False, sort_keys=True)
    except (RecursionError, TypeError, ValueError):
        text = _redact_text(type(payload).__name__)
    return text[:MAX_PREVIEW_CHARS]


def _connect():
    path = Path(config.SQLITE_ALERT_DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.executescript(_SCHEMA)
    return connection


def _cutoff(now=None) -> str:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return utc_iso(now - timedelta(days=config.INGESTION_FAILURE_RETENTION_DAYS))


def record_ingestion_failure(
    failure_type, reason, payload, *, source_type="WINDOWS_EVENT",
    collector_id="unknown", occurred_at=None,
) -> dict:
    failure_type = str(failure_type).lower()
    if failure_type not in FAILURE_TYPES:
        raise ValueError("ingestion failure_type is invalid")
    record = {
        "failure_id": f"ING-{uuid4()}",
        "occurred_at": utc_iso(occurred_at),
        "source_type": str(source_type)[:64],
        "collector_id": str(collector_id)[:128],
        "failure_type": failure_type,
        "reason": _redact_text(reason)[:MAX_REASON_CHARS],
        "payload_preview": _preview(payload),
    }
    with _connect() as connection:
        connection.execute(
            "DELETE FROM ingestion_failures WHERE datetime(occurred_at) < datetime(?)",
            (_cutoff(),),
        )
        connection.execute(
            """
            INSERT INTO ingestion_failures (
                failure_id, occurred_at, source_type, collector_id,
                failure_type, reason, payload_preview
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(record.values()),
        )
    return record


def get_ingestion_failure_diagnostics(limit=20, now=None) -> dict:
    limit = min(100, max(0, int(limit)))
    with _connect() as connection:
        connection.execute(
            "DELETE FROM ingestion_failures WHERE datetime(occurred_at) < datetime(?)",
            (_cutoff(now),),
        )
        counts = dict(connection.execute(
            "SELECT failure_type, COUNT(*) FROM ingestion_failures GROUP BY failure_type"
        ).fetchall())
        rows = connection.execute(
            """
            SELECT failure_id, occurred_at, source_type, collector_id,
                   failure_type, reason, payload_preview
            FROM ingestion_failures ORDER BY datetime(occurred_at) DESC LIMIT ?
            """,
            (limit,),
        ).fetchall() if limit else []
    keys = (
        "failure_id", "occurred_at", "source_type", "collector_id",
        "failure_type", "reason", "payload_preview",
    )
    normalized = {failure_type: int(counts.get(failure_type, 0)) for failure_type in FAILURE_TYPES}
    return {
        "retention_days": config.INGESTION_FAILURE_RETENTION_DAYS,
        "total": sum(normalized.values()),
        "counts": normalized,
        "recent": [dict(zip(keys, row)) for row in rows],
    }


def record_ingestion_health(summary, source_type, processing_seconds) -> None:
    source_type = str(source_type).strip().upper()
    if source_type not in SOURCE_TYPES:
        raise ValueError("ingestion health source_type is invalid")
    received = max(0, int(summary.get("read") or 0))
    imported = max(0, int(summary.get("imported") or 0))
    duplicates = max(0, int(summary.get("duplicates") or 0))
    rejected = max(0, int(summary.get("errors") or 0)) + max(
        0, int(summary.get("unsupported") or 0)
    )
    normalized = imported + duplicates
    last_seen_at = utc_iso() if received else None
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO ingestion_health (
                source_type, events_received, events_normalized, events_rejected,
                events_deduplicated, processing_seconds, collector_last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_type) DO UPDATE SET
                events_received=events_received + excluded.events_received,
                events_normalized=events_normalized + excluded.events_normalized,
                events_rejected=events_rejected + excluded.events_rejected,
                events_deduplicated=events_deduplicated + excluded.events_deduplicated,
                processing_seconds=processing_seconds + excluded.processing_seconds,
                collector_last_seen_at=COALESCE(
                    excluded.collector_last_seen_at, collector_last_seen_at
                )
            """,
            (
                source_type, received, normalized, rejected, duplicates,
                max(0.0, float(processing_seconds)), last_seen_at,
            ),
        )


def get_ingestion_health_metrics(now=None) -> dict:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT source_type, events_received, events_normalized, events_rejected,
                   events_deduplicated, processing_seconds, collector_last_seen_at
            FROM ingestion_health
            """
        ).fetchall()
    result = {
        source_type: {
            "events_received_total": 0,
            "events_normalized_total": 0,
            "events_rejected_total": 0,
            "events_deduplicated_total": 0,
            "event_processing_seconds": 0.0,
            "collector_last_seen_seconds": None,
        }
        for source_type in INGESTION_HEALTH_SOURCES
    }
    for source_type, received, normalized, rejected, deduplicated, seconds, last_seen in rows:
        try:
            seen = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
            age = max(0.0, (now.astimezone(timezone.utc) - seen.astimezone(timezone.utc)).total_seconds())
        except (TypeError, ValueError):
            age = None
        result[source_type] = {
            "events_received_total": int(received),
            "events_normalized_total": int(normalized),
            "events_rejected_total": int(rejected),
            "events_deduplicated_total": int(deduplicated),
            "event_processing_seconds": max(0.0, float(seconds)),
            "collector_last_seen_seconds": age,
        }
    return result
