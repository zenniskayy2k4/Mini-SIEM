import json
import math
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from config import config
from src.alert_schema import SOURCE_TYPES, utc_iso
from src.event_envelope import normalize_collector_id
from src.sqlite_store import ensure_database_schema


FAILURE_TYPES = ("parser", "schema", "unsupported")
INGESTION_HEALTH_SOURCES = ("WINDOWS_EVENT",)
MAX_PREVIEW_CHARS = 512
MAX_REASON_CHARS = 500
MAX_COLLECTOR_HEARTBEATS = 100
BUFFER_DIAGNOSTIC_FIELDS = {
    "buffered_events", "buffer_oldest_age", "retry_attempts", "delivery_failures",
}
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
    ensure_database_schema(connection)
    return connection


def _cutoff(now=None) -> str:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return utc_iso(now - timedelta(days=config.INGESTION_FAILURE_RETENTION_DAYS))


def _collector_text(value, field, max_length) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    value = value.strip()
    if not value or len(value) > max_length or any(not character.isprintable() for character in value):
        raise ValueError(f"{field} must contain 1 to {max_length} printable characters")
    return value


def _buffer_diagnostics(value) -> tuple[bool, dict]:
    if value is None:
        return False, {
            "buffered_events": 0,
            "buffer_oldest_age": None,
            "retry_attempts": 0,
            "delivery_failures": 0,
        }
    if not isinstance(value, dict) or set(value) != BUFFER_DIAGNOSTIC_FIELDS:
        raise ValueError("buffer_diagnostics must contain all supported metrics")
    counts = {}
    for field, maximum in (
        ("buffered_events", 500),
        ("retry_attempts", 2**63 - 1),
        ("delivery_failures", 2**63 - 1),
    ):
        item = value[field]
        if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= maximum:
            raise ValueError(f"{field} is outside its supported range")
        counts[field] = item
    age = value["buffer_oldest_age"]
    if age is not None and (
        isinstance(age, bool) or not isinstance(age, (int, float))
        or not math.isfinite(age) or not 0 <= age <= 315_360_000
    ):
        raise ValueError("buffer_oldest_age is outside its supported range")
    if (counts["buffered_events"] == 0) != (age is None):
        raise ValueError("buffer_oldest_age must be set only when events are buffered")
    return True, {**counts, "buffer_oldest_age": float(age) if age is not None else None}


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


def record_collector_heartbeat(
    collector_id, *, events_received=0, endpoint_available=True,
    source_type="WINDOWS_EVENT", collector_version="legacy", hostname=None,
    buffer_diagnostics=None, now=None,
) -> dict:
    collector_id = normalize_collector_id(collector_id)
    collector_version = _collector_text(collector_version, "collector_version", 64)
    hostname = _collector_text(
        collector_id if hostname is None else hostname, "hostname", 255,
    )
    source_type = str(source_type).strip().upper()
    if source_type not in SOURCE_TYPES:
        raise ValueError("collector heartbeat source_type is invalid")
    if not isinstance(endpoint_available, bool):
        raise ValueError("endpoint_available must be boolean")
    events_received = max(0, int(events_received))
    metrics_reported, buffer = _buffer_diagnostics(buffer_diagnostics)
    buffered_events = max(0, buffer["buffered_events"] - events_received)
    buffer_oldest_age = buffer["buffer_oldest_age"] if buffered_events else None
    heartbeat_at = utc_iso(now)
    event_at = heartbeat_at if events_received else None
    with _connect() as connection:
        cursor = connection.execute(
            """
            INSERT INTO collector_heartbeats (
                source_type, collector_id, last_heartbeat_at, last_event_at,
                last_batch_events, endpoint_available, collector_version,
                hostname, duplicate_id_warning, buffered_events,
                buffer_oldest_age, retry_attempts, delivery_failures,
                last_successful_delivery
            )
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?
            WHERE EXISTS (
                SELECT 1 FROM collector_heartbeats
                WHERE source_type = ? AND collector_id = ?
            ) OR (SELECT COUNT(*) FROM collector_heartbeats) < ?
            ON CONFLICT(source_type, collector_id) DO UPDATE SET
                last_heartbeat_at=excluded.last_heartbeat_at,
                last_event_at=COALESCE(excluded.last_event_at, last_event_at),
                last_batch_events=excluded.last_batch_events,
                endpoint_available=excluded.endpoint_available,
                collector_version=CASE
                    WHEN collector_heartbeats.hostname = 'unknown'
                        OR (
                            lower(collector_heartbeats.hostname) = lower(excluded.hostname)
                            AND excluded.collector_version != 'legacy'
                        )
                        THEN excluded.collector_version
                    ELSE collector_heartbeats.collector_version
                END,
                hostname=CASE
                    WHEN collector_heartbeats.hostname = 'unknown' THEN excluded.hostname
                    ELSE collector_heartbeats.hostname
                END,
                duplicate_id_warning=CASE
                    WHEN lower(collector_heartbeats.hostname) NOT IN ('unknown', lower(excluded.hostname))
                        THEN 1
                    ELSE collector_heartbeats.duplicate_id_warning
                END,
                buffered_events=CASE WHEN ? THEN excluded.buffered_events
                    ELSE collector_heartbeats.buffered_events END,
                buffer_oldest_age=CASE WHEN ? THEN excluded.buffer_oldest_age
                    WHEN collector_heartbeats.buffered_events > 0
                        AND collector_heartbeats.buffer_oldest_age IS NOT NULL
                        THEN collector_heartbeats.buffer_oldest_age + max(
                            0, (julianday(excluded.last_heartbeat_at)
                                - julianday(collector_heartbeats.last_heartbeat_at)) * 86400.0
                        )
                    ELSE collector_heartbeats.buffer_oldest_age END,
                retry_attempts=CASE WHEN ? THEN excluded.retry_attempts
                    ELSE collector_heartbeats.retry_attempts END,
                delivery_failures=CASE WHEN ? THEN excluded.delivery_failures
                    ELSE collector_heartbeats.delivery_failures END,
                last_successful_delivery=excluded.last_successful_delivery
            """,
            (
                source_type, collector_id, heartbeat_at, event_at,
                events_received, int(endpoint_available), collector_version, hostname,
                buffered_events, buffer_oldest_age, buffer["retry_attempts"],
                buffer["delivery_failures"], heartbeat_at,
                source_type, collector_id, MAX_COLLECTOR_HEARTBEATS,
                *((int(metrics_reported),) * 4),
            ),
        )
        if cursor.rowcount != 1:
            raise ValueError("collector heartbeat limit reached")
        connection.execute(
            """
            INSERT INTO ingestion_health (source_type, collector_last_seen_at)
            VALUES (?, ?)
            ON CONFLICT(source_type) DO UPDATE SET
                collector_last_seen_at=excluded.collector_last_seen_at
            """,
            (source_type, heartbeat_at),
        )
        row = connection.execute(
            """
            SELECT collector_version, hostname, duplicate_id_warning,
                   buffered_events, buffer_oldest_age, retry_attempts,
                   delivery_failures, last_successful_delivery
            FROM collector_heartbeats
            WHERE source_type = ? AND collector_id = ?
            """,
            (source_type, collector_id),
        ).fetchone()
    return {
        "collector_id": collector_id,
        "collector_version": row[0],
        "hostname": row[1],
        "source_type": source_type,
        "last_seen": heartbeat_at,
        "duplicate_id_warning": bool(row[2]),
        "buffered_events": row[3],
        "buffer_oldest_age": row[4],
        "retry_attempts": row[5],
        "delivery_failures": row[6],
        "last_successful_delivery": row[7],
    }


def get_collector_gap_diagnostics(now=None, stale_seconds=None) -> dict:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    stale_seconds = max(10, int(
        stale_seconds if stale_seconds is not None
        else config.WINDOWS_COLLECTOR_STALE_SECONDS
    ))
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT source_type, collector_id, last_heartbeat_at, last_event_at,
                   last_batch_events, endpoint_available, collector_version,
                   hostname, duplicate_id_warning, buffered_events,
                   buffer_oldest_age, retry_attempts, delivery_failures,
                   last_successful_delivery
            FROM collector_heartbeats
            ORDER BY source_type, collector_id
            """
        ).fetchall()

    collectors = []
    for (
        source_type, collector_id, heartbeat_at, event_at, event_count,
        endpoint_available, collector_version, hostname, duplicate_id_warning,
        buffered_events, buffer_oldest_age, retry_attempts, delivery_failures,
        last_successful_delivery,
    ) in rows:
        heartbeat = datetime.fromisoformat(heartbeat_at.replace("Z", "+00:00"))
        heartbeat_age = max(0.0, (now.astimezone(timezone.utc) - heartbeat).total_seconds())
        event_age = None
        if event_at:
            event = datetime.fromisoformat(event_at.replace("Z", "+00:00"))
            event_age = max(0.0, (now.astimezone(timezone.utc) - event).total_seconds())
        status = (
            "offline" if heartbeat_age > stale_seconds
            else "endpoint_unavailable" if not endpoint_available
            else "idle" if not event_count
            else "healthy"
        )
        collectors.append({
            "source_type": source_type,
            "collector_id": collector_id,
            "collector_version": collector_version,
            "hostname": hostname,
            "status": status,
            "last_seen": heartbeat_at,
            "last_heartbeat_at": heartbeat_at,
            "last_event_at": event_at,
            "heartbeat_age_seconds": round(heartbeat_age, 1),
            "last_event_age_seconds": round(event_age, 1) if event_age is not None else None,
            "endpoint_available": bool(endpoint_available),
            "duplicate_id_warning": bool(duplicate_id_warning),
            "buffered_events": buffered_events,
            "buffer_oldest_age": (
                round(buffer_oldest_age + heartbeat_age, 1)
                if buffered_events and buffer_oldest_age is not None else None
            ),
            "retry_attempts": retry_attempts,
            "delivery_failures": delivery_failures,
            "last_successful_delivery": last_successful_delivery,
        })

    states = {collector["status"] for collector in collectors}
    status = (
        "offline" if not collectors or "offline" in states
        else "endpoint_unavailable" if "endpoint_unavailable" in states
        else "healthy" if "healthy" in states
        else "idle"
    )
    return {
        "status": status,
        "stale_after_seconds": stale_seconds,
        "collectors": collectors,
    }
