import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from uuid import uuid4

from config import config
from src.alert_schema import utc_iso
from src.assets import normalize_ip_address, validate_asset
from src.audit import append_audit_event


CORE_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    alert_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_type TEXT NOT NULL,
    incident_id TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(json_extract(payload_json, '$.rule_id'));

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL UNIQUE REFERENCES alerts(alert_id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    assigned_to TEXT,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_events_timestamp ON incident_events(timestamp DESC);

CREATE TABLE IF NOT EXISTS analyst_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    note_text TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detection_feedback (
    feedback_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    classification TEXT NOT NULL CHECK(
        classification IN ('TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN_EXPECTED')
    ),
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detection_feedback_alert
ON detection_feedback(alert_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_detection_feedback_rule
ON detection_feedback(rule_id, created_at DESC);

CREATE TABLE IF NOT EXISTS detection_exceptions (
    exception_id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL CHECK(scope_type IN (
        'hostname', 'source_ip', 'user', 'process_path', 'rule_id', 'asset_id'
    )),
    scope_value TEXT NOT NULL,
    reason TEXT NOT NULL,
    creator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_detection_exceptions_active
ON detection_exceptions(scope_type, scope_value, expires_at);

CREATE TABLE IF NOT EXISTS alert_suppression_policies (
    policy_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    correlation_key TEXT NOT NULL,
    window_seconds INTEGER NOT NULL CHECK(window_seconds BETWEEN 1 AND 86400),
    creator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(rule_id, correlation_key)
);
CREATE INDEX IF NOT EXISTS idx_alert_suppression_policy_scope
ON alert_suppression_policies(rule_id, correlation_key);

CREATE TABLE IF NOT EXISTS response_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL COLLATE NOCASE UNIQUE,
    os TEXT NOT NULL,
    owner TEXT NOT NULL,
    department TEXT NOT NULL,
    environment TEXT NOT NULL CHECK(environment IN ('dev', 'test', 'prod')),
    criticality TEXT NOT NULL CHECK(criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    tags_json TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS asset_ip_addresses (
    asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL UNIQUE,
    PRIMARY KEY (asset_id, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_asset_ip_address ON asset_ip_addresses(ip_address);
"""

INGESTION_SCHEMA = """
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

CREATE TABLE IF NOT EXISTS collector_heartbeats (
    source_type TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    last_heartbeat_at TEXT NOT NULL,
    last_event_at TEXT,
    last_batch_events INTEGER NOT NULL DEFAULT 0,
    endpoint_available INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (source_type, collector_id)
);
"""

BASELINE_SCHEMA = CORE_SCHEMA + INGESTION_SCHEMA

SCHEMA_MIGRATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY CHECK(version > 0),
    name TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL,
    checksum TEXT NOT NULL CHECK(length(checksum) = 64)
);
"""
BASELINE_VERSION = 1
BASELINE_NAME = "baseline_v0.7.0"
BASELINE_CHECKSUM = hashlib.sha256(BASELINE_SCHEMA.encode("utf-8")).hexdigest()
QUERY_INDEX_SCHEMA = """
DROP INDEX IF EXISTS idx_alerts_timestamp;
DROP INDEX IF EXISTS idx_alerts_severity;
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp_id
ON alerts(timestamp DESC, alert_id DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_timestamp_id
ON alerts(severity, timestamp DESC, alert_id DESC);
CREATE INDEX IF NOT EXISTS idx_incident_events_type_timestamp
ON incident_events(event_type, timestamp);
"""
QUERY_INDEX_VERSION = 2
QUERY_INDEX_NAME = "query_indexes_v0.9.0"
QUERY_INDEX_CHECKSUM = hashlib.sha256(QUERY_INDEX_SCHEMA.encode("utf-8")).hexdigest()
COLLECTOR_IDENTITY_SCHEMA = """
ALTER TABLE collector_heartbeats
ADD COLUMN collector_version TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE collector_heartbeats
ADD COLUMN hostname TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE collector_heartbeats
ADD COLUMN duplicate_id_warning INTEGER NOT NULL DEFAULT 0
CHECK(duplicate_id_warning IN (0, 1));
"""
COLLECTOR_IDENTITY_VERSION = 3
COLLECTOR_IDENTITY_NAME = "collector_identity_v0.9.0"
COLLECTOR_IDENTITY_CHECKSUM = hashlib.sha256(
    COLLECTOR_IDENTITY_SCHEMA.encode("utf-8")
).hexdigest()
COLLECTOR_BUFFER_SCHEMA = """
ALTER TABLE collector_heartbeats
ADD COLUMN buffered_events INTEGER NOT NULL DEFAULT 0 CHECK(buffered_events >= 0);
ALTER TABLE collector_heartbeats
ADD COLUMN buffer_oldest_age REAL CHECK(buffer_oldest_age IS NULL OR buffer_oldest_age >= 0);
ALTER TABLE collector_heartbeats
ADD COLUMN retry_attempts INTEGER NOT NULL DEFAULT 0 CHECK(retry_attempts >= 0);
ALTER TABLE collector_heartbeats
ADD COLUMN delivery_failures INTEGER NOT NULL DEFAULT 0 CHECK(delivery_failures >= 0);
ALTER TABLE collector_heartbeats
ADD COLUMN last_successful_delivery TEXT;
"""
COLLECTOR_BUFFER_VERSION = 4
COLLECTOR_BUFFER_NAME = "collector_buffer_diagnostics_v0.9.0"
COLLECTOR_BUFFER_CHECKSUM = hashlib.sha256(
    COLLECTOR_BUFFER_SCHEMA.encode("utf-8")
).hexdigest()
MIGRATIONS = (
    (BASELINE_VERSION, BASELINE_NAME, BASELINE_CHECKSUM, BASELINE_SCHEMA),
    (QUERY_INDEX_VERSION, QUERY_INDEX_NAME, QUERY_INDEX_CHECKSUM, QUERY_INDEX_SCHEMA),
    (
        COLLECTOR_IDENTITY_VERSION,
        COLLECTOR_IDENTITY_NAME,
        COLLECTOR_IDENTITY_CHECKSUM,
        COLLECTOR_IDENTITY_SCHEMA,
    ),
    (
        COLLECTOR_BUFFER_VERSION,
        COLLECTOR_BUFFER_NAME,
        COLLECTOR_BUFFER_CHECKSUM,
        COLLECTOR_BUFFER_SCHEMA,
    ),
)


def ensure_database_schema(connection):
    try:
        has_history = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone()
        if has_history:
            expected = {version: (name, checksum) for version, name, checksum, _ in MIGRATIONS}
            recorded = connection.execute(
                "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
            ).fetchall()
            if not recorded or any(expected.get(row[0]) != row[1:] for row in recorded):
                raise RuntimeError("Database migration history does not match this build")
            return
        connection.executescript(
            "BEGIN IMMEDIATE;\n" + BASELINE_SCHEMA + SCHEMA_MIGRATIONS_TABLE
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO schema_migrations (
                version, name, applied_at, checksum
            ) VALUES (?, ?, ?, ?)
            """,
            (BASELINE_VERSION, BASELINE_NAME, utc_iso(), BASELINE_CHECKSUM),
        )
        recorded = connection.execute(
            "SELECT name, checksum FROM schema_migrations WHERE version = ?",
            (BASELINE_VERSION,),
        ).fetchone()
        if recorded != (BASELINE_NAME, BASELINE_CHECKSUM):
            raise RuntimeError("Database baseline migration does not match this build")
    except Exception:
        connection.rollback()
        raise
    connection.commit()


class _SQLiteRepository:
    def __init__(self, path=None):
        self._path = path
        self._schema_path = None
        self._schema_lock = threading.Lock()

    @property
    def path(self):
        return self._path or config.SQLITE_ALERT_DB

    def _connect(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def ensure_schema(self):
        if self._schema_path == self.path and os.path.exists(self.path):
            return
        with self._schema_lock:
            if self._schema_path == self.path and os.path.exists(self.path):
                return
            with self._connect() as connection:
                ensure_database_schema(connection)
            self._schema_path = self.path


class SQLiteAlertRepository(_SQLiteRepository):

    FEEDBACK_CLASSIFICATIONS = {
        "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_EXPECTED",
    }
    MAX_FEEDBACK_REASON_LENGTH = 2000
    EXCEPTION_SCOPES = {
        "hostname", "source_ip", "user", "process_path", "rule_id", "asset_id",
    }
    MAX_EXCEPTION_REASON_LENGTH = 2000
    MAX_EXCEPTION_VALUE_LENGTH = 500
    MAX_SUPPRESSION_RULE_ID_LENGTH = 200
    MAX_SUPPRESSION_KEY_LENGTH = 500

    @staticmethod
    def _write_alert(connection, alert):
        payload = json.dumps(alert, ensure_ascii=False)
        connection.execute(
            """
            INSERT INTO alerts (
                alert_id, timestamp, alert_name, severity, source_type,
                incident_id, payload_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                timestamp=excluded.timestamp,
                alert_name=excluded.alert_name,
                severity=excluded.severity,
                source_type=excluded.source_type,
                incident_id=excluded.incident_id,
                payload_json=excluded.payload_json,
                created_at=excluded.created_at,
                updated_at=excluded.updated_at
            """,
            (
                alert["alert_id"], alert["timestamp"], alert["alert_name"],
                alert["severity"], alert["source_type"], alert.get("incident_id"),
                payload, alert.get("created_at"), alert["updated_at"],
            ),
        )
        SQLiteAlertRepository._sync_incident(connection, alert)

    def create_alerts(self, alerts) -> list[dict]:
        alerts = list(alerts)
        if not alerts:
            return alerts
        self.ensure_schema()
        with self._connect() as connection:
            for alert in alerts:
                self._write_alert(connection, alert)
        return alerts

    def create_alert(self, alert: dict) -> dict:
        self.create_alerts((alert,))
        return alert

    @staticmethod
    def _sync_incident(connection, alert):
        incident_id = alert.get("incident_id")
        if not incident_id:
            connection.execute("DELETE FROM incidents WHERE alert_id = ?", (alert["alert_id"],))
            return

        connection.execute(
            "DELETE FROM incidents WHERE alert_id = ? AND incident_id != ?",
            (alert["alert_id"], incident_id),
        )
        connection.execute(
            """
            INSERT INTO incidents (
                incident_id, alert_id, status, assigned_to, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                alert_id=excluded.alert_id,
                status=excluded.status,
                assigned_to=excluded.assigned_to,
                created_at=excluded.created_at,
                updated_at=excluded.updated_at
            """,
            (
                incident_id, alert["alert_id"], alert.get("incident_status") or "NEW",
                alert.get("assigned_to"), alert.get("created_at"), alert.get("updated_at"),
            ),
        )
        connection.execute("DELETE FROM incident_events WHERE incident_id = ?", (incident_id,))
        connection.executemany(
            """
            INSERT INTO incident_events (incident_id, event_type, timestamp, payload_json)
            VALUES (?, ?, ?, ?)
            """,
            [
                (
                    incident_id, event.get("event_type", "UPDATED"), event.get("timestamp", ""),
                    json.dumps(event, ensure_ascii=False),
                )
                for event in alert.get("timeline") or []
            ],
        )
        connection.execute("DELETE FROM analyst_notes WHERE incident_id = ?", (incident_id,))
        connection.executemany(
            """
            INSERT INTO analyst_notes (incident_id, author, note_text, timestamp)
            VALUES (?, ?, ?, ?)
            """,
            [
                (
                    incident_id, note.get("author", "analyst"), note.get("text", ""),
                    note.get("timestamp", ""),
                )
                for note in alert.get("analyst_notes") or []
            ],
        )
        connection.execute("DELETE FROM response_actions WHERE incident_id = ?", (incident_id,))
        connection.executemany(
            """
            INSERT INTO response_actions (
                incident_id, action_type, status, timestamp, payload_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    incident_id, action["action_type"], action["status"],
                    action["created_at"], json.dumps(action, ensure_ascii=False),
                )
                for action in alert.get("response_actions") or []
            ],
        )

    def update_alert(self, alert_id: str, changes) -> dict | None:
        alert = self.get_alert(alert_id)
        if alert is None:
            return None
        changes(alert) if callable(changes) else alert.update(changes)
        return self.create_alert(alert)

    def get_alert(self, alert_id: str) -> dict | None:
        self.ensure_schema()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM alerts WHERE alert_id = ?", (alert_id,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list_alerts(
        self, filters: dict | None = None, limit: int | None = None, offset: int = 0,
    ) -> list[dict]:
        return self.search_alerts(filters, limit, offset)["items"]

    @staticmethod
    def _query(filters):
        filters = filters or {}
        clauses = []
        values = []

        def exact(sql, value):
            if value:
                clauses.append(sql)
                values.append(value)

        def contains(sql, value):
            if value:
                escaped = str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                clauses.append(sql)
                values.append(f"%{escaped}%")

        exact("a.severity = UPPER(?)", filters.get("severity"))
        exact(
            "UPPER(COALESCE(i.status, json_extract(a.payload_json, '$.incident_status'), '')) = UPPER(?)",
            filters.get("incident_status"),
        )
        exact(
            "UPPER(COALESCE(json_extract(a.payload_json, '$.ai_disposition'), '')) = UPPER(?)",
            filters.get("ai_disposition"),
        )
        exact(
            "UPPER(COALESCE(i.assigned_to, json_extract(a.payload_json, '$.assigned_to'), '')) = UPPER(?)",
            filters.get("assigned_to"),
        )
        if filters.get("unassigned"):
            clauses.append(
                "TRIM(COALESCE(i.assigned_to, json_extract(a.payload_json, '$.assigned_to'), '')) = ''"
            )
        if filters.get("open_incidents"):
            clauses.append(
                "COALESCE(i.incident_id, json_extract(a.payload_json, '$.incident_id')) IS NOT NULL "
                "AND UPPER(COALESCE(i.status, json_extract(a.payload_json, '$.incident_status'), '')) "
                "NOT IN ('RESOLVED', 'FALSE_POSITIVE')"
            )
        contains(
            "COALESCE(json_extract(a.payload_json, '$.ip_address'), '') LIKE ? ESCAPE '\\'",
            filters.get("ip"),
        )
        contains(
            "UPPER(COALESCE(json_extract(a.payload_json, '$.mitre_attck_id'), '')) LIKE UPPER(?) ESCAPE '\\'",
            filters.get("mitre"),
        )
        if filters.get("from"):
            clauses.append("a.timestamp >= ?")
            values.append(filters["from"])
        if filters.get("to"):
            clauses.append("a.timestamp <= ?")
            values.append(filters["to"])
        if filters.get("q"):
            escaped = str(filters["q"]).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append(
                "LOWER(COALESCE(json_extract(a.payload_json, '$.alert_name'), '') || ' ' || "
                "COALESCE(json_extract(a.payload_json, '$.description'), '') || ' ' || "
                "COALESCE(json_extract(a.payload_json, '$.raw_log'), '')) LIKE LOWER(?) ESCAPE '\\'"
            )
            values.append(f"%{escaped}%")
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), values

    def search_alerts(
        self, filters: dict | None = None, limit: int | None = None, offset: int = 0,
    ) -> dict:
        self.ensure_schema()
        where, values = self._query(filters)
        source = " FROM alerts a LEFT JOIN incidents i ON i.alert_id = a.alert_id"
        offset = max(0, int(offset or 0))
        page = ""
        page_values = []
        if limit is not None:
            page = " LIMIT ? OFFSET ?"
            page_values = [max(0, int(limit)), offset]
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT a.payload_json" + source + where
                + " ORDER BY a.timestamp DESC, a.alert_id DESC" + page,
                values + page_values,
            ).fetchall()
            total = connection.execute(
                "SELECT COUNT(*)" + source + where, values,
            ).fetchone()[0]
            items = [json.loads(row[0]) for row in rows]
            if items:
                placeholders = ", ".join("?" for _ in items)
                feedback_rows = connection.execute(
                    f"""
                    SELECT feedback_id, alert_id, rule_id, classification, reason, actor, created_at
                    FROM detection_feedback
                    WHERE rowid IN (
                        SELECT MAX(rowid) FROM detection_feedback
                        WHERE alert_id IN ({placeholders}) GROUP BY alert_id
                    )
                    """,
                    [item["alert_id"] for item in items],
                ).fetchall()
                feedback = {row[1]: dict(zip(
                    ("feedback_id", "alert_id", "rule_id", "classification", "reason", "actor", "created_at"),
                    row,
                )) for row in feedback_rows}
                for item in items:
                    if item["alert_id"] in feedback:
                        item["detection_feedback"] = feedback[item["alert_id"]]
        return {"items": items, "total": total}

    def count_alerts(self, filters: dict | None = None) -> int:
        return self.search_alerts(filters, limit=0)["total"]

    def rule_hit_counts(self, rule_ids: list[str]) -> dict[str, int]:
        if not rule_ids:
            return {}
        self.ensure_schema()
        placeholders = ", ".join("?" for _ in rule_ids)
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT json_extract(payload_json, '$.rule_id'), COUNT(*)
                FROM alerts
                WHERE json_extract(payload_json, '$.rule_id') IN ({placeholders})
                GROUP BY json_extract(payload_json, '$.rule_id')
                """,
                rule_ids,
            ).fetchall()
        return {rule_id: int(count) for rule_id, count in rows}

    def create_detection_feedback(
        self, alert_id: str, classification: str, reason: str, actor: str, role=None,
    ) -> dict | None:
        if not isinstance(classification, str):
            raise ValueError("Invalid feedback classification")
        classification = classification.strip().upper()
        if classification not in self.FEEDBACK_CLASSIFICATIONS:
            raise ValueError("Invalid feedback classification")
        if not isinstance(reason, str):
            raise ValueError("Feedback reason must be text")
        reason = reason.strip()
        if classification == "FALSE_POSITIVE" and not reason:
            raise ValueError("Reason is required for false positive feedback")
        if len(reason) > self.MAX_FEEDBACK_REASON_LENGTH:
            raise ValueError(
                f"Feedback reason exceeds {self.MAX_FEEDBACK_REASON_LENGTH} characters"
            )
        if not isinstance(actor, str) or not actor.strip() or len(actor.strip()) > 100:
            raise ValueError("Invalid feedback actor")

        self.ensure_schema()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM alerts WHERE alert_id = ?", (alert_id,),
            ).fetchone()
            if row is None:
                return None
            rule_id = json.loads(row[0]).get("rule_id")
            if not isinstance(rule_id, str) or not rule_id.strip() or len(rule_id.strip()) > 200:
                raise ValueError("Alert has no valid detection rule")
            feedback = {
                "feedback_id": f"FB-{uuid4()}",
                "alert_id": alert_id,
                "rule_id": rule_id.strip(),
                "classification": classification,
                "reason": reason,
                "actor": actor.strip(),
                "created_at": utc_iso(),
            }
            connection.execute(
                """
                INSERT INTO detection_feedback (
                    feedback_id, alert_id, rule_id, classification, reason, actor, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(feedback.values()),
            )
            append_audit_event(
                "DETECTION_FEEDBACK_CREATED", feedback["actor"], role=role,
                target_type="detection_feedback", target_id=feedback["feedback_id"],
                details={
                    "alert_id": alert_id,
                    "rule_id": feedback["rule_id"],
                    "classification": classification,
                    "reason_length": len(reason),
                },
            )
        return feedback

    def rule_quality(self, from_timestamp: str, to_timestamp: str) -> list[dict]:
        self.ensure_schema()
        with self._connect() as connection:
            rows = connection.execute(
                """
                WITH scoped_alerts AS (
                    SELECT alert_id, json_extract(payload_json, '$.rule_id') AS rule_id
                    FROM alerts
                    WHERE created_at >= ? AND created_at < ?
                        AND json_extract(payload_json, '$.rule_id') IS NOT NULL
                )
                SELECT
                    scoped.rule_id,
                    COUNT(*),
                    COUNT(CASE WHEN feedback.classification = 'TRUE_POSITIVE' THEN 1 END),
                    COUNT(CASE WHEN feedback.classification = 'FALSE_POSITIVE' THEN 1 END),
                    COUNT(CASE WHEN feedback.classification = 'BENIGN_EXPECTED' THEN 1 END),
                    COUNT(CASE WHEN feedback.alert_id IS NULL THEN 1 END)
                FROM scoped_alerts scoped
                LEFT JOIN detection_feedback feedback ON feedback.rowid = (
                    SELECT MAX(rowid) FROM detection_feedback
                    WHERE alert_id = scoped.alert_id
                )
                GROUP BY scoped.rule_id
                ORDER BY COUNT(*) DESC, scoped.rule_id
                """,
                (from_timestamp, to_timestamp),
            ).fetchall()
        quality = []
        for rule_id, alerts, true_positive, false_positive, benign, unclassified in rows:
            classified = true_positive + false_positive + benign
            quality.append({
                "rule_id": str(rule_id),
                "alerts_generated": int(alerts),
                "true_positives": int(true_positive),
                "false_positives": int(false_positive),
                "benign_expected": int(benign),
                "unclassified": int(unclassified),
                "classified_sample_size": int(classified),
                "false_positive_rate_percent": (
                    round(100 * false_positive / classified, 2) if classified else None
                ),
            })
        return quality

    @classmethod
    def _exception_scope(cls, scope_type, scope_value) -> tuple[str, str]:
        if not isinstance(scope_type, str) or scope_type.strip().lower() not in cls.EXCEPTION_SCOPES:
            raise ValueError("Invalid detection exception scope")
        scope_type = scope_type.strip().lower()
        if not isinstance(scope_value, str):
            raise ValueError("Detection exception value must be text")
        scope_value = scope_value.strip()
        if not scope_value or len(scope_value) > cls.MAX_EXCEPTION_VALUE_LENGTH:
            raise ValueError("Invalid detection exception value")
        if any(character in scope_value for character in "*?[]"):
            raise ValueError("Broad wildcard detection exceptions are not allowed")
        if scope_type == "source_ip":
            try:
                scope_value = normalize_ip_address(scope_value)
            except ValueError as exc:
                raise ValueError("Detection exception source_ip must be one IP address") from exc
        if scope_type == "process_path" and not (
            scope_value.startswith("/")
            or (len(scope_value) > 2 and scope_value[1] == ":" and scope_value[2] in "\\/")
        ):
            raise ValueError("Detection exception process_path must be absolute")
        return scope_type, scope_value

    @staticmethod
    def _exception_expiry(expires_at) -> str | None:
        if expires_at is None or expires_at == "":
            return None
        if not isinstance(expires_at, str):
            raise ValueError("Detection exception expiry must be an ISO-8601 timestamp")
        try:
            normalized = utc_iso(expires_at.strip())
        except (TypeError, ValueError) as exc:
            raise ValueError("Detection exception expiry must be an ISO-8601 timestamp") from exc
        if normalized <= utc_iso():
            raise ValueError("Detection exception expiry must be in the future")
        return normalized

    def create_detection_exception(
        self, scope_type, scope_value, reason, creator, role=None, expires_at=None,
    ) -> dict:
        scope_type, scope_value = self._exception_scope(scope_type, scope_value)
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("Detection exception reason is required")
        reason = reason.strip()
        if len(reason) > self.MAX_EXCEPTION_REASON_LENGTH:
            raise ValueError(
                f"Detection exception reason exceeds {self.MAX_EXCEPTION_REASON_LENGTH} characters"
            )
        if not isinstance(creator, str) or not creator.strip() or len(creator.strip()) > 100:
            raise ValueError("Invalid detection exception creator")
        record = {
            "exception_id": f"DEX-{uuid4()}",
            "scope_type": scope_type,
            "scope_value": scope_value,
            "reason": reason,
            "creator": creator.strip(),
            "created_at": utc_iso(),
            "expires_at": self._exception_expiry(expires_at),
        }
        self.ensure_schema()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO detection_exceptions (
                    exception_id, scope_type, scope_value, reason, creator, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(record.values()),
            )
            append_audit_event(
                "DETECTION_EXCEPTION_CREATED", record["creator"], role=role,
                target_type="detection_exception", target_id=record["exception_id"],
                details={
                    "scope_type": scope_type,
                    "scope_value": scope_value,
                    "expires_at": record["expires_at"],
                    "reason_length": len(reason),
                },
            )
        return {**record, "active": True}

    def list_detection_exceptions(self) -> list[dict]:
        self.ensure_schema()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT exception_id, scope_type, scope_value, reason, creator, created_at, expires_at
                FROM detection_exceptions ORDER BY created_at DESC, rowid DESC
                """
            ).fetchall()
        now = utc_iso()
        columns = (
            "exception_id", "scope_type", "scope_value", "reason", "creator",
            "created_at", "expires_at",
        )
        return [
            {**dict(zip(columns, row)), "active": row[6] is None or row[6] > now}
            for row in rows
        ]

    def delete_detection_exception(self, exception_id, actor, role=None) -> bool:
        if not isinstance(exception_id, str) or not exception_id.startswith("DEX-"):
            raise ValueError("Invalid detection exception ID")
        if not isinstance(actor, str) or not actor.strip() or len(actor.strip()) > 100:
            raise ValueError("Invalid detection exception actor")
        self.ensure_schema()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT scope_type, scope_value FROM detection_exceptions WHERE exception_id = ?",
                (exception_id,),
            ).fetchone()
            if row is None:
                return False
            connection.execute(
                "DELETE FROM detection_exceptions WHERE exception_id = ?", (exception_id,),
            )
            append_audit_event(
                "DETECTION_EXCEPTION_DELETED", actor.strip(), role=role,
                target_type="detection_exception", target_id=exception_id,
                details={"scope_type": row[0], "scope_value": row[1]},
            )
        return True

    @staticmethod
    def _exception_candidates(alert: dict, scope_type: str) -> list[str]:
        if scope_type == "hostname":
            values = [alert.get("hostname"), alert.get("computer")]
        elif scope_type == "source_ip":
            values = [alert.get("ip_address")]
        elif scope_type == "user":
            values = [alert.get("user"), alert.get("username")]
            target_users = alert.get("target_users")
            if isinstance(target_users, (list, tuple, set)):
                values.extend(target_users)
        elif scope_type == "process_path":
            process = alert.get("process") if isinstance(alert.get("process"), dict) else {}
            target = alert.get("target_process") if isinstance(alert.get("target_process"), dict) else {}
            values = [alert.get("process_path"), process.get("image"), target.get("image")]
        elif scope_type == "rule_id":
            values = [alert.get("rule_id")]
        else:
            values = [alert.get("asset_id")]
        return [str(value).strip() for value in values if value is not None and str(value).strip()]

    def match_detection_exception(self, alert: dict) -> dict | None:
        if not isinstance(alert, dict):
            raise ValueError("Detection exception matching requires an alert object")
        now = utc_iso()
        self.ensure_schema()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT exception_id, scope_type, scope_value, reason, creator, created_at, expires_at
                FROM detection_exceptions
                WHERE expires_at IS NULL OR expires_at > ?
                ORDER BY created_at, rowid
                """,
                (now,),
            ).fetchall()
        columns = (
            "exception_id", "scope_type", "scope_value", "reason", "creator",
            "created_at", "expires_at",
        )
        for row in rows:
            record = dict(zip(columns, row))
            expected = record["scope_value"]
            candidates = self._exception_candidates(alert, record["scope_type"])
            if record["scope_type"] == "source_ip":
                normalized = []
                for candidate in candidates:
                    try:
                        normalized.append(normalize_ip_address(candidate))
                    except ValueError:
                        continue
                matched = expected in normalized
            else:
                matched = expected.casefold() in {candidate.casefold() for candidate in candidates}
            if matched:
                return {**record, "active": True, "matched_at": now}
        return None

    @classmethod
    def _suppression_scope(cls, rule_id, correlation_key) -> tuple[str, str]:
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError("Suppression policy rule_id is required")
        if not isinstance(correlation_key, str) or not correlation_key.strip():
            raise ValueError("Suppression policy correlation_key is required")
        rule_id, correlation_key = rule_id.strip(), correlation_key.strip()
        if len(rule_id) > cls.MAX_SUPPRESSION_RULE_ID_LENGTH:
            raise ValueError("Suppression policy rule_id is too long")
        if len(correlation_key) > cls.MAX_SUPPRESSION_KEY_LENGTH:
            raise ValueError("Suppression policy correlation_key is too long")
        if any(character in rule_id + correlation_key for character in "*?[]"):
            raise ValueError("Suppression policy wildcards are not allowed")
        return rule_id, correlation_key

    def create_alert_suppression_policy(
        self, rule_id, correlation_key, window_seconds, creator, role=None,
    ) -> dict:
        rule_id, correlation_key = self._suppression_scope(rule_id, correlation_key)
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, int):
            raise ValueError("Suppression window_seconds must be an integer")
        if not 1 <= window_seconds <= 86400:
            raise ValueError("Suppression window_seconds must be between 1 and 86400")
        if not isinstance(creator, str) or not creator.strip() or len(creator.strip()) > 100:
            raise ValueError("Invalid suppression policy creator")
        policy = {
            "policy_id": f"SUP-{uuid4()}",
            "rule_id": rule_id,
            "correlation_key": correlation_key,
            "window_seconds": window_seconds,
            "creator": creator.strip(),
            "created_at": utc_iso(),
        }
        self.ensure_schema()
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO alert_suppression_policies (
                        policy_id, rule_id, correlation_key, window_seconds, creator, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    tuple(policy.values()),
                )
                append_audit_event(
                    "ALERT_SUPPRESSION_POLICY_CREATED", policy["creator"], role=role,
                    target_type="alert_suppression_policy", target_id=policy["policy_id"],
                    details={
                        "rule_id": rule_id,
                        "correlation_key": correlation_key,
                        "window_seconds": window_seconds,
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("A suppression policy already exists for this exact scope") from exc
        return policy

    def list_alert_suppression_policies(self) -> list[dict]:
        self.ensure_schema()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT policy_id, rule_id, correlation_key, window_seconds, creator, created_at
                FROM alert_suppression_policies ORDER BY created_at DESC, rowid DESC
                """
            ).fetchall()
        columns = (
            "policy_id", "rule_id", "correlation_key", "window_seconds", "creator",
            "created_at",
        )
        return [dict(zip(columns, row)) for row in rows]

    def delete_alert_suppression_policy(self, policy_id, actor, role=None) -> bool:
        if not isinstance(policy_id, str) or not policy_id.startswith("SUP-"):
            raise ValueError("Invalid alert suppression policy ID")
        if not isinstance(actor, str) or not actor.strip() or len(actor.strip()) > 100:
            raise ValueError("Invalid suppression policy actor")
        self.ensure_schema()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT rule_id, correlation_key, window_seconds
                FROM alert_suppression_policies WHERE policy_id = ?
                """,
                (policy_id,),
            ).fetchone()
            if row is None:
                return False
            connection.execute(
                "DELETE FROM alert_suppression_policies WHERE policy_id = ?", (policy_id,),
            )
            append_audit_event(
                "ALERT_SUPPRESSION_POLICY_DELETED", actor.strip(), role=role,
                target_type="alert_suppression_policy", target_id=policy_id,
                details={
                    "rule_id": row[0], "correlation_key": row[1],
                    "window_seconds": row[2],
                },
            )
        return True

    @staticmethod
    def _suppression_time(value) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(utc_iso(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None

    def apply_alert_suppression(self, alert: dict) -> dict:
        if not isinstance(alert, dict):
            raise ValueError("Alert suppression requires an alert object")
        rule_id, correlation_key = alert.get("rule_id"), alert.get("correlation_key")
        if not isinstance(rule_id, str) or not isinstance(correlation_key, str):
            return {"alert": alert, "suppressed": False, "policy": None}
        self.ensure_schema()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT policy_id, rule_id, correlation_key, window_seconds, creator, created_at
                FROM alert_suppression_policies
                WHERE rule_id = ? AND correlation_key = ?
                """,
                (rule_id, correlation_key),
            ).fetchone()
            if row is None:
                return {"alert": alert, "suppressed": False, "policy": None}
            columns = (
                "policy_id", "rule_id", "correlation_key", "window_seconds", "creator",
                "created_at",
            )
            policy = dict(zip(columns, row))
            candidate = connection.execute(
                """
                SELECT payload_json FROM alerts
                WHERE alert_id != ?
                    AND json_extract(payload_json, '$.rule_id') = ?
                    AND json_extract(payload_json, '$.correlation_key') = ?
                    AND json_extract(payload_json, '$.suppression_policy.policy_id') = ?
                ORDER BY datetime(json_extract(payload_json, '$.last_seen')) DESC, rowid DESC
                LIMIT 1
                """,
                (alert.get("alert_id"), rule_id, correlation_key, policy["policy_id"]),
            ).fetchone()

        summary = {
            key: policy[key]
            for key in ("policy_id", "rule_id", "correlation_key", "window_seconds")
        }
        alert["suppression_policy"] = summary
        if int(alert.get("suppressed_count") or 0) > 0:
            return {"alert": alert, "suppressed": True, "policy": policy}
        if candidate is None:
            alert.setdefault("suppressed_count", 0)
            return {"alert": alert, "suppressed": False, "policy": policy}

        previous = json.loads(candidate[0])
        previous_seen = self._suppression_time(previous.get("last_seen") or previous.get("timestamp"))
        observed = self._suppression_time(alert.get("last_seen") or alert.get("timestamp"))
        if previous_seen is None or observed is None:
            return {"alert": alert, "suppressed": False, "policy": policy}
        elapsed = (observed - previous_seen).total_seconds()
        if elapsed < 0 or elapsed > policy["window_seconds"]:
            alert.setdefault("suppressed_count", 0)
            return {"alert": alert, "suppressed": False, "policy": policy}

        previous["suppression_policy"] = summary
        previous["suppressed_count"] = int(previous.get("suppressed_count") or 0) + 1
        previous["event_count"] = max(1, int(previous.get("event_count") or 1)) + max(
            1, int(alert.get("event_count") or 1),
        )
        previous["first_seen"] = min(
            previous.get("first_seen") or previous["timestamp"],
            alert.get("first_seen") or alert["timestamp"],
        )
        previous["last_seen"] = max(
            previous.get("last_seen") or previous["timestamp"],
            alert.get("last_seen") or alert["timestamp"],
        )
        previous["updated_at"] = utc_iso()
        return {"alert": previous, "suppressed": True, "policy": policy}

    def stats(self) -> dict:
        self.ensure_schema()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*),
                    SUM(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN UPPER(severity) = 'HIGH' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN UPPER(severity) = 'MEDIUM' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN UPPER(severity) IN ('LOW', 'INFO') THEN 1 ELSE 0 END),
                    SUM(CASE WHEN json_type(payload_json, '$.ml_anomaly_score') IS NOT NULL THEN 1 ELSE 0 END)
                FROM alerts
                """
            ).fetchone()
        return dict(zip(
            ("total", "critical", "high", "medium", "info", "anomalies"),
            (int(value or 0) for value in row),
        ))

    def soc_kpis(self, from_timestamp: str, to_timestamp: str) -> dict:
        self.ensure_schema()
        period = (from_timestamp, to_timestamp)
        with self._connect() as connection:
            alerts = connection.execute(
                """
                SELECT
                    COUNT(*),
                    COUNT(CASE WHEN julianday(created_at) >= julianday(timestamp) THEN 1 END),
                    AVG(CASE WHEN julianday(created_at) >= julianday(timestamp)
                        THEN (julianday(created_at) - julianday(timestamp)) * 86400 END),
                    SUM(CASE WHEN json_extract(payload_json, '$.ai_disposition') =
                        'REQUIRES_HUMAN_REVIEW' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN json_extract(payload_json, '$.ai_analysis.analysed_at')
                        IS NOT NULL THEN 1 ELSE 0 END),
                    SUM(CASE WHEN json_extract(payload_json, '$.ai_analysis.error') IS NOT NULL
                        OR json_extract(payload_json, '$.ai_analyst_error') IS NOT NULL
                        THEN 1 ELSE 0 END)
                FROM alerts
                WHERE created_at >= ? AND created_at < ?
                """,
                period,
            ).fetchone()
            incidents = connection.execute(
                """
                WITH scoped AS (
                    SELECT i.incident_id, i.status, i.created_at
                    FROM incidents i
                    JOIN alerts a ON a.alert_id = i.alert_id
                    WHERE a.created_at >= ? AND a.created_at < ?
                ),
                acknowledged AS (
                    SELECT e.incident_id, MIN(e.timestamp) AS acknowledged_at
                    FROM incident_events e
                    JOIN scoped s ON s.incident_id = e.incident_id
                    WHERE e.event_type IN ('STATUS_CHANGED', 'NOTE_ADDED', 'ASSIGNMENT_CHANGED')
                        OR e.event_type LIKE 'RESPONSE_ACTION_%'
                    GROUP BY e.incident_id
                ),
                resolved AS (
                    SELECT e.incident_id, MIN(e.timestamp) AS resolved_at
                    FROM incident_events e
                    JOIN scoped s ON s.incident_id = e.incident_id
                    WHERE e.event_type = 'STATUS_CHANGED'
                        AND json_extract(e.payload_json, '$.to_status') = 'RESOLVED'
                    GROUP BY e.incident_id
                )
                SELECT
                    COUNT(*),
                    SUM(CASE WHEN s.status IN ('NEW', 'INVESTIGATING', 'CONTAINED')
                        THEN 1 ELSE 0 END),
                    SUM(CASE WHEN s.status = 'RESOLVED' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN s.status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END),
                    COUNT(CASE WHEN julianday(k.acknowledged_at) >= julianday(s.created_at)
                        THEN 1 END),
                    AVG(CASE WHEN julianday(k.acknowledged_at) >= julianday(s.created_at)
                        THEN (julianday(k.acknowledged_at) - julianday(s.created_at)) * 86400 END),
                    COUNT(CASE WHEN julianday(r.resolved_at) >= julianday(s.created_at)
                        THEN 1 END),
                    AVG(CASE WHEN julianday(r.resolved_at) >= julianday(s.created_at)
                        THEN (julianday(r.resolved_at) - julianday(s.created_at)) * 86400 END)
                FROM scoped s
                LEFT JOIN acknowledged k ON k.incident_id = s.incident_id
                LEFT JOIN resolved r ON r.incident_id = s.incident_id
                """,
                period,
            ).fetchone()
            rules = connection.execute(
                """
                SELECT json_extract(payload_json, '$.rule_id'), COUNT(*)
                FROM alerts
                WHERE created_at >= ? AND created_at < ?
                    AND json_extract(payload_json, '$.rule_id') IS NOT NULL
                GROUP BY json_extract(payload_json, '$.rule_id')
                ORDER BY COUNT(*) DESC, json_extract(payload_json, '$.rule_id')
                """,
                period,
            ).fetchall()

        def measured(value, sample_size):
            available = int(sample_size or 0) > 0
            return {
                "available": available,
                "sample_size": int(sample_size or 0),
                "value": round(float(value), 2) if available else None,
            }

        def count(value, population):
            available = int(population or 0) > 0
            return {
                "available": available,
                "sample_size": int(population or 0),
                "value": int(value or 0) if available else None,
            }

        def rate(numerator, denominator):
            available = int(denominator or 0) > 0
            return {
                "available": available,
                "sample_size": int(denominator or 0),
                "value": round(100 * int(numerator or 0) / denominator, 2) if available else None,
            }

        closed = int(incidents[2] or 0) + int(incidents[3] or 0)
        ai_attempts = int(alerts[4] or 0) + int(alerts[5] or 0)
        rule_samples = sum(int(row[1]) for row in rules)
        return {
            "mttd_seconds": measured(alerts[2], alerts[1]),
            "mtta_seconds": measured(incidents[5], incidents[4]),
            "mttr_seconds": measured(incidents[7], incidents[6]),
            "open_incidents": count(incidents[1], incidents[0]),
            "resolved_incidents": count(incidents[2], incidents[0]),
            "false_positive_rate_percent": rate(incidents[3], closed),
            "alerts_per_rule": {
                "available": rule_samples > 0,
                "sample_size": rule_samples,
                "value": [
                    {"rule_id": rule_id, "alerts": int(total)} for rule_id, total in rules
                ] if rule_samples else None,
            },
            "human_review_rate_percent": rate(alerts[3], alerts[0]),
            "ai_enrichment_success_rate_percent": rate(alerts[4], ai_attempts),
        }

    def soc_analytics(self, from_timestamp: str, to_timestamp: str) -> dict:
        """Return bounded chart aggregates without loading alert payloads into Python."""
        self.ensure_schema()
        start = datetime.fromisoformat(from_timestamp.replace("Z", "+00:00"))
        end = datetime.fromisoformat(to_timestamp.replace("Z", "+00:00"))
        granularity = "hour" if end - start <= timedelta(days=2) else "day"
        bucket = "%Y-%m-%dT%H:00:00Z" if granularity == "hour" else "%Y-%m-%dT00:00:00Z"
        period = (from_timestamp, to_timestamp)
        with self._connect() as connection:
            alert_trend = connection.execute(
                """
                SELECT strftime(?, created_at), COUNT(*)
                FROM alerts
                WHERE created_at >= ? AND created_at < ?
                GROUP BY 1 ORDER BY 1
                """,
                (bucket, *period),
            ).fetchall()
            incident_distribution = connection.execute(
                """
                SELECT i.status, COUNT(*)
                FROM incidents i JOIN alerts a ON a.alert_id = i.alert_id
                WHERE a.created_at >= ? AND a.created_at < ?
                GROUP BY i.status ORDER BY COUNT(*) DESC, i.status
                """,
                period,
            ).fetchall()
            top_rules = connection.execute(
                """
                SELECT json_extract(payload_json, '$.rule_id'), COUNT(*)
                FROM alerts
                WHERE created_at >= ? AND created_at < ?
                    AND json_extract(payload_json, '$.rule_id') IS NOT NULL
                GROUP BY 1 ORDER BY COUNT(*) DESC, 1 LIMIT 10
                """,
                period,
            ).fetchall()
            top_mitre = connection.execute(
                """
                SELECT json_extract(payload_json, '$.mitre_attck_id'), COUNT(*)
                FROM alerts
                WHERE created_at >= ? AND created_at < ?
                    AND json_extract(payload_json, '$.mitre_attck_id') IS NOT NULL
                GROUP BY 1 ORDER BY COUNT(*) DESC, 1 LIMIT 10
                """,
                period,
            ).fetchall()
            false_positive_trend = connection.execute(
                """
                SELECT strftime(?, timestamp), COUNT(*)
                FROM incident_events
                WHERE timestamp >= ? AND timestamp < ?
                    AND event_type = 'STATUS_CHANGED'
                    AND json_extract(payload_json, '$.to_status') = 'FALSE_POSITIVE'
                GROUP BY 1 ORDER BY 1
                """,
                (bucket, *period),
            ).fetchall()

        points = lambda rows: [{"timestamp": key, "count": int(total)} for key, total in rows]
        ranked = lambda rows, key: [{key: label, "count": int(total)} for label, total in rows]
        return {
            "granularity": granularity,
            "alert_trend": points(alert_trend),
            "false_positive_trend": points(false_positive_trend),
            "incident_distribution": ranked(incident_distribution, "status"),
            "top_rules": ranked(top_rules, "rule_id"),
            "top_mitre_techniques": ranked(top_mitre, "technique_id"),
        }


class SQLiteAssetRepository(_SQLiteRepository):
    _COLUMNS = (
        "asset_id", "hostname", "os", "owner", "department", "environment",
        "criticality", "tags_json", "enabled", "created_at", "updated_at",
    )

    @staticmethod
    def _from_row(row, ip_addresses=None):
        if row is None:
            return None
        asset = dict(zip(SQLiteAssetRepository._COLUMNS, row))
        asset["tags"] = json.loads(asset.pop("tags_json"))
        asset["enabled"] = bool(asset["enabled"])
        asset["ip_addresses"] = ip_addresses or []
        return asset

    @staticmethod
    def _duplicate_asset_id(connection, asset, exclude_asset_id=None):
        suffix = " AND asset_id != ?" if exclude_asset_id else ""
        values = [asset["hostname"]]
        if exclude_asset_id:
            values.append(exclude_asset_id)
        row = connection.execute(
            "SELECT asset_id FROM assets WHERE hostname = ? COLLATE NOCASE" + suffix,
            values,
        ).fetchone()
        if row:
            return row[0]
        for address in asset["ip_addresses"]:
            values = [address]
            if exclude_asset_id:
                values.append(exclude_asset_id)
            row = connection.execute(
                "SELECT asset_id FROM asset_ip_addresses WHERE ip_address = ?" + suffix,
                values,
            ).fetchone()
            if row:
                return row[0]
        return None

    @staticmethod
    def _write(connection, asset):
        connection.execute(
            """
            INSERT INTO assets (
                asset_id, hostname, os, owner, department, environment,
                criticality, tags_json, enabled, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset["asset_id"], asset["hostname"], asset["os"], asset["owner"],
                asset["department"], asset["environment"], asset["criticality"],
                json.dumps(asset["tags"], ensure_ascii=False), int(asset["enabled"]),
                asset["created_at"], asset["updated_at"],
            ),
        )
        connection.executemany(
            "INSERT INTO asset_ip_addresses (asset_id, ip_address) VALUES (?, ?)",
            [(asset["asset_id"], address) for address in asset["ip_addresses"]],
        )

    def create_asset(self, asset: dict, actor="system", role=None) -> dict:
        asset = validate_asset(asset)
        self.ensure_schema()
        try:
            with self._connect() as connection:
                duplicate = self._duplicate_asset_id(connection, asset)
                if duplicate:
                    raise ValueError(f"Asset duplicates existing asset {duplicate}")
                self._write(connection, asset)
        except sqlite3.IntegrityError as exc:
            raise ValueError("Asset hostname or IP address already exists") from exc
        append_audit_event(
            "ASSET_CREATED", actor, role=role, target_type="asset",
            target_id=asset["asset_id"], details={"hostname": asset["hostname"]},
        )
        return self.get_asset(asset["asset_id"])

    def get_asset(self, asset_id: str) -> dict | None:
        self.ensure_schema()
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {', '.join(self._COLUMNS)} FROM assets WHERE asset_id = ?",
                (asset_id,),
            ).fetchone()
            addresses = connection.execute(
                "SELECT ip_address FROM asset_ip_addresses WHERE asset_id = ? ORDER BY ip_address",
                (asset_id,),
            ).fetchall() if row else []
        return self._from_row(row, [address[0] for address in addresses])

    def list_assets(self, enabled=None) -> list[dict]:
        if enabled is not None and not isinstance(enabled, bool):
            raise ValueError("Asset enabled filter must be boolean")
        self.ensure_schema()
        where = " WHERE enabled = ?" if enabled is not None else ""
        values = (int(enabled),) if enabled is not None else ()
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {', '.join(self._COLUMNS)} FROM assets{where} ORDER BY hostname COLLATE NOCASE",
                values,
            ).fetchall()
            addresses = connection.execute(
                "SELECT asset_id, ip_address FROM asset_ip_addresses ORDER BY ip_address",
            ).fetchall()
        address_map = {}
        for asset_id, address in addresses:
            address_map.setdefault(asset_id, []).append(address)
        return [self._from_row(row, address_map.get(row[0], [])) for row in rows]

    def find_by_hostname(self, hostname: str) -> dict | None:
        self.ensure_schema()
        hostname = str(hostname or "").strip()
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {', '.join(self._COLUMNS)} FROM assets WHERE hostname = ? COLLATE NOCASE",
                (hostname,),
            ).fetchone()
        return self.get_asset(row[0]) if row else None

    def find_by_ip(self, ip_address: str) -> dict | None:
        self.ensure_schema()
        address = normalize_ip_address(ip_address)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT asset_id FROM asset_ip_addresses WHERE ip_address = ?", (address,),
            ).fetchone()
        return self.get_asset(row[0]) if row else None

    def update_asset(self, asset_id: str, changes, actor="system", role=None) -> dict | None:
        current = self.get_asset(asset_id)
        if current is None:
            return None
        before = dict(current)
        if callable(changes):
            changes(current)
        elif isinstance(changes, dict):
            current.update(changes)
        else:
            raise ValueError("Asset changes must be an object or callable")
        if current.get("asset_id") != asset_id:
            raise ValueError("Asset asset_id is immutable")
        current["created_at"] = before["created_at"]
        current["updated_at"] = utc_iso()
        current = validate_asset(current)
        changed_fields = sorted(
            field for field in current
            if field != "updated_at" and current.get(field) != before.get(field)
        )
        if not changed_fields:
            return before
        try:
            with self._connect() as connection:
                duplicate = self._duplicate_asset_id(connection, current, asset_id)
                if duplicate:
                    raise ValueError(f"Asset duplicates existing asset {duplicate}")
                connection.execute(
                    """
                    UPDATE assets SET
                        hostname = ?, os = ?, owner = ?, department = ?, environment = ?,
                        criticality = ?, tags_json = ?, enabled = ?, updated_at = ?
                    WHERE asset_id = ?
                    """,
                    (
                        current["hostname"], current["os"], current["owner"],
                        current["department"], current["environment"], current["criticality"],
                        json.dumps(current["tags"], ensure_ascii=False), int(current["enabled"]),
                        current["updated_at"], asset_id,
                    ),
                )
                connection.execute("DELETE FROM asset_ip_addresses WHERE asset_id = ?", (asset_id,))
                connection.executemany(
                    "INSERT INTO asset_ip_addresses (asset_id, ip_address) VALUES (?, ?)",
                    [(asset_id, address) for address in current["ip_addresses"]],
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Asset hostname or IP address already exists") from exc
        append_audit_event(
            "ASSET_UPDATED", actor, role=role, target_type="asset", target_id=asset_id,
            details={"fields": changed_fields},
        )
        return self.get_asset(asset_id)

    def delete_asset(self, asset_id: str, actor="system", role=None) -> bool:
        current = self.get_asset(asset_id)
        if current is None:
            return False
        with self._connect() as connection:
            connection.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
        append_audit_event(
            "ASSET_DELETED", actor, role=role, target_type="asset", target_id=asset_id,
            details={"hostname": current["hostname"]},
        )
        return True
