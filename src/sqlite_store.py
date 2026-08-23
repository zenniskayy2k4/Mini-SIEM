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


SCHEMA = """
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
                connection.executescript(SCHEMA)
            self._schema_path = self.path


class SQLiteAlertRepository(_SQLiteRepository):

    FEEDBACK_CLASSIFICATIONS = {
        "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_EXPECTED",
    }
    MAX_FEEDBACK_REASON_LENGTH = 2000

    def create_alert(self, alert: dict) -> dict:
        self.ensure_schema()
        payload = json.dumps(alert, ensure_ascii=False)
        with self._connect() as connection:
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
            self._sync_incident(connection, alert)
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

        exact("UPPER(a.severity) = UPPER(?)", filters.get("severity"))
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
            clauses.append("datetime(a.timestamp) >= datetime(?)")
            values.append(filters["from"])
        if filters.get("to"):
            clauses.append("datetime(a.timestamp) <= datetime(?)")
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
                + " ORDER BY a.timestamp DESC, a.rowid DESC" + page,
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
