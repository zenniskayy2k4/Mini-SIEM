import json
import os
import sqlite3
import threading

from config import config


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

CREATE TABLE IF NOT EXISTS analyst_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    note_text TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS response_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
"""


class SQLiteAlertRepository:
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
        return {"items": [json.loads(row[0]) for row in rows], "total": total}

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
