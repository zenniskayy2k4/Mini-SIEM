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
    def __init__(self):
        self._schema_path = None
        self._schema_lock = threading.Lock()

    @property
    def path(self):
        return config.SQLITE_ALERT_DB

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
        self.ensure_schema()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM alerts ORDER BY rowid DESC",
            ).fetchall()
        alerts = [json.loads(row[0]) for row in rows]
        if filters:
            alerts = [
                alert for alert in alerts
                if all(alert.get(key) == value for key, value in filters.items())
            ]
        offset = max(0, offset)
        return alerts[offset:] if limit is None else alerts[offset:offset + max(0, limit)]

    def count_alerts(self) -> int:
        self.ensure_schema()
        with self._connect() as connection:
            return connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
