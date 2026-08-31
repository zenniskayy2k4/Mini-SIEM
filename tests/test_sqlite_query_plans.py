import json
import sqlite3
import tempfile
from pathlib import Path

from src.sqlite_store import SQLiteAlertRepository
from tools.migrate_db import migrate_database


def _plan(connection, sql, params=()):
    return " | ".join(
        row[3] for row in connection.execute("EXPLAIN QUERY PLAN " + sql, params)
    )


def test_sqlite_query_plans():
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory, "plans.db")
        SQLiteAlertRepository(str(database)).ensure_schema()
        migrate_database(database, backup_path=Path(directory, "plans.backup.db"))
        with sqlite3.connect(database) as connection:
            for index in range(200):
                alert_id = f"ALT-{index:04d}"
                incident_id = f"INC-{index:04d}"
                timestamp = f"2026-08-{index % 28 + 1:02d}T12:00:00Z"
                status = "NEW" if index % 2 else "RESOLVED"
                payload = json.dumps({
                    "rule_id": f"DET-{index % 5}", "incident_status": status,
                })
                connection.execute(
                    "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?)",
                    (alert_id, timestamp, "Fixture", "HIGH", "HIDS_LOG", incident_id,
                     payload, timestamp, timestamp),
                )
                connection.execute(
                    "INSERT INTO incidents VALUES (?,?,?,?,?,?)",
                    (incident_id, alert_id, status, None, timestamp, timestamp),
                )
                connection.execute(
                    "INSERT INTO incident_events(incident_id,event_type,timestamp,payload_json) "
                    "VALUES (?,?,?,?)",
                    (incident_id, "STATUS_CHANGED", timestamp, json.dumps({"to_status": status})),
                )
                connection.execute(
                    "INSERT INTO detection_feedback VALUES (?,?,?,?,?,?,?)",
                    (f"FB-{index:04d}", alert_id, f"DET-{index % 5}", "TRUE_POSITIVE",
                     "verified", "analyst", timestamp),
                )
            connection.execute(
                "INSERT INTO assets VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("AST-1", "host-1", "Linux", "SOC", "Security", "prod", "HIGH",
                 "[]", 1, "2026-08-01", "2026-08-01"),
            )
            connection.execute("ANALYZE")

            list_plan = _plan(connection,
                "SELECT payload_json FROM alerts ORDER BY timestamp DESC, alert_id DESC LIMIT 50")
            time_plan = _plan(connection,
                "SELECT payload_json FROM alerts WHERE timestamp>=? AND timestamp<=? "
                "ORDER BY timestamp DESC, alert_id DESC LIMIT 50", ("2026-08-01", "2026-09-01"))
            severity_plan = _plan(connection,
                "SELECT payload_json FROM alerts WHERE severity=UPPER(?) "
                "ORDER BY timestamp DESC, alert_id DESC LIMIT 50", ("high",))
            incident_plan = _plan(connection,
                "SELECT a.payload_json FROM alerts a LEFT JOIN incidents i ON i.alert_id=a.alert_id "
                "WHERE UPPER(COALESCE(i.status,json_extract(a.payload_json,'$.incident_status'),''))="
                "UPPER(?) ORDER BY a.timestamp DESC,a.alert_id DESC LIMIT 50", ("NEW",))
            rule_plan = _plan(connection,
                "SELECT json_extract(payload_json,'$.rule_id'),COUNT(*) FROM alerts WHERE "
                "json_extract(payload_json,'$.rule_id') IN (?) GROUP BY 1", ("DET-1",))
            kpi_plan = _plan(connection,
                "SELECT COUNT(*) FROM alerts WHERE created_at>=? AND created_at<?",
                ("2026-08-01", "2026-08-02"))
            event_plan = _plan(connection,
                "SELECT COUNT(*) FROM incident_events WHERE event_type=? AND timestamp>=? AND timestamp<?",
                ("STATUS_CHANGED", "2026-08-01", "2026-09-01"))
            asset_plan = _plan(connection,
                "SELECT asset_id FROM assets ORDER BY hostname COLLATE NOCASE")
            quality_plan = _plan(connection,
                "WITH scoped AS (SELECT alert_id FROM alerts WHERE created_at>=? AND created_at<?) "
                "SELECT COUNT(*) FROM scoped LEFT JOIN detection_feedback feedback ON feedback.rowid="
                "(SELECT MAX(rowid) FROM detection_feedback WHERE alert_id=scoped.alert_id)",
                ("2026-08-01", "2026-08-02"))

        assert "idx_alerts_timestamp_id" in list_plan and "TEMP B-TREE FOR ORDER BY" not in list_plan
        assert "idx_alerts_timestamp_id" in time_plan and "timestamp>? AND timestamp<?" in time_plan
        assert "idx_alerts_severity_timestamp_id" in severity_plan
        assert "idx_alerts_timestamp_id" in incident_plan
        assert "idx_alerts_rule_id" in rule_plan
        assert "idx_alerts_created_at" in kpi_plan
        assert "idx_incident_events_type_timestamp" in event_plan
        assert "idx_assets_hostname" in asset_plan
        assert "idx_alerts_created_at" in quality_plan
        assert "idx_detection_feedback_alert" in quality_plan and "SCAN detection_feedback" not in quality_plan


if __name__ == "__main__":
    test_sqlite_query_plans()
    print("M26.1 SQLite query plan audit passed")
