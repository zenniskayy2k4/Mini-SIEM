import json
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from config import config
from src.alert_schema import build_alert
from src.maintenance import apply_retention, rotate_logs
from src.sqlite_store import SQLiteAlertRepository
from src.storage import DualWriteAlertRepository, JsonAlertRepository
from tools.migrate_json_to_sqlite import migrate


def test_maintenance():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        fields = (
            "SQLITE_ALERT_DB", "OUTPUT_ALERT_FILE", "ALERT_ARCHIVE_DIR",
            "SQLITE_BACKUP_DIR", "LOG_FILE_TO_WATCH", "WINDOWS_EVENT_FILE",
            "RESPONSE_LOG_FILE", "NOTIFICATION_LOG_FILE", "ANALYST_AUDIT_FILE",
        )
        original = {field: getattr(config, field) for field in fields}
        config.SQLITE_ALERT_DB = str(directory / "alerts.db")
        config.OUTPUT_ALERT_FILE = str(directory / "alerts.jsonl")
        config.ALERT_ARCHIVE_DIR = str(directory / "archive")
        config.SQLITE_BACKUP_DIR = str(directory / "backups")
        config.LOG_FILE_TO_WATCH = str(directory / "auth.log")
        config.WINDOWS_EVENT_FILE = str(directory / "windows.jsonl")
        config.RESPONSE_LOG_FILE = str(directory / "responses.log")
        config.NOTIFICATION_LOG_FILE = str(directory / "notifications.log")
        config.ANALYST_AUDIT_FILE = str(directory / "analyst_audit.jsonl")
        try:
            repository = DualWriteAlertRepository(
                JsonAlertRepository(), SQLiteAlertRepository(config.SQLITE_ALERT_DB),
            )
            alerts = [
                build_alert(
                    alert_name="Old closed alert", severity="LOW", source_type="HIDS_LOG",
                    description="archive", timestamp="2026-01-01T00:00:00Z",
                ),
                build_alert(
                    alert_name="Old open incident", severity="HIGH", source_type="HIDS_LOG",
                    description="preserve", timestamp="2026-01-02T00:00:00Z",
                    incident_status="INVESTIGATING",
                ),
                build_alert(
                    alert_name="Old resolved incident", severity="HIGH", source_type="HIDS_LOG",
                    description="archive", timestamp="2026-01-03T00:00:00Z",
                    incident_status="RESOLVED",
                ),
                build_alert(
                    alert_name="Recent alert", severity="LOW", source_type="HIDS_LOG",
                    description="preserve", timestamp="2026-08-10T00:00:00Z",
                ),
            ]
            for alert in alerts:
                repository.create_alert(alert)

            report = apply_retention(
                30, now=datetime(2026, 8, 14, tzinfo=timezone.utc),
            )
            assert report["archived"] == 2
            assert report["preserved_open_incidents"] == 1
            assert report["json_mirror_removed"] == 2
            archived = [
                json.loads(line)
                for line in Path(report["archive"]).read_text(encoding="utf-8").splitlines()
            ]
            assert {item["alert_name"] for item in archived} == {
                "Old closed alert", "Old resolved incident",
            }
            remaining = SQLiteAlertRepository(config.SQLITE_ALERT_DB).list_alerts()
            assert {item["alert_name"] for item in remaining} == {
                "Old open incident", "Recent alert",
            }
            mirror = [
                json.loads(line)
                for line in Path(config.OUTPUT_ALERT_FILE).read_text(encoding="utf-8").splitlines()
            ]
            assert {item["alert_name"] for item in mirror} == {
                "Old open incident", "Recent alert",
            }
            with sqlite3.connect(report["backup"]) as backup:
                assert backup.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                assert backup.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 4

            restored_db = directory / "restored.db"
            restored = migrate(report["archive"], restored_db)
            assert restored["imported"] == 2
            assert SQLiteAlertRepository(str(restored_db)).stats()["total"] == 2

            operational_logs = [
                config.LOG_FILE_TO_WATCH, config.WINDOWS_EVENT_FILE,
                config.RESPONSE_LOG_FILE, config.NOTIFICATION_LOG_FILE,
            ]
            for path in [*operational_logs, config.ANALYST_AUDIT_FILE]:
                Path(path).write_text("0123456789abcdef", encoding="utf-8")
            rotation = rotate_logs(max_bytes=10, backups=2)
            assert set(rotation["rotated"]) == set(operational_logs)
            assert all(Path(path).read_text(encoding="utf-8") == "" for path in operational_logs)
            assert all(Path(f"{path}.1").read_text(encoding="utf-8") == "0123456789abcdef" for path in operational_logs)
            assert Path(config.ANALYST_AUDIT_FILE).read_text(encoding="utf-8") == "0123456789abcdef"

            try:
                apply_retention(0)
                raise AssertionError("zero-day retention must fail")
            except ValueError:
                pass
        finally:
            for field, value in original.items():
                setattr(config, field, value)


if __name__ == "__main__":
    test_maintenance()
    print("M8.4 retention, backup and log rotation passed")
