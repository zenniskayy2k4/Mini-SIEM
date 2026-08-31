import hashlib
import shutil
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from config import config
from src.alert_schema import build_alert
from src.assets import build_asset
from src.audit import append_audit_event, verify_audit_log
from src.maintenance import backup_database
from src.sqlite_store import SQLiteAlertRepository, SQLiteAssetRepository
from tools.migrate_db import inspect_database


def test_restore_drill():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        database = root / "working.db"
        backup = root / "backup.db"
        audit = root / "audit.jsonl"
        alert_repository = SQLiteAlertRepository(str(database))
        asset_repository = SQLiteAssetRepository(str(database))

        with patch.object(config, "ANALYST_AUDIT_FILE", str(audit)):
            alert = build_alert(
                alert_id="ALT-RESTORE-001",
                incident_id="INC-RESTORE-001",
                alert_name="Restore drill incident",
                severity="HIGH",
                source_type="HIDS_LOG",
                description="deterministic restore evidence",
                incident_status="INVESTIGATING",
                assigned_to="tier-2",
                analyst_notes=[{
                    "author": "analyst",
                    "text": "preserve this note",
                    "timestamp": "2026-08-29T00:00:00Z",
                }],
                external_cases={
                    "fixture": {
                        "external_id": "CASE-RESTORE-001",
                        "status": "EXPORTED",
                    }
                },
                timestamp="2026-08-29T00:00:00Z",
            )
            alert_repository.create_alert(alert)
            asset = asset_repository.create_asset(build_asset(
                "restore.example.test",
                ip_addresses=["192.0.2.240"],
                os="Linux",
                owner="SOC",
                department="Security",
                environment="test",
                criticality="HIGH",
                tags=["restore-drill"],
            ))
            append_audit_event(
                "CASE_EXPORT",
                "restore-drill",
                role="analyst",
                target_type="incident",
                target_id=alert["incident_id"],
                details={"provider": "fixture", "external_id": "CASE-RESTORE-001"},
            )

            expected_alert = alert_repository.get_alert(alert["alert_id"])
            expected_asset = asset_repository.get_asset(asset["asset_id"])
            expected_audit_hash = hashlib.sha256(audit.read_bytes()).hexdigest()
            assert inspect_database(database) == 1
            backup_database(database, backup)

            Path(f"{database}-wal").unlink(missing_ok=True)
            Path(f"{database}-shm").unlink(missing_ok=True)
            database.unlink()
            database.write_bytes(b"damaged database")
            try:
                inspect_database(database)
                raise AssertionError("Damaged database must fail validation")
            except sqlite3.DatabaseError:
                pass

            shutil.copy2(backup, database)
            restored_alerts = SQLiteAlertRepository(str(database))
            restored_assets = SQLiteAssetRepository(str(database))
            with sqlite3.connect(database) as connection:
                assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                incident = connection.execute(
                    "SELECT incident_id, status, assigned_to FROM incidents"
                ).fetchone()
                note_count = connection.execute("SELECT COUNT(*) FROM analyst_notes").fetchone()[0]

            assert restored_alerts.get_alert(alert["alert_id"]) == expected_alert
            assert incident == (alert["incident_id"], "INVESTIGATING", "tier-2")
            assert note_count == 1
            assert restored_assets.get_asset(asset["asset_id"]) == expected_asset
            assert expected_alert["external_cases"]["fixture"]["external_id"] == "CASE-RESTORE-001"
            assert inspect_database(database) == 1
            assert hashlib.sha256(audit.read_bytes()).hexdigest() == expected_audit_hash
            assert verify_audit_log()[0] is True


if __name__ == "__main__":
    test_restore_drill()
    print("M24.3 automated database restore drill passed")
