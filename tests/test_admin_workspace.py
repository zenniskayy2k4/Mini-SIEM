import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.audit import verify_audit_log
from src.dashboard_auth import authenticate, get_user
from tests.auth_helpers import login_as


def test_admin_workspace():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original = (
            config.DASHBOARD_USERS_FILE,
            config.ANALYST_AUDIT_FILE,
            config.SQLITE_ALERT_DB,
            config.SQLITE_BACKUP_DIR,
            config.ALERT_ARCHIVE_DIR,
        )
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        config.SQLITE_ALERT_DB = str(directory / "mini_siem.db")
        config.SQLITE_BACKUP_DIR = str(directory / "backups")
        config.ALERT_ARCHIVE_DIR = str(directory / "archive")
        Path(config.SQLITE_ALERT_DB).write_bytes(b"fixture database")
        Path(config.SQLITE_BACKUP_DIR).mkdir()
        Path(config.SQLITE_BACKUP_DIR, "mini_siem.backup-fixture.db").write_bytes(b"backup")
        Path(config.ALERT_ARCHIVE_DIR).mkdir()
        Path(config.ALERT_ARCHIVE_DIR, "alerts-fixture.jsonl").write_text("{}\n", encoding="utf-8")
        health = {
            "status": "healthy",
            "agent": {"status": "healthy", "age_seconds": 1.5},
            "database": {"status": "healthy", "check": "ok"},
            "queue": {"busy": False, "backlog": 0},
            "ai": {"enabled": True, "available": True, "provider": "fixture"},
        }
        try:
            admin = dashboard.app.test_client()
            login_as(admin, directory, role="admin", username="soc-admin")
            with patch.object(dashboard, "build_system_status", return_value=health):
                page = admin.get("/settings")
                assert page.status_code == 200
                html = page.get_data(as_text=True)
                for marker in (
                    "Admin workspace", "User Management", "Integrations", "Audit Integrity",
                    "Retention & Backup", "Detection Rules", 'id="set-nids-enabled"',
                ):
                    assert marker in html

                workspace = admin.get("/api/admin/workspace")
                assert workspace.status_code == 200
                payload = workspace.get_json()
                assert payload["health"]["status"] == "healthy"
                assert payload["audit"]["valid"] is True
                assert payload["maintenance"]["retention_days"] == config.ALERT_RETENTION_DAYS
                assert payload["maintenance"]["backups"]["count"] == 1
                assert payload["maintenance"]["archives"]["count"] == 1
                assert payload["users"] == [{"role": "admin", "username": "soc-admin"}]
                assert {item["name"] for item in payload["integrations"]} == {
                    "External case", "AI analyst", "Threat intelligence",
                    "Notifications", "Windows collector",
                }
                assert "password" not in json.dumps(payload).lower()

                created = admin.post("/api/admin/users", json={
                    "username": "tier-1", "password": "first-password-123", "role": "viewer",
                })
                assert created.status_code == 201 and created.get_json() == {
                    "username": "tier-1", "role": "viewer",
                }
                updated = admin.post("/api/admin/users", json={
                    "username": "tier-1", "password": "second-password-123", "role": "analyst",
                })
                assert updated.status_code == 200
                assert authenticate("tier-1", "second-password-123")[1]["role"] == "analyst"
                assert admin.post("/api/admin/users", json={
                    "username": "short", "password": "too-short", "role": "viewer",
                }).status_code == 400
                assert admin.post("/api/admin/users", json={
                    "username": "soc-admin", "password": "admin-password-reset", "role": "viewer",
                }).status_code == 400
                assert get_user("soc-admin")["role"] == "admin"
                assert admin.delete("/api/admin/users/soc-admin").status_code == 400
                assert admin.delete("/api/admin/users/tier-1").status_code == 200
                assert get_user("tier-1") is None

                refreshed = admin.get("/api/admin/workspace").get_json()
                assert refreshed["audit"] == {
                    "valid": True, "message": "Audit chain is valid", "events": 3,
                }
                assert verify_audit_log()[0] is True
                audit_text = Path(config.ANALYST_AUDIT_FILE).read_text(encoding="utf-8")
                assert [event["event_type"] for event in map(json.loads, audit_text.splitlines())] == [
                    "USER_CREATED", "USER_UPDATED", "USER_DELETED",
                ]
                assert "first-password-123" not in audit_text and "second-password-123" not in audit_text

            analyst = dashboard.app.test_client()
            login_as(analyst, directory, role="analyst", username="soc-analyst")
            assert analyst.get("/api/admin/workspace").status_code == 403
            assert analyst.post("/api/admin/users", json={
                "username": "blocked", "password": "blocked-password-123", "role": "viewer",
            }).status_code == 403
        finally:
            (
                config.DASHBOARD_USERS_FILE,
                config.ANALYST_AUDIT_FILE,
                config.SQLITE_ALERT_DB,
                config.SQLITE_BACKUP_DIR,
                config.ALERT_ARCHIVE_DIR,
            ) = original


if __name__ == "__main__":
    test_admin_workspace()
    print("M17.3 admin workspace passed")
