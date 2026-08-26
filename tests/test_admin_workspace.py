import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.audit import verify_audit_log
from src.dashboard_auth import authenticate, get_user, load_users, save_user, user_auth_version
from src.ingestion_failures import record_ingestion_failure
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
        record_ingestion_failure(
            "schema", "Missing event field", {"api_" + "key": "admin-secret"},
            collector_id="win-lab",
        )
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
            "ingestion": {"status": "idle", "collectors": [{"collector_id": "win-lab"}]},
        }
        try:
            admin = dashboard.app.test_client()
            login_as(admin, directory, role="admin", username="soc-admin")
            assert dashboard.app.config["MAX_CONTENT_LENGTH"] == 2 * 1024 * 1024
            with patch.object(dashboard, "build_system_status", return_value=health):
                page = admin.get("/settings")
                assert page.status_code == 200
                html = page.get_data(as_text=True)
                for marker in (
                    "Admin workspace", "User Management", "Integrations", "Audit Integrity",
                    "Retention & Backup", "Ingestion Failures", 'id="set-nids-enabled"',
                    'id="admin-health-ingestion"',
                ):
                    assert marker in html
                tuning = admin.get("/detections")
                assert tuning.status_code == 200
                assert b"Detection tuning" in tuning.data
                assert b'detection-tuning-body' in tuning.data

                workspace = admin.get("/api/admin/workspace")
                assert workspace.status_code == 200
                payload = workspace.get_json()
                assert payload["health"]["status"] == "healthy"
                assert payload["audit"]["valid"] is True
                assert payload["maintenance"]["retention_days"] == config.ALERT_RETENTION_DAYS
                assert payload["maintenance"]["backups"]["count"] == 1
                assert payload["maintenance"]["archives"]["count"] == 1
                assert payload["ingestion_failures"]["counts"]["schema"] == 1
                assert payload["ingestion_failures"]["recent"][0]["collector_id"] == "win-lab"
                assert "admin-secret" not in json.dumps(payload)
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
                tier_one = dashboard.app.test_client()
                with tier_one.session_transaction() as user_session:
                    user_session.update(
                        username="tier-1",
                        role="viewer",
                        auth_version=user_auth_version(get_user("tier-1")),
                        csrf_token="tier-one-csrf",
                    )
                assert tier_one.get("/api/admin/workspace").status_code == 403
                with patch.object(dashboard, "append_audit_event", side_effect=OSError):
                    assert admin.delete("/api/admin/users/tier-1").status_code == 503
                assert get_user("tier-1") is not None
                updated = admin.post("/api/admin/users", json={
                    "username": "tier-1", "password": "second-password-123", "role": "analyst",
                })
                assert updated.status_code == 200
                assert authenticate("tier-1", "second-password-123")[1]["role"] == "analyst"
                assert tier_one.get("/api/admin/workspace").status_code == 401
                assert admin.post("/api/admin/users", json={
                    "username": "short", "password": "too-short", "role": "viewer",
                }).status_code == 400
                assert admin.post("/api/admin/users", json={
                    "username": "too-long", "password": "x" * 257, "role": "viewer",
                }).status_code == 400
                assert admin.post(
                    "/api/admin/users",
                    data=b"x" * (2 * 1024 * 1024 + 1),
                    content_type="application/json",
                ).status_code == 413
                with patch.object(dashboard, "append_audit_event", side_effect=OSError):
                    assert admin.post("/api/admin/users", json={
                        "username": "audit-failure",
                        "password": "audit-failure-password",
                        "role": "viewer",
                    }).status_code == 503
                assert get_user("audit-failure") is None
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

            config.DASHBOARD_USERS_FILE = str(directory / "concurrent-users.json")
            with patch("src.dashboard_auth.generate_password_hash", side_effect=lambda value: f"hash:{value}"):
                with ThreadPoolExecutor(max_workers=16) as executor:
                    list(executor.map(
                        lambda index: save_user(
                            f"concurrent-{index}", "concurrent-password", "analyst"
                        ),
                        range(40),
                    ))
            assert len(load_users()) == 40
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
