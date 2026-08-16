import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from config import config
from dashboard import app
from src.alert_schema import build_alert
from src.audit import verify_audit_log
from src.dashboard_auth import save_user
from src.rules import set_rule_enabled
from src.sqlite_store import SQLiteAlertRepository


def _csrf(client):
    with client.session_transaction() as session:
        return session["csrf_token"]


def test_audit_log():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original = (
            config.ANALYST_AUDIT_FILE,
            config.DASHBOARD_USERS_FILE,
            config.RESPONSE_LOG_FILE,
            config.RESPONSE_MODE,
            config.RESPONSE_TARGET_OS,
        )
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        config.DASHBOARD_USERS_FILE = str(directory / "users.json")
        config.RESPONSE_LOG_FILE = str(directory / "responses.jsonl")
        config.RESPONSE_MODE = "manual"
        config.RESPONSE_TARGET_OS = "linux"
        save_user("audit-admin", "audit-password-123", "admin")

        repository = SQLiteAlertRepository(str(directory / "alerts.db"))
        alert = build_alert(
            alert_name="Audit test",
            severity="HIGH",
            source_type="HIDS_LOG",
            description="audit workflow",
            ip_address="192.0.2.77",
        )
        repository.create_alert(alert)
        rule_directory = directory / "rules"
        rule_directory.mkdir()
        (rule_directory / "audit.yml").write_text(
            """id: DET-AUDIT-001
title: Audit rule
enabled: true
severity: HIGH
source_type: HIDS_LOG
mitre:
  tactic: Credential Access
  technique: T1110
match:
  contains: audit-test
description: Audit rule state changes
""",
            encoding="utf-8",
        )
        try:
            client = app.test_client()
            client.get("/login")
            response = client.post("/login", data={
                "username": "audit-admin",
                "password": "audit-password-123",
                "csrf_token": _csrf(client),
            })
            assert response.status_code == 302
            client.environ_base["HTTP_X_CSRF_TOKEN"] = _csrf(client)
            with patch("src.alert_store.alert_repository", repository), patch(
                "dashboard.RUNTIME_SETTINGS_FILE", str(directory / "runtime.json")
            ):
                assert client.patch(
                    f"/api/alerts/{alert['alert_id']}/status",
                    json={"status": "INVESTIGATING"},
                ).status_code == 200
                assert client.post(
                    f"/api/alerts/{alert['alert_id']}/notes",
                    json={"note": "sensitive analyst note"},
                ).status_code == 200
                assert client.patch(
                    f"/api/alerts/{alert['alert_id']}/assignee",
                    json={"assigned_to": "tier-2"},
                ).status_code == 200
                proposed = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions",
                    json={"action_type": "BLOCK_IP", "target": "192.0.2.77"},
                ).get_json()["response_actions"][-1]
                assert client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions/{proposed['action_id']}/approve"
                ).status_code == 200
                assert client.post(
                    "/api/settings/update", json={"GRAPH_AUTO_REFRESH": False}
                ).status_code == 200

            set_rule_enabled("DET-AUDIT-001", False, "audit-admin", str(rule_directory))
            set_rule_enabled("DET-AUDIT-001", True, "audit-admin", str(rule_directory))
            assert client.post("/logout").status_code == 302

            valid, message = verify_audit_log()
            assert valid, message
            audit_text = Path(config.ANALYST_AUDIT_FILE).read_text(encoding="utf-8")
            events = [json.loads(line) for line in audit_text.splitlines()]
            event_types = {event["event_type"] for event in events}
            assert {
                "LOGIN", "LOGOUT", "STATUS_CHANGED", "NOTE_ADDED",
                "ASSIGNMENT_CHANGED", "RESPONSE_REQUESTED", "RESPONSE_APPROVED",
                "RESPONSE_EXECUTED", "RULE_ENABLED", "RULE_DISABLED",
                "RUNTIME_SETTING_CHANGED",
            } <= event_types
            assert all(event["actor"] == "audit-admin" for event in events)
            assert "audit-password-123" not in audit_text
            assert "sensitive analyst note" not in audit_text
            assert "192.0.2.77" not in audit_text

            Path(config.ANALYST_AUDIT_FILE).write_text(
                audit_text.replace("audit-admin", "intruder", 1), encoding="utf-8"
            )
            assert verify_audit_log()[0] is False
        finally:
            (
                config.ANALYST_AUDIT_FILE,
                config.DASHBOARD_USERS_FILE,
                config.RESPONSE_LOG_FILE,
                config.RESPONSE_MODE,
                config.RESPONSE_TARGET_OS,
            ) = original


if __name__ == "__main__":
    test_audit_log()
    print("M8.2 immutable analyst audit log passed")
