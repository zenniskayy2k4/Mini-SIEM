import tempfile
from pathlib import Path
from unittest.mock import patch

from config import config
from dashboard import app
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def test_response_approval():
    with tempfile.TemporaryDirectory() as directory:
        original = (
            config.RESPONSE_LOG_FILE,
            config.RESPONSE_MODE,
            config.RESPONSE_TARGET_OS,
            config.RESPONSE_PROTECTED_TARGETS,
            config.DASHBOARD_USERS_FILE,
        )
        config.RESPONSE_LOG_FILE = str(Path(directory, "responses.jsonl"))
        config.RESPONSE_MODE = "manual"
        config.RESPONSE_TARGET_OS = "linux"
        config.RESPONSE_PROTECTED_TARGETS = {"localhost", "127.0.0.1", "192.0.2.1", "/etc", "root", "1"}
        repository = SQLiteAlertRepository(str(Path(directory, "alerts.db")))
        alert = build_alert(
            alert_name="Approval test",
            severity="HIGH",
            source_type="HIDS_LOG",
            description="manual approval workflow",
            ip_address="192.0.2.63",
        )
        repository.create_alert(alert)
        try:
            with patch("src.alert_store.alert_repository", repository):
                client = app.test_client()
                login_as(client, directory)
                proposed = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions",
                    json={"action_type": "BLOCK_IP", "target": "192.0.2.63"},
                ).get_json()["response_actions"][-1]
                assert proposed["status"] == "PROPOSED"

                approved_response = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions/{proposed['action_id']}/approve",
                    json={"analyst": "blue-team"},
                )
                assert approved_response.status_code == 200
                approved = approved_response.get_json()["response_actions"][-1]
                assert approved["status"] == "SIMULATED"
                assert approved["approved_by"] == "blue-team"
                assert approved["result"].startswith("would execute ")
                event_types = [event["event_type"] for event in approved_response.get_json()["timeline"]]
                assert event_types[-2:] == ["RESPONSE_ACTION_APPROVED", "RESPONSE_ACTION_SIMULATED"]

                rollback = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions/{proposed['action_id']}/rollback",
                    json={"analyst": "blue-team"},
                )
                assert rollback.status_code == 200
                assert rollback.get_json()["response_actions"][-1]["status"] == "ROLLED_BACK"

                protected = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions",
                    json={"action_type": "BLOCK_IP", "target": "127.0.0.1"},
                )
                injected = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions",
                    json={"action_type": "BLOCK_IP", "target": "192.0.2.64;whoami"},
                )
                critical = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions",
                    json={"action_type": "BLOCK_IP", "target": "192.0.2.1"},
                )
                protected_path = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions",
                    json={"action_type": "QUARANTINE_FILE", "target": "/etc/passwd"},
                )
                assert protected.status_code == injected.status_code == 400
                assert critical.status_code == protected_path.status_code == 400

                expiring = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions",
                    json={"action_type": "DISABLE_USER", "target": "testuser"},
                ).get_json()["response_actions"][-1]
                repository.update_alert(
                    alert["alert_id"],
                    lambda stored: stored["response_actions"][-1].update(
                        approval_expires_at="2000-01-01T00:00:00Z"
                    ),
                )
                expired = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions/{expiring['action_id']}/approve",
                    json={"analyst": "blue-team"},
                )
                assert expired.status_code == 200
                assert expired.get_json()["response_actions"][-1]["status"] == "FAILED"
                assert "expired" in expired.get_json()["response_actions"][-1]["error"].lower()
        finally:
            (
                config.RESPONSE_LOG_FILE,
                config.RESPONSE_MODE,
                config.RESPONSE_TARGET_OS,
                config.RESPONSE_PROTECTED_TARGETS,
                config.DASHBOARD_USERS_FILE,
            ) = original


if __name__ == "__main__":
    test_response_approval()
    print("M6.3 response approval passed")
