import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from config import config
from dashboard import app
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository


def test_response_simulation():
    action_types = (
        "BLOCK_IP", "UNBLOCK_IP", "DISABLE_USER",
        "KILL_PROCESS", "QUARANTINE_FILE", "NOTIFY_ANALYST",
    )
    with tempfile.TemporaryDirectory() as directory:
        original = (config.RESPONSE_LOG_FILE, config.RESPONSE_MODE, config.RESPONSE_TARGET_OS)
        config.RESPONSE_LOG_FILE = str(Path(directory, "responses.jsonl"))
        config.RESPONSE_MODE = "simulation"
        config.RESPONSE_TARGET_OS = "linux"
        repository = SQLiteAlertRepository(str(Path(directory, "alerts.db")))
        alert = build_alert(
            alert_name="Simulation test",
            severity="HIGH",
            source_type="HIDS_LOG",
            description="safe response simulation",
            ip_address="192.0.2.62",
        )
        repository.create_alert(alert)
        try:
            with patch("src.alert_store.alert_repository", repository):
                client = app.test_client()
                for action_type in action_types:
                    response = client.post(
                        f"/api/alerts/{alert['alert_id']}/response-actions",
                        json={"action_type": action_type, "target": "192.0.2.62"},
                    )
                    assert response.status_code == 201
                    action = response.get_json()["response_actions"][-1]
                    assert action["action_type"] == action_type
                    assert action["status"] == "SIMULATED"
                    assert action["result"].startswith("would execute ")
                    assert "command" not in json.dumps(action).lower()

                invalid = client.post(
                    f"/api/alerts/{alert['alert_id']}/response-actions",
                    json={"action_type": "RUN_SHELL", "target": "whoami"},
                )
                assert invalid.status_code == 400

            stored = repository.get_alert(alert["alert_id"])
            assert len(stored["response_actions"]) == len(action_types)
            assert len([event for event in stored["timeline"] if event["event_type"] == "RESPONSE_ACTION_SIMULATED"]) == len(action_types)
            with repository._connect() as connection:
                assert connection.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0] == len(action_types)
                assert connection.execute("SELECT COUNT(*) FROM incident_events").fetchone()[0] == len(action_types)
            assert len(Path(config.RESPONSE_LOG_FILE).read_text(encoding="utf-8").splitlines()) == len(action_types)
        finally:
            config.RESPONSE_LOG_FILE, config.RESPONSE_MODE, config.RESPONSE_TARGET_OS = original


if __name__ == "__main__":
    test_response_simulation()
    print("M6.2 response simulation passed")
