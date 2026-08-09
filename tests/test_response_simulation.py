import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from config import config
from dashboard import app
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository


def test_response_simulation():
    targets = {
        "BLOCK_IP": "192.0.2.62",
        "UNBLOCK_IP": "192.0.2.62",
        "DISABLE_USER": "testuser",
        "KILL_PROCESS": "4242",
        "QUARANTINE_FILE": "/tmp/m6.2-eicar",
        "NOTIFY_ANALYST": "analyst",
    }
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
                for action_type, target in targets.items():
                    response = client.post(
                        f"/api/alerts/{alert['alert_id']}/response-actions",
                        json={"action_type": action_type, "target": target},
                    )
                    assert response.status_code == 201, (action_type, response.get_json())
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
            assert len(stored["response_actions"]) == len(targets)
            assert len([event for event in stored["timeline"] if event["event_type"] == "RESPONSE_ACTION_SIMULATED"]) == len(targets)
            with repository._connect() as connection:
                assert connection.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0] == len(targets)
                assert connection.execute("SELECT COUNT(*) FROM incident_events").fetchone()[0] == len(targets)
            assert len(Path(config.RESPONSE_LOG_FILE).read_text(encoding="utf-8").splitlines()) == len(targets)
        finally:
            config.RESPONSE_LOG_FILE, config.RESPONSE_MODE, config.RESPONSE_TARGET_OS = original


if __name__ == "__main__":
    test_response_simulation()
    print("M6.2 response simulation passed")
