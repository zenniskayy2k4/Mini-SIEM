import json
import tempfile
from pathlib import Path

from config import config
from src.alert_schema import build_alert
from src.response import IncidentResponder, build_response_action
from src.sqlite_store import SQLiteAlertRepository


def test_response_contract():
    with tempfile.TemporaryDirectory() as directory:
        original_log = config.RESPONSE_LOG_FILE
        config.RESPONSE_LOG_FILE = str(Path(directory, "responses.jsonl"))
        try:
            alert = build_alert(
                alert_name="SSH Brute Force Attempt",
                severity="HIGH",
                source_type="HIDS_LOG",
                description="response contract test",
                ip_address="192.0.2.61",
                mitigation_command="iptables must never persist",
            )
            responder = IncidentResponder(mode="simulation", target_os="linux")
            responder.handle_incident(alert)
            responder.handle_incident(alert)
            action = alert["response_actions"][0]

            assert "mitigation_command" not in alert
            assert len(alert["response_actions"]) == 1
            assert action["action_type"] == "BLOCK_IP"
            assert action["handler"] == "linux_firewall"
            assert action["status"] == "PROPOSED"
            assert "iptables" not in json.dumps(action)
            assert len(Path(config.RESPONSE_LOG_FILE).read_text(encoding="utf-8").splitlines()) == 1

            repository = SQLiteAlertRepository(str(Path(directory, "alerts.db")))
            repository.create_alert(alert)
            with repository._connect() as connection:
                row = connection.execute(
                    "SELECT action_type, status, payload_json FROM response_actions"
                ).fetchone()
            assert row[:2] == ("BLOCK_IP", "PROPOSED")
            assert json.loads(row[2])["action_id"] == action["action_id"]
        finally:
            config.RESPONSE_LOG_FILE = original_log

    llm_action = build_response_action(
        incident_id="INC-test",
        action_type="NOTIFY_ANALYST",
        target="INC-test",
        mode="automatic",
        target_os="windows",
        requested_by="llm",
    )
    assert llm_action["status"] == "REQUIRES_APPROVAL"
    assert llm_action["handler"] == "event_log"

    for mode in ("disabled", "simulation", "manual", "automatic"):
        action = build_response_action(
            incident_id="INC-modes",
            action_type="NOTIFY_ANALYST",
            target="INC-modes",
            mode=mode,
            target_os="linux",
        )
        assert action["action_id"].startswith("ACT-")
        assert action["mode"] == mode
        assert action["status"] == ("SKIPPED" if mode == "disabled" else "PROPOSED")

    disabled_llm_action = build_response_action(
        incident_id="INC-LLM-DISABLED",
        action_type="NOTIFY_ANALYST",
        target="INC-LLM-DISABLED",
        mode="disabled",
        target_os="linux",
        requested_by="llm",
    )
    assert disabled_llm_action["status"] == "SKIPPED"


if __name__ == "__main__":
    test_response_contract()
    print("M6.1 response contract passed")
