import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

import dashboard
from config import config
from src.alert_schema import build_alert
from src.rules import load_detection_rules
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def _sigma_rule(rule_id: str, modifier: str = "endswith") -> dict:
    return {
        "title": f"Sigma lifecycle {modifier}",
        "id": rule_id,
        "status": "experimental",
        "description": "Sigma lifecycle regression",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {f"Image|{modifier}": r"\powershell.exe"},
            "condition": "selection",
        },
        "level": "high",
    }


def test_sigma_lifecycle():
    sigma_id = "5719596b-04c2-466b-9a53-113e207b5672"
    unsupported_id = "4962d44c-6c27-4f32-90ea-85ddce96a434"
    original_rules = dashboard.DETECTION_RULES
    original_sigma = dashboard.SIGMA_RULES
    original_loaded_at = dashboard.RULES_LOADED_AT
    original_users_file = config.DASHBOARD_USERS_FILE

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        sigma_directory = root / "sigma"
        native_directory = root / "native"
        sigma_directory.mkdir()
        native_directory.mkdir()
        (sigma_directory / "lifecycle.yml").write_text(
            yaml.safe_dump_all([
                _sigma_rule(sigma_id),
                _sigma_rule(unsupported_id, "re"),
            ], sort_keys=False),
            encoding="utf-8",
        )
        state_file = root / "sigma_rule_states.json"
        audit_file = root / "audit.jsonl"
        repository = SQLiteAlertRepository(str(root / "alerts.db"))
        repository.create_alert(build_alert(
            rule_id=sigma_id,
            rule_source="sigma",
            sigma_rule_id=sigma_id,
            alert_name="Lifecycle hit",
            severity="HIGH",
            source_type="WINDOWS_EVENT",
            description="lifecycle coverage",
            mitre_attck_id="T1059.001",
        ))

        try:
            with (
                patch.object(config, "RULES_DIR", str(native_directory)),
                patch.object(config, "SIGMA_RULES_DIR", str(sigma_directory)),
                patch.object(config, "SIGMA_RULE_STATE_FILE", str(state_file)),
                patch.object(config, "ANALYST_AUDIT_FILE", str(audit_file)),
                patch.object(dashboard, "alert_repository", repository),
            ):
                dashboard._reload_detection_rules()
                client = dashboard.app.test_client()
                login_as(client, directory, role="admin", username="sigma-admin")

                workspace = client.get("/detections")
                assert workspace.status_code == 200
                assert b'detection-tuning-body' in workspace.data

                response = client.get("/api/detection-rules")
                assert response.status_code == 200
                rules = {rule["rule_id"]: rule for rule in response.get_json()["rules"]}
                assert {rule["rule_source"] for rule in rules.values()} == {"native", "sigma"}
                assert rules[sigma_id]["validation_status"] == "valid"
                assert rules[sigma_id]["last_loaded_at"].endswith("Z")
                assert rules[sigma_id]["hit_count"] == 1
                assert rules[sigma_id]["never_hit"] is False
                assert rules[unsupported_id]["supported"] is False

                disabled = client.patch(
                    f"/api/detection-rules/{sigma_id}", json={"enabled": False},
                )
                assert disabled.status_code == 200
                assert disabled.get_json()["enabled"] is False
                assert json.loads(state_file.read_text(encoding="utf-8"))[sigma_id] is False
                active = load_detection_rules(
                    str(native_directory), config.SIGNATURES, str(sigma_directory),
                )
                assert sigma_id not in {rule["id"] for rule in active}

                rejected = client.patch(
                    f"/api/detection-rules/{unsupported_id}", json={"enabled": True},
                )
                assert rejected.status_code == 400

                enabled = client.patch(
                    f"/api/detection-rules/{sigma_id}", json={"enabled": True},
                )
                assert enabled.status_code == 200
                assert enabled.get_json()["enabled"] is True

                audit = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").splitlines()]
                assert [event["event_type"] for event in audit] == ["RULE_DISABLED", "RULE_ENABLED"]
                assert all(event["details"]["source"] == "sigma" for event in audit)
        finally:
            dashboard.DETECTION_RULES = original_rules
            dashboard.SIGMA_RULES = original_sigma
            dashboard.RULES_LOADED_AT = original_loaded_at
            config.DASHBOARD_USERS_FILE = original_users_file


if __name__ == "__main__":
    test_sigma_lifecycle()
    print("M11.3 Sigma lifecycle passed")
