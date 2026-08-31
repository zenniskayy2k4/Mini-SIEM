import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert, utc_iso
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def test_detection_tuning_workspace():
    with tempfile.TemporaryDirectory() as directory_name:
        root = Path(directory_name)
        original_users = config.DASHBOARD_USERS_FILE
        original_audit = config.ANALYST_AUDIT_FILE
        config.DASHBOARD_USERS_FILE = str(root / "users.json")
        config.ANALYST_AUDIT_FILE = str(root / "audit.jsonl")
        repository = SQLiteAlertRepository(str(root / "alerts.db"))
        alert = build_alert(
            alert_name="Tuning fixture", severity="HIGH", source_type="HIDS_LOG",
            description="Evidence-bound feedback", rule_id="DET-TUNE-001",
            mitre_attck_id="T1110.001",
        )
        repository.create_alert(alert)
        expiry = utc_iso(datetime.now(timezone.utc) + timedelta(hours=1))
        repository.create_detection_exception(
            "rule_id", "DET-TUNE-001", "<img src=x onerror=alert(1)>",
            "soc-admin", "admin", expiry,
        )
        repository.create_alert_suppression_policy(
            "DET-TUNE-001", "AUTH|192.0.2.10", 300, "soc-admin", "admin",
        )
        validation_file = root / "validation.json"
        validation_file.write_text(json.dumps({"rules": [{
            "rule_id": "DET-TUNE-001", "scenario_count": 2,
            "last_validation_result": "PASS",
        }]}), encoding="utf-8")
        rule = {
            "id": "DET-TUNE-001", "title": "SSH tuning fixture",
            "rule_source": "native", "enabled": True, "supported": True,
            "validation_status": "valid", "last_loaded_at": utc_iso(),
            "mitre": {"tactic": "Credential Access", "technique": "T1110.001"},
        }

        try:
            with (
                patch.object(dashboard, "alert_repository", repository),
                patch.object(dashboard, "DETECTION_RULES", [rule]),
                patch.object(dashboard, "SIGMA_RULES", []),
                patch.object(dashboard, "VALIDATION_COVERAGE_FILE", validation_file),
            ):
                viewer = dashboard.app.test_client()
                login_as(viewer, root, role="viewer", username="tuning-viewer")
                assert viewer.get("/detections").status_code == 403
                assert viewer.get("/api/detection-tuning").status_code == 403

                analyst = dashboard.app.test_client()
                login_as(analyst, root, role="analyst", username="tier-1")
                page = analyst.get("/detections")
                assert page.status_code == 200
                assert b'detection-tuning-body' in page.data
                assert b'Manage policies' not in page.data
                assert analyst.patch(
                    "/api/detection-rules/DET-TUNE-001", json={"enabled": False},
                ).status_code == 403
                created = analyst.post(
                    f"/api/alerts/{alert['alert_id']}/feedback",
                    json={"classification": "TRUE_POSITIVE", "reason": ""},
                )
                assert created.status_code == 201
                payload = analyst.get("/api/detection-tuning").get_json()
                tuned = payload["rules"][0]
                assert tuned["hit_count"] == 1 and tuned["enabled"] is True
                assert tuned["feedback"]["true_positives"] == 1
                assert tuned["feedback"]["last_validation_result"] == "PASS"
                assert tuned["feedback"]["validation_scenario_count"] == 2
                assert tuned["mitre_tactic"] == "Credential Access"
                assert tuned["mitre_technique"] == "T1110.001"
                assert tuned["exceptions"][0]["expires_at"] == expiry
                assert tuned["suppression_policies"][0]["window_seconds"] == 300
                assert payload["active_exceptions"][0]["active"] is True

                admin = dashboard.app.test_client()
                login_as(admin, root, role="admin", username="tuning-admin")
                admin_page = admin.get("/detections")
                assert admin_page.status_code == 200 and b'Manage policies' in admin_page.data
                admin.environ_base.pop("HTTP_X_CSRF_TOKEN")
                assert admin.patch(
                    "/api/detection-rules/DET-TUNE-001", json={"enabled": False},
                ).status_code == 400

                script = analyst.get("/static/js/app.js").get_data(as_text=True)
                assert "initDetectionTuning" in script and "tuning-rule-toggle" in script
                assert "escapeHTML(record.reason)" in script
                assert "/logs?q=" in script and "URLSearchParams(window.location.search)" in script
        finally:
            config.DASHBOARD_USERS_FILE = original_users
            config.ANALYST_AUDIT_FILE = original_audit


if __name__ == "__main__":
    test_detection_tuning_workspace()
    print("M20.5 detection tuning workspace passed")
