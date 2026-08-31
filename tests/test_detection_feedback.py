import json
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert
from src.audit import verify_audit_log
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def test_detection_feedback():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original_users = config.DASHBOARD_USERS_FILE
        original_audit = config.ANALYST_AUDIT_FILE
        config.DASHBOARD_USERS_FILE = str(directory / "users.json")
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        repository = SQLiteAlertRepository(str(directory / "alerts.db"))
        alert = build_alert(
            alert_name="Feedback fixture", severity="HIGH", source_type="HIDS_LOG",
            description="Immutable evidence", raw_log="original evidence",
            incident_status="INVESTIGATING", rule_id="DET-FEEDBACK-001",
            mitre_attck_id="T1110",
        )
        repository.create_alert(alert)
        with sqlite3.connect(repository.path) as connection:
            original_payload = connection.execute(
                "SELECT payload_json FROM alerts WHERE alert_id = ?", (alert["alert_id"],),
            ).fetchone()[0]

        try:
            analyst = dashboard.app.test_client()
            login_as(analyst, directory, role="analyst", username="tier-1")
            with patch.object(dashboard, "alert_repository", repository):
                missing_reason = analyst.post(
                    f"/api/alerts/{alert['alert_id']}/feedback",
                    json={"classification": "FALSE_POSITIVE", "reason": ""},
                )
                assert missing_reason.status_code == 400

                invalid_classification = analyst.post(
                    f"/api/alerts/{alert['alert_id']}/feedback",
                    json={"classification": "TRUE_POSITIVE'); DROP TABLE alerts; --", "reason": ""},
                )
                assert invalid_classification.status_code == 400

                actor_override = analyst.post(
                    f"/api/alerts/{alert['alert_id']}/feedback",
                    json={"classification": "TRUE_POSITIVE", "reason": "", "actor": "attacker"},
                )
                assert actor_override.status_code == 400

                created = analyst.post(
                    f"/api/alerts/{alert['alert_id']}/feedback",
                    json={"classification": "TRUE_POSITIVE", "reason": ""},
                )
                assert created.status_code == 201
                first = created.get_json()
                assert first["feedback_id"].startswith("FB-")
                assert first["actor"] == "tier-1"
                assert first["alert_id"] == alert["alert_id"]
                assert first["rule_id"] == "DET-FEEDBACK-001"

            admin = dashboard.app.test_client()
            login_as(admin, directory, role="admin", username="soc-admin")
            with patch.object(dashboard, "alert_repository", repository):
                created = admin.post(
                    f"/api/alerts/{alert['alert_id']}/feedback",
                    json={
                        "classification": "FALSE_POSITIVE",
                        "reason": "Approved maintenance activity",
                    },
                )
                assert created.status_code == 201
                assert created.get_json()["actor"] == "soc-admin"
                assert admin.post(
                    "/api/alerts/ALT-missing/feedback",
                    json={"classification": "TRUE_POSITIVE", "reason": ""},
                ).status_code == 404

            viewer = dashboard.app.test_client()
            login_as(viewer, directory, role="viewer", username="soc-viewer")
            with patch.object(dashboard, "alert_repository", repository):
                stored = viewer.get("/api/alerts").get_json()[0]
                assert stored["detection_feedback"]["classification"] == "FALSE_POSITIVE"
                assert viewer.post(
                    f"/api/alerts/{alert['alert_id']}/feedback",
                    json={"classification": "BENIGN_EXPECTED", "reason": ""},
                ).status_code == 403
                script = viewer.get("/static/js/app.js").get_data(as_text=True)
                assert "incident-feedback-btn" in script and "Detection feedback" in script

            with sqlite3.connect(repository.path) as connection:
                assert connection.execute("SELECT COUNT(*) FROM detection_feedback").fetchone()[0] == 2
                assert connection.execute(
                    "SELECT payload_json FROM alerts WHERE alert_id = ?", (alert["alert_id"],),
                ).fetchone()[0] == original_payload

            audit_text = Path(config.ANALYST_AUDIT_FILE).read_text(encoding="utf-8")
            events = [json.loads(line) for line in audit_text.splitlines()]
            feedback_events = [
                event for event in events
                if event["event_type"] == "DETECTION_FEEDBACK_CREATED"
            ]
            assert [event["actor"] for event in feedback_events] == ["tier-1", "soc-admin"]
            assert "Approved maintenance activity" not in audit_text
            assert verify_audit_log()[0] is True

            with patch("src.sqlite_store.append_audit_event", side_effect=OSError("offline")):
                try:
                    repository.create_detection_feedback(
                        alert["alert_id"], "BENIGN_EXPECTED", "", "tier-1", "analyst",
                    )
                    raise AssertionError("Audit failure must reject feedback")
                except OSError:
                    pass
            with sqlite3.connect(repository.path) as connection:
                assert connection.execute("SELECT COUNT(*) FROM detection_feedback").fetchone()[0] == 2
        finally:
            config.DASHBOARD_USERS_FILE = original_users
            config.ANALYST_AUDIT_FILE = original_audit


if __name__ == "__main__":
    test_detection_feedback()
    print("M20.1 analyst detection feedback passed")
