import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import dashboard
from config import config
from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert
from src.audit import verify_audit_log
from src.sqlite_store import SQLiteAlertRepository, SQLiteAssetRepository
from src.storage import DualWriteAlertRepository, JsonAlertRepository
from tests.auth_helpers import login_as


def test_configurable_alert_suppression():
    original = {
        "DASHBOARD_USERS_FILE": config.DASHBOARD_USERS_FILE,
        "ANALYST_AUDIT_FILE": config.ANALYST_AUDIT_FILE,
        "OUTPUT_ALERT_FILE": config.OUTPUT_ALERT_FILE,
        "SQLITE_ALERT_DB": config.SQLITE_ALERT_DB,
    }
    with tempfile.TemporaryDirectory() as directory_name:
        root = Path(directory_name)
        config.DASHBOARD_USERS_FILE = str(root / "users.json")
        config.ANALYST_AUDIT_FILE = str(root / "audit.jsonl")
        config.OUTPUT_ALERT_FILE = str(root / "alerts.jsonl")
        config.SQLITE_ALERT_DB = str(root / "alerts.db")
        sqlite_repository = SQLiteAlertRepository(config.SQLITE_ALERT_DB)
        repository = DualWriteAlertRepository(JsonAlertRepository(), sqlite_repository)
        assets = SQLiteAssetRepository(config.SQLITE_ALERT_DB)

        try:
            viewer = dashboard.app.test_client()
            login_as(viewer, root, role="viewer", username="suppression-viewer")
            with patch.object(dashboard, "alert_repository", repository):
                assert viewer.get("/api/alert-suppression-policies").status_code == 403
                assert viewer.post("/api/alert-suppression-policies", json={}).status_code == 403

            admin = dashboard.app.test_client()
            login_as(admin, root, role="admin", username="suppression-admin")
            with patch.object(dashboard, "alert_repository", repository):
                invalid = [
                    {"rule_id": "", "correlation_key": "AUTH|host", "window_seconds": 60},
                    {"rule_id": "DET-AUTH", "correlation_key": "*", "window_seconds": 60},
                    {"rule_id": "DET-AUTH", "correlation_key": "AUTH|host", "window_seconds": True},
                    {"rule_id": "DET-AUTH", "correlation_key": "AUTH|host", "window_seconds": 86401},
                    {"rule_id": "DET-AUTH", "correlation_key": "AUTH|host", "window_seconds": 60, "creator": "spoof"},
                ]
                assert all(
                    admin.post("/api/alert-suppression-policies", json=body).status_code == 400
                    for body in invalid
                )
                response = admin.post("/api/alert-suppression-policies", json={
                    "rule_id": "DET-AUTH",
                    "correlation_key": "AUTH|192.0.2.10",
                    "window_seconds": 60,
                })
                assert response.status_code == 201
                policy = response.get_json()
                assert policy["policy_id"].startswith("SUP-")
                assert policy["creator"] == "suppression-admin"
                assert admin.post("/api/alert-suppression-policies", json={
                    "rule_id": "DET-AUTH",
                    "correlation_key": "AUTH|192.0.2.10",
                    "window_seconds": 120,
                }).status_code == 400
                assert admin.get("/api/alert-suppression-policies").get_json() == {
                    "policies": [policy]
                }
                assert 'id="suppression-policy-form"' in admin.get("/settings").get_data(as_text=True)

            base = datetime.now(timezone.utc) + timedelta(seconds=1)

            def alert_at(seconds, *, key="AUTH|192.0.2.10", rule="DET-AUTH"):
                return build_alert(
                    alert_name="Repeated authentication alert", severity="HIGH",
                    source_type="HIDS_LOG", description="Valid detection",
                    raw_log=f"event at {seconds}", ip_address="192.0.2.10",
                    rule_id=rule, correlation_key=key, timestamp=base + timedelta(seconds=seconds),
                )

            first = repository.apply_alert_suppression(alert_at(0))
            assert first["suppressed"] is False
            assert first["alert"]["suppressed_count"] == 0
            assert first["alert"]["suppression_policy"]["policy_id"] == policy["policy_id"]
            repository.create_alert(first["alert"])

            ai = Mock()
            repeated = alert_at(10)
            with (
                patch("src.alert_pipeline.alert_repository", repository),
                patch("src.alert_store.alert_repository", repository),
                patch("src.alert_pipeline.notification_service.notify") as notify,
            ):
                grouped = persist_and_enrich(
                    repeated, ai_analyst=ai, stix_store=None, asset_repository=assets,
                )
            assert grouped["alert_id"] == first["alert"]["alert_id"]
            assert grouped["suppressed_count"] == 1 and grouped["event_count"] == 2
            assert grouped["first_seen"] == first["alert"]["first_seen"]
            assert grouped["last_seen"] == alert_at(10)["last_seen"]
            assert grouped["raw_log"] == "event at 0"
            assert repository.list_alerts()[0]["suppressed_count"] == 1
            assert len(repository.list_alerts()) == 1
            notify.assert_not_called()
            ai.enrich_async.assert_not_called()

            wrong_key = repository.apply_alert_suppression(alert_at(20, key="AUTH|192.0.2.11"))
            wrong_rule = repository.apply_alert_suppression(alert_at(20, rule="DET-OTHER"))
            assert wrong_key["policy"] is None and wrong_rule["policy"] is None

            outside = repository.apply_alert_suppression(alert_at(120))
            assert outside["suppressed"] is False and outside["alert"]["suppressed_count"] == 0
            repository.create_alert(outside["alert"])
            assert len(repository.list_alerts()) == 2

            rollback = repository.create_alert_suppression_policy(
                "DET-ROLLBACK", "ROLLBACK|host", 30, "suppression-admin", "admin",
            )
            with patch("src.sqlite_store.append_audit_event", side_effect=OSError("offline")):
                try:
                    repository.delete_alert_suppression_policy(
                        rollback["policy_id"], "suppression-admin", "admin",
                    )
                    raise AssertionError("Audit failure must reject policy deletion")
                except OSError:
                    pass
            assert any(
                item["policy_id"] == rollback["policy_id"]
                for item in repository.list_alert_suppression_policies()
            )

            with patch.object(dashboard, "alert_repository", repository):
                assert admin.delete(
                    f"/api/alert-suppression-policies/{policy['policy_id']}",
                    headers={"X-CSRF-Token": "bad"},
                ).status_code == 400
                assert admin.delete(
                    f"/api/alert-suppression-policies/{policy['policy_id']}"
                ).status_code == 204
                assert admin.delete(
                    f"/api/alert-suppression-policies/{policy['policy_id']}"
                ).status_code == 404

            events = [
                json.loads(line)
                for line in Path(config.ANALYST_AUDIT_FILE).read_text(encoding="utf-8").splitlines()
            ]
            assert events[0]["event_type"] == "ALERT_SUPPRESSION_POLICY_CREATED"
            assert events[-1]["event_type"] == "ALERT_SUPPRESSION_POLICY_DELETED"
            assert verify_audit_log()[0] is True
            script = admin.get("/static/js/app.js").get_data(as_text=True)
            assert "suppression-summary" in script and "suppressed" in script
        finally:
            for key, value in original.items():
                setattr(config, key, value)


if __name__ == "__main__":
    test_configurable_alert_suppression()
    print("M20.4 configurable alert suppression passed")
