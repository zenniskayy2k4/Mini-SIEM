import json
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import dashboard
from config import config
from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert, ensure_lifecycle
from src.audit import verify_audit_log
from src.sqlite_store import SQLiteAlertRepository, SQLiteAssetRepository
from tests.auth_helpers import login_as


def test_scoped_detection_exceptions():
    with tempfile.TemporaryDirectory() as directory_name:
        root = Path(directory_name)
        repository = SQLiteAlertRepository(str(root / "alerts.db"))
        assets = SQLiteAssetRepository(str(root / "alerts.db"))
        original_users = config.DASHBOARD_USERS_FILE
        original_audit = config.ANALYST_AUDIT_FILE
        config.DASHBOARD_USERS_FILE = str(root / "users.json")
        config.ANALYST_AUDIT_FILE = str(root / "audit.jsonl")
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        try:
            viewer = dashboard.app.test_client()
            login_as(viewer, root, role="viewer", username="exception-viewer")
            with patch.object(dashboard, "alert_repository", repository):
                assert viewer.get("/api/detection-exceptions").status_code == 403
                assert viewer.post("/api/detection-exceptions", json={}).status_code == 403

            admin = dashboard.app.test_client()
            login_as(admin, root, role="admin", username="exception-admin")
            with patch.object(dashboard, "alert_repository", repository):
                assert admin.post(
                    "/api/detection-exceptions",
                    json={"scope_type": "rule_id", "scope_value": "*", "reason": "broad"},
                ).status_code == 400
                assert admin.post(
                    "/api/detection-exceptions",
                    json={"scope_type": "rule_id", "scope_value": "DET-001", "reason": ""},
                ).status_code == 400
                assert admin.post(
                    "/api/detection-exceptions",
                    json={"scope_type": "process_path", "scope_value": "cmd.exe", "reason": "narrow"},
                ).status_code == 400
                assert admin.post(
                    "/api/detection-exceptions",
                    json={
                        "scope_type": "rule_id", "scope_value": "DET-001", "reason": "expired",
                        "expires_at": "2020-01-01T00:00:00Z",
                    },
                ).status_code == 400
                assert admin.post(
                    "/api/detection-exceptions",
                    json={"scope_type": "rule_id", "scope_value": "DET-001", "reason": "valid", "creator": "spoof"},
                ).status_code == 400

                response = admin.post(
                    "/api/detection-exceptions",
                    json={
                        "scope_type": "source_ip", "scope_value": "192.0.2.44",
                        "reason": "approved scanner", "expires_at": future,
                    },
                )
                assert response.status_code == 201
                created = response.get_json()
                assert created["exception_id"].startswith("DEX-")
                assert created["creator"] == "exception-admin" and created["active"] is True
                assert admin.get("/api/detection-exceptions").get_json()["exceptions"] == [created]
                page = admin.get("/settings").get_data(as_text=True)
                assert 'id="detection-exception-form"' in page

            fixtures = {
                "hostname": ("WIN-01", {"computer": "win-01"}),
                "source_ip": ("192.0.2.45", {"ip_address": "192.0.2.45"}),
                "user": ("EXAMPLE\\analyst", {"user": "example\\ANALYST"}),
                "process_path": (r"C:\\Windows\\System32\\cmd.exe", {"process": {"image": r"c:\\windows\\system32\\CMD.EXE"}}),
                "rule_id": ("DET-EXCEPTION-001", {"rule_id": "det-exception-001"}),
                "asset_id": ("AST-00000000-0000-0000-0000-000000000001", {"asset_id": "ast-00000000-0000-0000-0000-000000000001"}),
            }
            for scope_type, (scope_value, alert_fields) in fixtures.items():
                record = repository.create_detection_exception(
                    scope_type, scope_value, f"fixture {scope_type}", "exception-admin", "admin",
                )
                match = repository.match_detection_exception(alert_fields)
                assert match["exception_id"] == record["exception_id"]
                assert match["scope_type"] == scope_type and match["matched_at"]

            alert = build_alert(
                alert_name="Excepted fixture", severity="HIGH", source_type="HIDS_LOG",
                description="Original evidence", raw_log="immutable raw event",
                ip_address="192.0.2.44", rule_id="DET-OTHER",
            )
            ai = Mock()
            with (
                patch("src.alert_pipeline.alert_repository", repository),
                patch("src.alert_pipeline.upsert_alert", side_effect=repository.create_alert),
                patch("src.alert_pipeline.notification_service.notify") as notify,
            ):
                persisted = persist_and_enrich(
                    alert, ai_analyst=ai, stix_store=None, asset_repository=assets,
                )
            assert persisted["status"] == "EXCEPTED"
            assert persisted["incident_id"] is None and persisted["incident_status"] is None
            assert persisted["raw_log"] == "immutable raw event"
            assert persisted["detection_exception_match"]["exception_id"] == created["exception_id"]
            assert repository.get_alert(alert["alert_id"])["raw_log"] == "immutable raw event"
            assert ensure_lifecycle(persisted)["incident_id"] is None
            notify.assert_not_called()
            ai.enrich_async.assert_not_called()

            with patch("src.sqlite_store.append_audit_event", side_effect=OSError("offline")):
                try:
                    repository.create_detection_exception(
                        "rule_id", "DET-ROLLBACK", "must rollback", "exception-admin", "admin",
                    )
                    raise AssertionError("Audit failure must reject the exception")
                except OSError:
                    pass
            assert not any(
                item["scope_value"] == "DET-ROLLBACK"
                for item in repository.list_detection_exceptions()
            )

            with patch.object(dashboard, "alert_repository", repository):
                assert admin.delete(
                    f"/api/detection-exceptions/{created['exception_id']}",
                    headers={"X-CSRF-Token": "bad"},
                ).status_code == 400
                assert admin.delete(
                    f"/api/detection-exceptions/{created['exception_id']}"
                ).status_code == 204
                assert admin.delete(
                    f"/api/detection-exceptions/{created['exception_id']}"
                ).status_code == 404

            with sqlite3.connect(repository.path) as connection:
                stored = connection.execute(
                    "SELECT payload_json FROM alerts WHERE alert_id = ?", (alert["alert_id"],),
                ).fetchone()[0]
                assert json.loads(stored)["raw_log"] == "immutable raw event"

            audit_text = Path(config.ANALYST_AUDIT_FILE).read_text(encoding="utf-8")
            events = [json.loads(line) for line in audit_text.splitlines()]
            assert events[0]["event_type"] == "DETECTION_EXCEPTION_CREATED"
            assert events[-1]["event_type"] == "DETECTION_EXCEPTION_DELETED"
            assert "approved scanner" not in audit_text and "must rollback" not in audit_text
            assert verify_audit_log()[0] is True
            script = admin.get("/static/js/app.js").get_data(as_text=True)
            assert "Detection exception matched" in script
        finally:
            config.DASHBOARD_USERS_FILE = original_users
            config.ANALYST_AUDIT_FILE = original_audit


if __name__ == "__main__":
    test_scoped_detection_exceptions()
    print("M20.3 scoped detection exceptions passed")
