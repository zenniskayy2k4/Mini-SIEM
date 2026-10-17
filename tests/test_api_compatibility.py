import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

import dashboard
from config import config
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


ROOT = Path(__file__).resolve().parents[1]


def _legacy_alert():
    return {
        "alert_id": "ALT-api-legacy",
        "timestamp": "2026-09-01T00:00:09Z",
        "alert_name": "Legacy API alert",
        "severity": "INFO",
        "status": "DETECTED",
        "source_type": "HIDS_LOG",
        "description": "Pre-versioned API fixture",
    }


def test_api_compatibility():
    contract = yaml.safe_load((ROOT / "docs" / "openapi-v1.yaml").read_text(encoding="utf-8"))
    alert_schema = contract["components"]["schemas"]["Alert"]
    required_alert_fields = set(alert_schema["required"])
    assert alert_schema["properties"]["event_count"]["minimum"] == 1
    assert alert_schema["properties"]["external_cases"]["type"] == "object"

    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original = config.DASHBOARD_USERS_FILE, config.ANALYST_AUDIT_FILE
        config.DASHBOARD_USERS_FILE = str(directory / "users.json")
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        repository = SQLiteAlertRepository(str(directory / "alerts.db"))
        current = []
        for index in range(4):
            alert = build_alert(
                alert_name=f"API compatibility {index}",
                severity="HIGH",
                source_type="HIDS_LOG",
                description="Current API fixture",
                timestamp=f"2026-09-01T00:00:0{index}Z",
            )
            repository.create_alert(alert)
            current.append(alert)

        legacy = _legacy_alert()
        with repository._connect() as connection:
            connection.execute(
                "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    legacy["alert_id"], legacy["timestamp"], legacy["alert_name"],
                    legacy["severity"], legacy["source_type"], None,
                    json.dumps(legacy), legacy["timestamp"], legacy["timestamp"],
                ),
            )

        try:
            anonymous = dashboard.app.test_client()
            unauthorized = anonymous.get("/api/v1/alerts")
            assert unauthorized.status_code == 401 and "error" in unauthorized.get_json()

            viewer = dashboard.app.test_client()
            login_as(viewer, directory, role="viewer", username="api-viewer")
            analyst = dashboard.app.test_client()
            login_as(analyst, directory, role="analyst", username="api-analyst")
            admin = dashboard.app.test_client()
            login_as(admin, directory, role="admin", username="api-admin")

            with (
                patch.object(dashboard, "alert_repository", repository),
                patch("src.alert_store.alert_repository", repository),
            ):
                alerts = viewer.get("/api/v1/alerts")
                assert alerts.status_code == 200
                payload = alerts.get_json()
                assert len(payload) == 5
                assert all(required_alert_fields <= set(alert) for alert in payload)
                normalized = next(alert for alert in payload if alert["alert_id"] == legacy["alert_id"])
                assert normalized["alert_schema_version"] == 1
                assert normalized["severity"] == "LOW"
                assert normalized["event_count"] == 1
                assert normalized["first_seen"] == normalized["last_seen"] == legacy["timestamp"]
                assert isinstance(normalized["external_cases"], dict)

                first = viewer.get("/api/v1/alerts/search?page=1&page_size=2").get_json()
                second = viewer.get("/api/v1/alerts/search?page=2&page_size=2").get_json()
                assert (first["total"], first["page"], first["page_size"], first["total_pages"]) == (5, 1, 2, 3)
                assert second["page"] == 2 and len(second["items"]) == 2
                assert {item["alert_id"] for item in first["items"]}.isdisjoint(
                    item["alert_id"] for item in second["items"]
                )

                target = current[0]["alert_id"]
                forbidden = viewer.post(
                    f"/api/v1/alerts/{target}/notes", json={"note": "blocked"},
                )
                assert forbidden.status_code == 403 and "error" in forbidden.get_json()
                assert viewer.get("/api/v1/detection-rules").status_code == 403
                assert analyst.get("/api/v1/detection-rules").status_code == 403
                assert admin.get("/api/v1/detection-rules").status_code == 200

                note = analyst.post(
                    f"/api/v1/alerts/{target}/notes", json={"note": "compatible"},
                )
                assert note.status_code == 200 and note.get_json()["analyst_notes"][-1]["text"] == "compatible"

                errors = (
                    analyst.patch(
                        f"/api/v1/alerts/{target}/status", json={"status": "INVALID"},
                    ),
                    viewer.get("/api/v1/alerts/ALT-missing/report.pdf"),
                    analyst.post(
                        f"/api/v1/alerts/{target}/feedback",
                        data=b"{" + b" " * 8192 + b"}",
                        content_type="application/json",
                    ),
                )
                assert [response.status_code for response in errors] == [400, 404, 413]
                assert all("error" in response.get_json() for response in errors)
        finally:
            config.DASHBOARD_USERS_FILE, config.ANALYST_AUDIT_FILE = original


if __name__ == "__main__":
    test_api_compatibility()
    print("M28.4 API compatibility regression passed")
