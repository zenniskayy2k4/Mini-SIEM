import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def test_viewer_workspace():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original_users = config.DASHBOARD_USERS_FILE
        original_audit = config.ANALYST_AUDIT_FILE
        config.DASHBOARD_USERS_FILE = str(directory / "users.json")
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        repository = SQLiteAlertRepository(str(directory / "alerts.db"))
        alert = build_alert(
            alert_name="Viewer incident", severity="HIGH", source_type="HIDS_LOG",
            description="Read-only fixture", incident_status="INVESTIGATING",
            rule_id="DET-VIEW-001", mitre_attck_id="T1110",
        )
        repository.create_alert(alert)
        try:
            client = dashboard.app.test_client()
            login_as(client, directory, role="viewer", username="soc-viewer")
            with patch.object(dashboard, "alert_repository", repository):
                page = client.get("/")
                assert page.status_code == 200
                html = page.get_data(as_text=True)
                assert "Viewer workspace" in html and "Read-only SOC visibility" in html
                assert 'id="viewer-kpis"' in html and "Detection Coverage" in html
                assert "Incident Status" in html
                assert 'href="/settings"' not in html and 'href="/assets"' not in html
                assert 'content="viewer"' in html

                for endpoint in (
                    "/api/alerts", "/api/alerts/search",
                    "/api/stats", "/api/detection-coverage", "/api/analytics/kpis",
                ):
                    response = client.get(endpoint)
                    assert response.status_code == 200, endpoint
                stored = client.get("/api/alerts").get_json()[0]
                assert stored["incident_status"] == "INVESTIGATING"

                mutations = (
                    ("post", f"/api/alerts/{alert['alert_id']}/notes", {"note": "blocked"}),
                    ("patch", f"/api/alerts/{alert['alert_id']}/status", {"status": "RESOLVED"}),
                    ("patch", f"/api/alerts/{alert['alert_id']}/assignee", {"assigned_to": "viewer"}),
                    ("post", f"/api/alerts/{alert['alert_id']}/response-actions", {
                        "action_type": "BLOCK_IP", "target": "203.0.113.9",
                    }),
                    ("post", f"/api/alerts/{alert['alert_id']}/external-case", {}),
                    ("post", f"/api/alerts/{alert['alert_id']}/feedback", {
                        "classification": "TRUE_POSITIVE", "reason": "",
                    }),
                    ("post", "/api/settings/update", {"GRAPH_AUTO_REFRESH": False}),
                )
                for method, endpoint, body in mutations:
                    assert getattr(client, method)(endpoint, json=body).status_code == 403, endpoint
                assert repository.get_alert(alert["alert_id"])["incident_status"] == "INVESTIGATING"
        finally:
            config.DASHBOARD_USERS_FILE = original_users
            config.ANALYST_AUDIT_FILE = original_audit


if __name__ == "__main__":
    test_viewer_workspace()
    print("M17.1 viewer workspace passed")
