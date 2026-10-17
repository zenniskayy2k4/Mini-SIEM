import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def test_api_v1():
    rules = {rule.endpoint: rule for rule in dashboard.app.url_map.iter_rules()}
    for endpoint in dashboard.V1_API_ENDPOINTS:
        legacy, versioned = rules[endpoint], rules[f"v1_{endpoint}"]
        assert versioned.rule == legacy.rule.replace("/api/", "/api/v1/", 1)
        assert versioned.methods == legacy.methods
        assert dashboard.app.view_functions[versioned.endpoint] is dashboard.app.view_functions[endpoint]

    paths = {rule.rule for rule in dashboard.app.url_map.iter_rules()}
    assert "/api/v1/settings" not in paths
    assert "/api/v1/windows-events" not in paths

    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original_users = config.DASHBOARD_USERS_FILE
        config.DASHBOARD_USERS_FILE = str(directory / "users.json")
        repository = SQLiteAlertRepository(str(directory / "alerts.db"))
        repository.create_alert(build_alert(
            alert_name="API v1 contract", severity="HIGH", source_type="HIDS_LOG",
            description="Compatibility fixture",
        ))
        try:
            anonymous = dashboard.app.test_client()
            assert anonymous.get("/api/alerts").status_code == 401
            assert anonymous.get("/api/v1/alerts").status_code == 401

            client = dashboard.app.test_client()
            login_as(client, directory, role="viewer", username="api-viewer")
            with patch.object(dashboard, "alert_repository", repository):
                legacy = client.get("/api/alerts")
                versioned = client.get("/api/v1/alerts")
            assert legacy.status_code == versioned.status_code == 200
            assert legacy.get_json() == versioned.get_json()
            assert legacy.headers["Deprecation"] == "true"
            assert legacy.headers["Link"] == '</api/v1/alerts>; rel="successor-version"'
            assert "Deprecation" not in versioned.headers
        finally:
            config.DASHBOARD_USERS_FILE = original_users


if __name__ == "__main__":
    test_api_v1()
    print("M28.1 REST API v1 passed")
