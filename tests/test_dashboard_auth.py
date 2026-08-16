import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from config import config
from dashboard import app
from src.alert_schema import build_alert
from src.dashboard_auth import save_user
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def _csrf(client):
    with client.session_transaction() as session:
        return session["csrf_token"]


def test_dashboard_auth():
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        original_users_file = config.DASHBOARD_USERS_FILE
        original_audit_file = config.ANALYST_AUDIT_FILE
        config.DASHBOARD_USERS_FILE = str(directory / "users.json")
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        save_user("viewer", "viewer-password-123", "viewer")
        save_user("analyst", "analyst-password-123", "analyst")
        save_user("admin", "admin-password-12345", "admin")
        users_text = Path(config.DASHBOARD_USERS_FILE).read_text(encoding="utf-8")
        assert "viewer-password-123" not in users_text
        assert "password_hash" in users_text

        repository = SQLiteAlertRepository(str(directory / "alerts.db"))
        alert = build_alert(
            alert_name="Auth test",
            severity="HIGH",
            source_type="HIDS_LOG",
            description="role matrix",
        )
        repository.create_alert(alert)
        try:
            client = app.test_client()
            assert client.get("/").status_code == 302
            assert client.get("/api/alerts").status_code == 401
            client.get("/login")
            assert client.post("/login", data={
                "username": "viewer", "password": "viewer-password-123", "csrf_token": "bad",
            }).status_code == 400
            token = _csrf(client)
            assert client.post("/login", data={
                "username": "viewer", "password": "wrong-password", "csrf_token": token,
            }).status_code == 401
            login_response = client.post("/login", data={
                "username": "viewer", "password": "viewer-password-123", "csrf_token": token,
            })
            assert login_response.status_code == 302
            cookie = login_response.headers.get("Set-Cookie", "")
            assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
            viewer_csrf = _csrf(client)
            assert client.get("/api/alerts").status_code == 200
            assert client.get("/settings").status_code == 403
            assert client.post(
                f"/api/alerts/{alert['alert_id']}/notes",
                json={"note": "viewer must fail"},
                headers={"X-CSRF-Token": viewer_csrf},
            ).status_code == 403
            users = json.loads(Path(config.DASHBOARD_USERS_FILE).read_text(encoding="utf-8"))
            users.pop("viewer")
            Path(config.DASHBOARD_USERS_FILE).write_text(json.dumps(users), encoding="utf-8")
            assert client.get("/api/alerts").status_code == 401

            analyst = app.test_client()
            login_as(analyst, directory, "analyst", "analyst")
            assert analyst.post(
                f"/api/alerts/{alert['alert_id']}/notes", json={"note": "missing csrf"},
                headers={"X-CSRF-Token": "bad"},
            ).status_code == 400
            with patch("src.alert_store.alert_repository", repository):
                note = analyst.post(
                    f"/api/alerts/{alert['alert_id']}/notes", json={"note": "triaged"},
                )
                assert note.status_code == 200
                assert note.get_json()["analyst_notes"][-1]["author"] == "analyst"
                status = analyst.patch(
                    f"/api/alerts/{alert['alert_id']}/status", json={"status": "INVESTIGATING"},
                )
                assert status.status_code == 200
            assert analyst.get("/settings").status_code == 403

            admin = app.test_client()
            login_as(admin, directory, "admin", "admin")
            with patch("dashboard.RUNTIME_SETTINGS_FILE", str(directory / "runtime.json")):
                assert admin.get("/settings").status_code == 200
                assert admin.post(
                    "/api/settings/update", json={"GRAPH_AUTO_REFRESH": False},
                ).status_code == 200
            logout = admin.post("/logout")
            assert logout.status_code == 302
            assert admin.get("/api/alerts").status_code == 401
        finally:
            config.DASHBOARD_USERS_FILE = original_users_file
            config.ANALYST_AUDIT_FILE = original_audit_file


if __name__ == "__main__":
    test_dashboard_auth()
    print("M8.1 dashboard authentication passed")
