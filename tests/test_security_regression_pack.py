import tempfile
from pathlib import Path
from unittest.mock import patch

from config import config
from dashboard import app
from src.alert_schema import build_alert
from src.dashboard_auth import (
    clear_login_failures,
    record_login_failure,
    save_user,
)
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def test_security_regression_pack():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original = (
            config.DASHBOARD_USERS_FILE,
            config.ANALYST_AUDIT_FILE,
            config.WINDOWS_COLLECTOR_SECRET,
            app.config["SESSION_COOKIE_SECURE"],
        )
        config.DASHBOARD_USERS_FILE = str(directory / "users.json")
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        repository = SQLiteAlertRepository(str(directory / "alerts.db"))
        alert = build_alert(
            alert_name="Security regression",
            severity="HIGH",
            source_type="HIDS_LOG",
            description="deployment security boundary",
        )
        repository.create_alert(alert)

        try:
            viewer = app.test_client()
            login_as(viewer, directory, "viewer", "security-viewer")
            assert viewer.get("/settings").status_code == 403  # RBAC denial

            analyst = app.test_client()
            login_as(analyst, directory, "analyst", "security-analyst")
            assert analyst.post(
                f"/api/alerts/{alert['alert_id']}/notes",
                json={"note": "missing CSRF"},
                headers={"X-CSRF-Token": "invalid"},
            ).status_code == 400

            revoked = app.test_client()
            login_as(revoked, directory, "analyst", "revoked-analyst")
            save_user("revoked-analyst", "replacement-password-123", "analyst")
            assert revoked.get("/api/alerts").status_code == 401

            throttled = app.test_client()
            save_user("throttled-user", "throttled-password-123", "viewer")
            throttled.get("/login")
            with throttled.session_transaction() as session:
                token = session["csrf_token"]
            clear_login_failures("127.0.0.1")
            for _ in range(5):
                record_login_failure("127.0.0.1")
            assert throttled.post("/login", data={
                "username": "throttled-user",
                "password": "throttled-password-123",
                "csrf_token": token,
            }).status_code == 429
            clear_login_failures("127.0.0.1")

            with patch("src.alert_store.alert_repository", repository):
                response = analyst.post(
                    f"/api/alerts/{alert['alert_id']}/notes",
                    json={"note": "<script>alert(1)</script>"},
                )
            note = response.get_json()["analyst_notes"][-1]["text"]
            assert response.status_code == 200
            assert "<script>" not in note and "&lt;script&gt;" in note

            config.WINDOWS_COLLECTOR_SECRET = "collector-security-secret"
            assert app.test_client().post(
                "/api/windows-events",
                headers={"X-Mini-SIEM-Secret": "collector-security-secret"},
                data=b"x" * (2 * 1024 * 1024 + 1),
            ).status_code == 413
            assert app.test_client().post(
                "/api/windows-events", json={"events": ["untrusted"]},
            ).status_code == 401

            app.config["SESSION_COOKIE_SECURE"] = True
            secure = app.test_client()
            save_user("secure-user", "secure-cookie-password-123", "viewer")
            secure.get("/login", base_url="https://localhost")
            with secure.session_transaction() as session:
                token = session["csrf_token"]
            response = secure.post("/login", base_url="https://localhost", data={
                "username": "secure-user",
                "password": "secure-cookie-password-123",
                "csrf_token": token,
            })
            cookie = response.headers.get("Set-Cookie", "")
            assert response.status_code == 302
            assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
        finally:
            clear_login_failures("127.0.0.1")
            (
                config.DASHBOARD_USERS_FILE,
                config.ANALYST_AUDIT_FILE,
                config.WINDOWS_COLLECTOR_SECRET,
                app.config["SESSION_COOKIE_SECURE"],
            ) = original


if __name__ == "__main__":
    test_security_regression_pack()
    print("M22.4 security regression pack passed")
