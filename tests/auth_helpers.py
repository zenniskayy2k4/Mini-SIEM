from pathlib import Path

from config import config
from src.dashboard_auth import save_user


def login_as(client, directory, role="analyst", username="blue-team"):
    config.DASHBOARD_USERS_FILE = str(Path(directory, "dashboard_users.json"))
    save_user(username, "test-password-12345", role)
    with client.session_transaction() as session:
        session.update(username=username, role=role, csrf_token="test-csrf-token")
    client.environ_base["HTTP_X_CSRF_TOKEN"] = "test-csrf-token"
