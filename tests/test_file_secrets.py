import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from flask import Flask

from config.secrets import read_secret
from src.dashboard_auth import init_auth
from tools.validate_config import validate


def test_file_secrets():
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        secret = "file-secret-" + "x" * 32
        path = directory / "session"
        path.write_text(secret + "\n", encoding="utf-8")

        assert read_secret("TOKEN", {"TOKEN": "existing-env"}) == "existing-env"
        assert read_secret("TOKEN", {"TOKEN_FILE": str(path)}) == secret

        conflict = {"TOKEN": "do-not-log-this", "TOKEN_FILE": str(path)}
        try:
            read_secret("TOKEN", conflict)
            raise AssertionError("environment/file conflict must fail")
        except RuntimeError as exc:
            assert "do-not-log-this" not in str(exc) and str(path) not in str(exc)

        bad_path = directory / "private-do-not-log"
        try:
            read_secret("TOKEN", {"TOKEN_FILE": str(bad_path)})
            raise AssertionError("missing secret file must fail")
        except RuntimeError as exc:
            assert str(bad_path) not in str(exc)

        for invalid_secret in (b"", b"\xff"):
            path.write_bytes(invalid_secret)
            try:
                read_secret("TOKEN", {"TOKEN_FILE": str(path)})
                raise AssertionError("empty or non-UTF-8 secret must fail")
            except RuntimeError:
                pass
        path.write_text("first-line\nsecond-line", encoding="utf-8")
        try:
            read_secret("TOKEN", {"TOKEN_FILE": str(path)})
            raise AssertionError("multi-line secret must fail")
        except RuntimeError:
            pass
        path.write_bytes(b"x" * (64 * 1024 + 1))
        try:
            read_secret("TOKEN", {"TOKEN_FILE": str(path)})
            raise AssertionError("oversized secret must fail")
        except RuntimeError:
            pass
        path.write_text(secret + "\n", encoding="utf-8")

        with patch.dict(os.environ, {
            "DASHBOARD_SESSION_SECRET": "", "DASHBOARD_SESSION_SECRET_FILE": str(path),
        }, clear=False):
            app = Flask(__name__)
            init_auth(app)
            assert app.config["SECRET_KEY"] == secret

        issues = validate({
            "DEPLOYMENT_ENV": "production",
            "AI_PROVIDER": "ollama_local",
            "DASHBOARD_SESSION_SECRET_FILE": str(path),
            "METRICS_BEARER_TOKEN_FILE": str(path),
            "DASHBOARD_COOKIE_SECURE": "true",
            "DASHBOARD_PUBLIC_URL": "https://siem.example.test",
            "DASHBOARD_HOST": "127.0.0.1",
            "FLASK_DEBUG": "false",
        })
        assert issues == []

        conflict_issues = validate({
            "AI_PROVIDER": "ollama_cloud",
            "OLLAMA_API_KEY": "validator-do-not-log",
            "OLLAMA_API_KEY_FILE": str(path),
        })
        assert any(
            issue["field"] == "OLLAMA_API_KEY" and issue["level"] == "ERROR"
            for issue in conflict_issues
        )
        assert "validator-do-not-log" not in str(conflict_issues) and str(path) not in str(conflict_issues)


if __name__ == "__main__":
    test_file_secrets()
    print("M22.3 file-based secrets passed")
