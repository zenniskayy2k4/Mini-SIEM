import tempfile
from pathlib import Path

from tools.validate_config import load_environment, validate


def test_config_validator():
    valid = {
        "DEPLOYMENT_ENV": "production",
        "AI_PROVIDER": "ollama_local",
        "DASHBOARD_SESSION_SECRET": "s" * 32,
        "METRICS_BEARER_TOKEN": "m" * 32,
        "DASHBOARD_COOKIE_SECURE": "true",
        "DASHBOARD_PUBLIC_URL": "https://siem.example.test",
        "DASHBOARD_HOST": "127.0.0.1",
        "ALERT_RETENTION_DAYS": "90",
        "INGESTION_FAILURE_RETENTION_DAYS": "30",
        "RESPONSE_MODE": "simulation",
        "FLASK_DEBUG": "false",
    }
    assert validate(valid) == []

    secret = "must-never-appear-in-diagnostics"
    invalid = {
        "DEPLOYMENT_ENV": "production",
        "AI_PROVIDER": "ollama_cloud",
        "AI_FALLBACK_PROVIDER": "ollama_cloud",
        "OLLAMA_API_KEY": secret,
        "DASHBOARD_SESSION_SECRET": "short",
        "DASHBOARD_COOKIE_SECURE": "false",
        "DASHBOARD_PUBLIC_URL": "http://siem.example.test",
        "DASHBOARD_HOST": "0.0.0.0",
        "ALERT_RETENTION_DAYS": "0",
        "INGESTION_FAILURE_RETENTION_DAYS": "invalid",
        "RESPONSE_MODE": "shell",
        "NOTIFICATION_WEBHOOK_URL": "ftp://example.test/hook",
        "FLASK_DEBUG": "true",
    }
    issues = validate(invalid)
    errors = {issue["field"] for issue in issues if issue["level"] == "ERROR"}
    assert {
        "METRICS_BEARER_TOKEN", "DASHBOARD_SESSION_SECRET", "DASHBOARD_COOKIE_SECURE",
        "DASHBOARD_PUBLIC_URL", "AI_FALLBACK_PROVIDER", "ALERT_RETENTION_DAYS",
        "INGESTION_FAILURE_RETENTION_DAYS", "RESPONSE_MODE", "NOTIFICATION_WEBHOOK_URL",
        "FLASK_DEBUG",
    } <= errors
    assert any(issue["field"] == "DASHBOARD_HOST" and issue["level"] == "WARNING" for issue in issues)
    assert secret not in str(issues)

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / ".env"
        path.write_text("AI_PROVIDER=ollama_local\nRESPONSE_MODE=simulation\n", encoding="utf-8")
        loaded = load_environment(path, {"RESPONSE_MODE": "manual"})
        assert loaded == {"AI_PROVIDER": "ollama_local", "RESPONSE_MODE": "manual"}


if __name__ == "__main__":
    test_config_validator()
    print("M22.1 deployment configuration validator passed")
