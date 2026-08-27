import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


DEFAULTS = {
    "DEPLOYMENT_ENV": "development",
    "AI_PROVIDER": "ollama_cloud",
    "AI_FALLBACK_PROVIDER": "",
    "DASHBOARD_COOKIE_SECURE": "false",
    "DASHBOARD_HOST": "0.0.0.0",
    "DASHBOARD_PUBLIC_URL": "http://localhost:5000",
    "ALERT_RETENTION_DAYS": "90",
    "INGESTION_FAILURE_RETENTION_DAYS": "30",
    "RESPONSE_MODE": "simulation",
    "CASE_EXPORT_ENABLED": "false",
    "CASE_EXPORT_PROVIDER": "thehive",
}
TRUE = {"1", "true", "yes", "on"}
FALSE = {"0", "false", "no", "off", ""}
PROVIDERS = {"ollama_cloud", "ollama_local"}
RESPONSE_MODES = {"disabled", "simulation", "manual", "automatic"}


def load_environment(path=".env", environ=None):
    values = {}
    env_path = Path(path)
    if env_path.exists():
        for number, raw_line in enumerate(env_path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                raise ValueError(f"Invalid .env assignment on line {number}")
            key, value = (part.strip() for part in line.split("=", 1))
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                raise ValueError(f"Invalid .env variable name on line {number}")
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            values[key] = value
    values.update(dict(os.environ if environ is None else environ))
    return values


def validate(values):
    issues = []

    def value(name):
        return str(values.get(name, DEFAULTS.get(name, ""))).strip()

    def add(level, name, message):
        issues.append({"level": level, "field": name, "message": message})

    def boolean(name):
        raw = value(name).lower()
        if raw in TRUE:
            return True
        if raw in FALSE:
            return False
        add("ERROR", name, "must be true or false")
        return None

    deployment = value("DEPLOYMENT_ENV").lower()
    if deployment not in {"development", "production"}:
        add("ERROR", "DEPLOYMENT_ENV", "must be development or production")
    production = deployment == "production"

    cookie_secure = boolean("DASHBOARD_COOKIE_SECURE")
    case_export = boolean("CASE_EXPORT_ENABLED")
    debug = boolean("FLASK_DEBUG")

    required = []
    if production:
        required.extend(("DASHBOARD_SESSION_SECRET", "METRICS_BEARER_TOKEN"))
    if case_export:
        provider = value("CASE_EXPORT_PROVIDER").lower()
        if provider == "thehive":
            required.extend(("THEHIVE_URL", "THEHIVE_API_KEY"))
        elif provider == "jira":
            required.extend(("JIRA_URL", "JIRA_USER_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"))
        else:
            add("ERROR", "CASE_EXPORT_PROVIDER", "must be thehive or jira")
    for name in required:
        if not value(name):
            add("ERROR", name, "is required for the selected deployment configuration")

    for name in ("DASHBOARD_SESSION_SECRET", "WINDOWS_COLLECTOR_SECRET", "METRICS_BEARER_TOKEN"):
        if value(name) and len(value(name)) < 32:
            add("ERROR", name, "must contain at least 32 characters")

    public_url = urlparse(value("DASHBOARD_PUBLIC_URL"))
    public_url_valid = public_url.scheme in {"http", "https"} and bool(public_url.netloc)
    if not public_url_valid:
        add("ERROR", "DASHBOARD_PUBLIC_URL", "must be an absolute HTTP(S) URL")
    elif cookie_secure is True and public_url.scheme != "https":
        add("ERROR", "DASHBOARD_COOKIE_SECURE", "requires an HTTPS DASHBOARD_PUBLIC_URL")
    elif production and cookie_secure is not True:
        add("ERROR", "DASHBOARD_COOKIE_SECURE", "must be true in production")
    elif public_url.scheme == "https" and cookie_secure is False:
        add("WARNING", "DASHBOARD_COOKIE_SECURE", "should be true when the public URL uses HTTPS")
    if production and public_url_valid and public_url.scheme != "https":
        add("ERROR", "DASHBOARD_PUBLIC_URL", "must use HTTPS in production")

    primary = value("AI_PROVIDER").lower()
    fallback = value("AI_FALLBACK_PROVIDER").lower()
    if primary not in PROVIDERS:
        add("ERROR", "AI_PROVIDER", "must be ollama_cloud or ollama_local")
    if fallback and fallback not in PROVIDERS:
        add("ERROR", "AI_FALLBACK_PROVIDER", "must be empty, ollama_cloud or ollama_local")
    if fallback and fallback == primary:
        add("ERROR", "AI_FALLBACK_PROVIDER", "must differ from AI_PROVIDER")
    if "ollama_cloud" in {primary, fallback} and not value("OLLAMA_API_KEY"):
        add("WARNING", "OLLAMA_API_KEY", "is empty; the Ollama Cloud provider will be unavailable")

    for name in ("ALERT_RETENTION_DAYS", "INGESTION_FAILURE_RETENTION_DAYS"):
        try:
            valid = int(value(name)) >= 1
        except ValueError:
            valid = False
        if not valid:
            add("ERROR", name, "must be a positive integer")

    if value("RESPONSE_MODE").lower() not in RESPONSE_MODES:
        add("ERROR", "RESPONSE_MODE", "must be disabled, simulation, manual or automatic")

    webhook = value("NOTIFICATION_WEBHOOK_URL")
    if webhook:
        parsed = urlparse(webhook)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            add("ERROR", "NOTIFICATION_WEBHOOK_URL", "must be an absolute HTTP(S) URL")
        elif production and parsed.scheme != "https":
            add("ERROR", "NOTIFICATION_WEBHOOK_URL", "must use HTTPS in production")

    if value("DASHBOARD_HOST").lower() in {"0.0.0.0", "::", "[::]"}:
        add("WARNING", "DASHBOARD_HOST", "binds every interface; restrict it or enforce firewall/proxy controls")
    if production and debug is True:
        add("ERROR", "FLASK_DEBUG", "must be false in production")

    return issues


def main():
    try:
        issues = validate(load_environment())
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR [ENV_FILE] {exc}", file=sys.stderr)
        return 1
    for issue in issues:
        print(f"{issue['level']} [{issue['field']}] {issue['message']}")
    errors = sum(issue["level"] == "ERROR" for issue in issues)
    warnings = sum(issue["level"] == "WARNING" for issue in issues)
    print(f"Configuration validation: {'FAIL' if errors else 'PASS'} ({errors} errors, {warnings} warnings)")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
