from pathlib import Path


SECRET_NAMES = (
    "OLLAMA_API_KEY",
    "THEHIVE_API_KEY",
    "JIRA_API_TOKEN",
    "ABUSEIPDB_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "TAXII_BEARER_TOKEN",
    "WINDOWS_COLLECTOR_SECRET",
    "DASHBOARD_SESSION_SECRET",
    "METRICS_BEARER_TOKEN",
)
MAX_SECRET_BYTES = 64 * 1024


def read_secret(name, environ):
    direct = str(environ.get(name, "") or "").strip()
    file_name = f"{name}_FILE"
    file_path = str(environ.get(file_name, "") or "").strip()
    if direct and file_path:
        raise RuntimeError(f"{name} and {file_name} cannot both be set")
    if not file_path:
        return direct
    try:
        path = Path(file_path)
        if not path.is_file():
            raise OSError
        with path.open("rb") as secret_file:
            raw_secret = secret_file.read(MAX_SECRET_BYTES + 1)
        if len(raw_secret) > MAX_SECRET_BYTES:
            raise OSError
        secret = raw_secret.decode("utf-8").strip()
    except (OSError, UnicodeError):
        raise RuntimeError(f"{file_name} cannot be read as a secret file") from None
    if not secret or any(character in secret for character in "\r\n\0"):
        raise RuntimeError(f"{file_name} must contain one non-empty secret")
    return secret
