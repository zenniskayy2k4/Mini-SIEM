# File-based secrets

Every persistent application secret supports either its existing environment variable or the matching `*_FILE` variable. Set exactly one; setting both fails at startup and validation. Secret files must be UTF-8, single-line, non-empty, and no larger than 64 KiB. Diagnostics name only the variable and never include the path or secret content.

Example:

```dotenv
DASHBOARD_SESSION_SECRET=
DASHBOARD_SESSION_SECRET_FILE=/run/secrets/dashboard_session_secret
```

For Docker Compose, keep secret files under the gitignored `secrets/` directory and mount only the files each service needs. A local override can use native Compose secrets:

```yaml
services:
  dashboard:
    environment:
      DASHBOARD_SESSION_SECRET_FILE: /run/secrets/dashboard_session_secret
    secrets:
      - dashboard_session_secret

secrets:
  dashboard_session_secret:
    file: ./secrets/dashboard_session_secret
```

Run `python -m tools.validate_config` before deployment; when paths such as `/run/secrets/...` exist only inside a container, run the validator in that same container. Existing environment-only configuration remains supported unchanged. Supported names are `OLLAMA_API_KEY_FILE`, `THEHIVE_API_KEY_FILE`, `JIRA_API_TOKEN_FILE`, `ABUSEIPDB_API_KEY_FILE`, `VIRUSTOTAL_API_KEY_FILE`, `TAXII_BEARER_TOKEN_FILE`, `WINDOWS_COLLECTOR_SECRET_FILE`, `DASHBOARD_SESSION_SECRET_FILE`, and `METRICS_BEARER_TOKEN_FILE`.
