# Troubleshooting runbook

Preserve evidence before changing state. Do not clear databases, alerts, logs, collector state,
models, or backups to make an error disappear.

## First response

Collect the same bounded evidence for every incident:

```powershell
docker compose ps
docker compose logs --tail 200 dashboard agent
docker compose run --rm dashboard python -m tools.doctor
(Invoke-WebRequest -UseBasicParsing http://localhost:5000/health).Content
```

An administrator can then open **Settings → System diagnostics** or request
`GET /api/system/status`. The authenticated diagnostics view connects database, ingestion,
rule-load, provider, integration, and collector state without exposing credentials. Record UTC
time, affected component, last known good change, and exact error class; redact payloads and secret
values before sharing output.

| Symptom | Inspect first | Safe next action |
|---|---|---|
| Health returns 503 | Public health fields, container state, queue/database status | Stop new ingestion; inspect diagnostics and service logs |
| No Windows events | Collector freshness, endpoint state, delivery counters, local buffer | Validate URL/secret/TLS and preserve collector state |
| AI unavailable or busy | AI diagnostics and configured provider/model | Fix configuration or wait for the shared worker; do not fan out probes |
| Rule did not load | Rule-load diagnostics and agent logs | Validate syntax/support, then restart both services after source changes |
| TI or case export failed | Integration state, bounded attempts, provider HTTP class | Validate configuration and egress; retry only after correcting the cause |
| Database unhealthy | Doctor integrity result and disk space | Stop both writers and follow the restore procedure |

## Collectors and ingestion

On the Windows host, preserve `%ProgramData%\Mini-SIEM` and inspect
`collector-diagnostics.json`, `collector-buffer.json`, and the Windows event channels. Never edit
cursor or buffer files while the collector is running.

Run one bounded delivery attempt from an elevated PowerShell session:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\windows_event_collector.ps1 `
  -ServerUrl <dashboard-url> -Secret $env:WINDOWS_COLLECTOR_SECRET -Once
```

Check these causes in order:

1. The dashboard URL is reachable from the Windows host and uses the expected TLS certificate.
2. Dashboard and collector use the same current shared secret.
3. The service account can read Sysmon, Security, and Defender channels.
4. Host time is synchronized and the collector identity/state directory survived restart.
5. The reported protocol version is supported by the server.
6. A full ingestion queue or repeated parser failure is visible in admin diagnostics.

HTTP 401 indicates a missing/mismatched secret; HTTP 400 indicates an invalid payload or unsupported
protocol; transport errors leave events in the local buffer. Do not delete the buffer to recover.

## Rule debugging

Native YAML lives under `config/rules/`; Sigma YAML lives under `config/sigma/`. Both directories
are read-only in the containers. Inspect the rule catalog and `skip_reason` in **Settings →
Detection Rules**, then search logs for loader warnings:

```powershell
docker compose logs --tail 200 agent dashboard
docker compose run --rm -v "${PWD}:/app" dashboard python -m tests.test_rule_loader
docker compose run --rm -v "${PWD}:/app" dashboard python -m tests.test_rule_matching
docker compose run --rm -v "${PWD}:/app" dashboard python -m tests.test_sigma_corpus
```

Compare rule fields with the normalized event envelope, not raw vendor field names. Sigma support
is intentionally bounded; unsupported modifiers and conditions remain disabled with a reason.
See [Sigma rule support](SIGMA_RULES.md). Restart `agent` and `dashboard` after source-file changes.

## AI debugging

The AI analyst uses one shared worker. A `busy` result means another analysis owns it; waiting or
reducing eligible alert volume is correct. Do not start concurrent health probes or direct retries.

1. Read AI state in `/api/system/status`; this does not consume an analysis request.
2. Run `tools.doctor` and `tools.validate_config` to check provider selection and key presence
   without printing the key.
3. For local Ollama, confirm the host service is running and the exact configured model is already
   installed with `ollama list`.
4. Confirm the container can reach the configured local base URL; `localhost` inside the container
   is not the Windows host.
5. Inspect the bounded provider attempt outcome. Fallback occurs inside the same worker and is
   attempted at most once.

AI failure does not block deterministic alert creation. Never paste raw alert payloads or provider
responses containing sensitive data into an issue.

## Threat intelligence and integrations

GeoIP, AbuseIPDB, VirusTotal, STIX/TAXII, notifications, TheHive, and Jira are optional. A disabled
provider is not a platform failure.

```powershell
docker compose run --rm dashboard python -m tools.validate_config
docker compose exec agent python tools/import_stix.py
docker compose logs --tail 200 agent dashboard
```

Run the STIX/TAXII import command only when exactly one offline bundle or configured TAXII URL is
selected. For an offline bundle, pass its container-visible path. Check DNS, HTTPS trust, egress,
timeouts, rate limits, and least-privilege credentials without logging request headers. VirusTotal
only performs hash metadata lookup; it never uploads a file.

Case export is manual and idempotent by incident. Confirm the selected provider, required project
fields, service-account permissions, and remote record search before retrying. Webhook and provider
attempts are bounded; do not add an external retry loop around them.

## Database, retention, and recovery

If doctor reports SQLite corruption, an unknown migration, or a non-writable data directory:

```powershell
docker compose stop agent dashboard
```

Do not run retention, migration, or ad-hoc SQL against a suspect database. Preserve the database,
WAL, SHM, logs, and latest backups, then follow
[Retention, backup and restore](RETENTION_BACKUP.md). Restart only after `PRAGMA integrity_check`
prints `ok` and the restored application health returns HTTP 200.

If disk space is low, identify the owner before deleting anything. Use application retention for
eligible alerts and documented log rotation. Never run `docker volume prune` as an application
recovery step.
