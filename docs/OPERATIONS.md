# Operations runbook

This runbook covers routine operation of the single-node Docker Compose deployment. Run commands
from the repository root. Use the [troubleshooting runbook](TROUBLESHOOTING.md) when a check fails
and the [upgrade runbook](UPGRADE.md) for version changes.

## Preflight

Keep deployment settings in the gitignored `.env` file. Before starting a changed configuration:

```powershell
docker compose config --quiet
docker compose run --rm dashboard python -m tools.validate_config
```

After the database and first administrator exist, the read-only environment doctor checks paths,
SQLite integrity, configuration, users, collectors, integrations, and AI readiness without making
an AI request:

```powershell
docker compose run --rm dashboard python -m tools.doctor
```

Treat an `ERROR` or doctor `FAIL` as a deployment blocker. Review warnings against the intended
environment; for example, an all-interface bind is expected only when a firewall or reverse proxy
controls access.

## Start, observe, and stop

Start the application, inspect container state, and require HTTP 200 from the health endpoint:

```powershell
docker compose up -d dashboard agent
docker compose ps
(Invoke-WebRequest -UseBasicParsing http://localhost:5000/health).StatusCode
```

Use the HTTPS profile when testing the bundled local reverse proxy:

```powershell
docker compose -f docker-compose.yml -f docker-compose.https.yml up -d
curl.exe --fail --silent --insecure https://localhost/health
```

The `--insecure` flag is for the local development CA only. See
[HTTPS deployment](HTTPS_DEPLOYMENT.md) before exposing the service beyond the host.

Inspect bounded recent logs and the authenticated admin diagnostics page before restarting a
failing service:

```powershell
docker compose logs --tail 200 dashboard agent
```

Stop writers before maintenance:

```powershell
docker compose stop agent dashboard
```

Start the dashboard before the agent after maintenance, then check health again:

```powershell
docker compose up -d dashboard agent
(Invoke-WebRequest -UseBasicParsing http://localhost:5000/health).StatusCode
```

`docker compose down` is reserved for recreating the stack. Never add `--volumes` during routine
operation; it can remove retained proxy state and other named volumes.

## Accounts and access

Create or update a dashboard account from an interactive terminal. The command prompts for the
password when `DASHBOARD_USER_PASSWORD` is unset:

```powershell
docker compose exec dashboard python tools/manage_dashboard_user.py <username> <viewer|analyst|admin>
```

Grant the least role needed. Keep at least one administrator, and use individual analyst accounts
so the audit chain identifies the actor.

## Collectors

Configure the same protected `WINDOWS_COLLECTOR_SECRET` on the dashboard and each authorized
Windows collector. Run the collector from an elevated PowerShell session when its service account
cannot read the Security log:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\windows_event_collector.ps1 `
  -ServerUrl <dashboard-url> -Secret $env:WINDOWS_COLLECTOR_SECRET -Once
```

Remove `-Once` for continuous polling or install the command through the host's service scheduler.
Preserve the default `%ProgramData%\Mini-SIEM` state directory across restarts: it contains cursor,
buffer, collector identity, and delivery diagnostics. A new collector starts at the newest records
and does not send historical events. Protocol compatibility is defined in
[Collector Ingestion Protocol](COLLECTOR_PROTOCOL.md).

For offline evidence, normalize a supported export without contacting the dashboard:

```powershell
python tools/import_windows_events.py evidence.evtx --output data/windows_events.jsonl
```

## Retention, backup, and recovery

Run retention and rotation only while the agent and dashboard are stopped:

```powershell
docker compose stop agent dashboard
docker compose run --rm dashboard python -m tools.maintenance retention
docker compose run --rm dashboard python -m tools.maintenance rotate
docker compose up -d dashboard agent
```

Retention first creates an integrity-checked SQLite backup and archives eligible alerts. It never
deletes open incidents. The analyst audit log is excluded from rotation to preserve its hash chain.

Use [Retention, backup and restore](RETENTION_BACKUP.md) for backup-only commands, full restore,
archive import, schema migration, and the isolated restore drill. Keep `data/backups/` on storage
with access control and a separate failure domain; a backup stored only beside the live database
does not cover host or disk loss.

## Routine schedule

| Frequency | Check |
|---|---|
| Each change | Compose config, configuration validator, doctor, and health HTTP 200 |
| Daily | Container state, admin diagnostics, collector freshness, ingestion failures, and disk space |
| Weekly | Bounded service logs, rule-load failures, integration state, backups, and archive growth |
| Monthly | Restore drill, account/role review, secret age, certificate expiry, and retention policy |
| Before release | Follow [Upgrade](UPGRADE.md), [Security](SECURITY.md), and the release checklist |

Do not clear alerts, databases, logs, collector state, models, or backups as a diagnostic shortcut.
Preserve evidence first and use the documented retention or recovery path.
