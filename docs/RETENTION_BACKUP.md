# Retention, backup and restore

Run maintenance while the agent and dashboard are stopped so log copy-truncate and the JSON mirror cannot race with new writes:

```powershell
docker compose stop agent dashboard
docker compose run --rm dashboard python -m tools.maintenance retention
docker compose run --rm dashboard python -m tools.maintenance rotate
docker compose up -d dashboard agent
```

Defaults are `ALERT_RETENTION_DAYS=90`, `LOG_ROTATE_MAX_BYTES=10485760` (10 MiB), and `LOG_ROTATE_BACKUPS=5`. Override them in `.env`, or pass `--days`, `--max-bytes`, and `--backups` to the commands.

Retention creates an integrity-checked SQLite backup under `data/backups/` and writes eligible alerts to `data/archive/*.jsonl` before deletion. Alerts newer than the cutoff and incidents in `NEW`, `INVESTIGATING`, or `CONTAINED` are never deleted. The JSON mirror is pruned only after the SQLite transaction commits.

Operational rotation covers `logs/auth.log`, Windows events, response logs, and notification logs. `data/analyst_audit.jsonl` is intentionally excluded because rotating it would break its tamper-evident hash chain.

## Backup only

```powershell
docker compose run --rm dashboard python -m tools.maintenance backup
```

## Upgrade the database schema

Stop writers, inspect the source and target versions without changing the database, then run the migration:

```powershell
docker compose stop agent dashboard
docker compose run --rm dashboard python -m tools.migrate_db --dry-run
docker compose run --rm dashboard python -m tools.migrate_db
docker compose up -d dashboard agent
```

A pending migration creates an integrity-checked backup under `data/backups/` before applying ordered changes in a SQLite transaction. The command rejects unknown versions or changed checksums and prints the source, target, result, backup, and integrity status. An already-current database is a no-op and does not create a redundant backup.

## Automated restore drill

Run the deterministic drill without touching the configured database:

```powershell
docker compose run --rm dashboard python -m tests.test_restore_drill
```

The drill works only in a temporary directory. It creates sample alert, incident, asset, external-case, analyst-note, schema-history, and audit-chain state; backs up SQLite; damages the working copy; restores it; and requires both integrity and exact state verification to pass.

## Historical upgrade matrix

CI upgrades deterministic `v0.6.0`, `v0.7.0`, and fresh SQLite fixtures to the current schema, checks backup creation and integrity, and verifies historical alert, incident, asset, external-case, tuning, and ingestion state. The matrix derives its required supported releases from `CHANGELOG.md`; publishing a new release without adding its fixture fails the baseline job and therefore blocks the release gate.

## Restore a full SQLite backup

Stop services, preserve the current database, copy the selected backup into place, then verify it before restarting:

```powershell
docker compose stop agent dashboard
Move-Item data/mini_siem.db data/mini_siem.before-restore.db
if (Test-Path data/mini_siem.db-wal) { Move-Item data/mini_siem.db-wal data/mini_siem.before-restore.db-wal }
if (Test-Path data/mini_siem.db-shm) { Move-Item data/mini_siem.db-shm data/mini_siem.before-restore.db-shm }
Copy-Item data/backups/mini_siem.backup-<timestamp>.db data/mini_siem.db -Force
docker compose run --rm dashboard python -c "import sqlite3; c=sqlite3.connect('/app/data/mini_siem.db'); print(c.execute('PRAGMA integrity_check').fetchone()[0])"
docker compose up -d dashboard agent
```

Restart only when the integrity check prints `ok`. SQLite remains the primary read path; keep the pre-restore database, WAL/SHM files, and JSON mirror until alerts and incidents have been verified in the dashboard.

## Restore archived alerts

Use the idempotent migration tool; existing alert IDs are skipped:

```powershell
docker compose stop agent dashboard
docker compose run --rm dashboard python -m tools.migrate_json_to_sqlite --json /app/data/archive/alerts-<timestamp>.jsonl
docker compose up -d dashboard agent
```
