# Upgrade runbook

This procedure upgrades the single-node Docker Compose deployment while preserving a recoverable
database. Read the target release notes and [release checklist](RELEASE_CHECKLIST.md) before the
maintenance window. Commands assume the base Compose file; include
`-f docker-compose.yml -f docker-compose.https.yml` for an HTTPS-profile deployment.

## Prepare

1. Record the current application version, health response, container state, and active `.env`
   variable names. Never copy secret values into a ticket or terminal transcript.
2. Confirm that the target release supports the current source version in its upgrade matrix.
3. Review changes to `.env.example`, Compose files, collector protocol, release notes, and database
   migrations.
4. Confirm enough free space for the new image plus an SQLite backup.
5. Schedule a collector and analyst write pause.

Run the current version's checks before changing the checkout:

```powershell
docker compose ps
(Invoke-WebRequest -UseBasicParsing http://localhost:5000/health).StatusCode
docker compose run --rm dashboard python -m tools.doctor
```

Resolve any failed integrity or configuration check before upgrading.

## Back up the current version

Stop both writers and create a backup with the current image:

```powershell
docker compose stop agent dashboard
docker compose run --rm dashboard python -m tools.maintenance backup
```

Verify that the command reports a new file under `data/backups/`. Copy that backup, `.env`, user
store, analyst audit log, rule overrides, and collector deployment configuration to protected
storage outside the application host. Do not include credentials in an unencrypted archive.

## Build and validate the target

Update the checkout to the reviewed release, then build once and validate the resolved
configuration before starting services:

```powershell
docker compose build
docker compose config --quiet
docker compose run --rm dashboard python -m tools.validate_config
docker compose run --rm dashboard python -m tools.migrate_db --dry-run
```

The dry run must report the expected source and target versions and `integrity: ok`. It makes no
database change. A newer-than-supported database, unknown migration, changed checksum, or failed
integrity check is a hard stop.

## Apply and verify

Apply forward-only migrations through the backup-first migration tool:

```powershell
docker compose run --rm dashboard python -m tools.migrate_db
docker compose run --rm dashboard python -m tools.migrate_db --dry-run
docker compose up -d dashboard agent
docker compose ps
(Invoke-WebRequest -UseBasicParsing http://localhost:5000/health).StatusCode
```

The second dry run must show no pending migrations and the target version as the result version.
After health returns HTTP 200, sign in and verify recent alerts, incidents, assets, rule state,
collector freshness, integration state, and the admin diagnostics view. Keep the pre-upgrade backup
until the acceptance window closes.

Upgrade the Windows collector only after the server is healthy. The server accepts documented
legacy protocol versions; a collector using a future protocol must not be deployed before its
server version. See [Collector Ingestion Protocol](COLLECTOR_PROTOCOL.md).

## Abort and recover

Before a migration is applied, abort by keeping both services stopped, restoring the reviewed
checkout/configuration, rebuilding the previous image, and starting it.

After a migration is applied, do not point an older application image at the migrated database
unless that exact downgrade is documented as compatible. Instead:

1. Stop `agent` and `dashboard`.
2. Preserve the failed upgraded database, WAL, and SHM files for diagnosis.
3. Restore the pre-upgrade SQLite backup by following
   [Restore a full SQLite backup](RETENTION_BACKUP.md#restore-a-full-sqlite-backup).
4. Restore the matching previous checkout and protected configuration.
5. Rebuild, run the configuration validator, start dashboard then agent, and require health HTTP
   200.
6. Verify data and the analyst audit chain before reopening ingestion.

For total host loss, use the disaster-recovery procedure in [Security](SECURITY.md#disaster-recovery).
