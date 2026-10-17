# Mini-SIEM v1.0.0-rc.1 Release Checklist

`v1.0.0-rc.1` is the stable-release candidate for the single-node Blue Team SIEM. The candidate freezes the product contract: versioned REST API v1 with a machine-readable OpenAPI description, a versioned and normalized alert schema, tested upgrade paths from every supported release, a completed security review, operator diagnostics, an accessibility pass, and production-style runbooks. No new schema migrations ship in this candidate. Detection evidence remains authoritative, response execution remains simulation-first, and release publication remains gated by CI.

The feature freeze recorded in the [roadmap](MINI_SIEM_ROADMAP_v0.7_to_v1.0.md) remains active until v1.0.0: only bug fixes, security fixes, documentation, performance regression fixes, and release blockers enter the candidate.

## Upgrade from v0.9.0

- Back up `data/mini_siem.db`, `data/dashboard_users.json`, and `data/analyst_audit.jsonl` before upgrading.
- No `.env` changes and no new schema migrations ship in this candidate; the v0.9.0 migration baseline (versions v1–v4) is unchanged.
- Inspect the migration state read-only before starting the upgraded stack:

```bash
docker compose run --rm dashboard python -m tools.migrate_db --dry-run
```

- Rebuild the application image once, validate configuration, and restart the stack. See the [upgrade runbook](UPGRADE.md) for the full procedure, abort, and recovery paths.
- Keep `RESPONSE_MODE=simulation`. This release does not add a production response executor.
- Unversioned `/api/...` routes remain temporary compatibility aliases for `/api/v1/...` and advertise deprecation headers. See [REST API v1](REST_API_V1.md) and [Alert Schema v1](ALERT_SCHEMA.md).

## Clean-clone setup

Clone and select the release candidate:

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
git checkout v1.0.0-rc.1
```

Create the local environment file:

```powershell
Copy-Item .env.example .env
```

Validate, build, migrate, and start:

```bash
docker compose run --rm dashboard python -m tools.validate_config
docker compose build
docker compose --profile train run --rm train
docker compose stop agent dashboard
docker compose run --rm dashboard python -m tools.migrate_db --dry-run
docker compose run --rm dashboard python -m tools.migrate_db
docker compose up -d
docker compose exec dashboard python tools/manage_dashboard_user.py admin admin
```

A fresh database is created at the baseline schema (v1). The versioned migration above brings it to the current target (v4), which adds the query indexes and the collector identity and buffer diagnostics tables that collector ingestion relies on. The migration runner is backup-first and reports `integrity: ok`.

Open <http://localhost:5000>, then verify `docker compose ps` and `curl http://localhost:5000/health`.

## Release-candidate qualification

- REST API v1: explicit endpoint inventory, OpenAPI 3.1 contract validated in CI, permission/pagination/error-model compatibility suite, deprecation headers on legacy aliases. See [REST API v1](REST_API_V1.md).
- Alert schema v1: persisted `alert_schema_version`, legacy normalization adapter, documented field, nullability, enum, and compatibility policy. See [Alert Schema v1](ALERT_SCHEMA.md).
- Environment doctor (`python -m tools.doctor`), unified operator diagnostics view, and the four operator runbooks (`OPERATIONS`, `UPGRADE`, `TROUBLESHOOTING`, `SECURITY`).
- Qualification gates: full executable regression set, detection replay corpus (18 scenarios, 14 rules), Sigma and AI evaluation corpora, security regression pack, API compatibility suite, DB migration tests, backup/restore drill, collector outage recovery, load smoke, and a clean-clone Docker smoke.
- Upgrade qualification: v0.6.0, v0.7.0, v0.8.0, and v0.9.0 → current, plus fresh installs, with alerts, incidents, assets, rule state, Sigma overrides, feedback, audit state, external case IDs, retention config, and users preserved.
- Security review: [SECURITY_REVIEW_v1.0.md](SECURITY_REVIEW_v1.0.md) — 15 areas reviewed with no critical or high-severity findings.

## Stabilization period

After the candidate tag is pushed and CI is green, the candidate enters a stabilization window. During the window only release blockers may land on the release branch. `v1.0.0` is tagged after the window closes without an open blocker.

## Known limitations

- The [v0.9.0 known-limitations list](RELEASE_HISTORY.md#mini-siem-v090-release-checklist) remains accurate for this candidate: educational single-node lab, local file-based identity, simulation-only response actions, and advisory AI behind one shared worker.
- The security review recommends shipping the analyst audit log to append-only external storage; it remains a documented follow-up, not a candidate blocker.
- The Windows collector still reports collector version `0.9.0` in telemetry metadata; ingest compatibility remains governed by `protocol_version: 1`.

## Tag and publish

Create the annotated tag only after the release commit's GitHub Actions run is green:

```bash
git status --short
git tag -a v1.0.0-rc.1 -m "Mini-SIEM v1.0.0-rc.1"
git push origin feature/blue-team-baseline
git push origin v1.0.0-rc.1
```

The pushed tag must pass the same GitHub Actions workflow before publication is complete. The GitHub Release event then attaches the verified SBOM and checksum.
