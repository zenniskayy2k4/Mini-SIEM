# Mini-SIEM v0.8.0 Release Checklist

`v0.8.0` hardens deployment configuration, secrets, dependency and container supply-chain checks, and SQLite migration/recovery for the single-node Blue Team lab. Detection evidence remains authoritative, response execution remains simulation-first, and release publication remains gated by CI.

Older release notes are consolidated in [Release History](RELEASE_HISTORY.md).

## Upgrade from v0.7.0

- Back up `data/mini_siem.db`, `data/dashboard_users.json`, and `data/analyst_audit.jsonl` before upgrading.
- Copy the deployment and matching `*_FILE` settings from `.env.example`; set either a direct secret or its file path, never both.
- Inspect and apply the versioned SQLite migration before starting the upgraded stack:

```bash
docker compose run --rm dashboard python -m tools.migrate_db --dry-run
docker compose run --rm dashboard python -m tools.migrate_db
```

- Rebuild the application image once, validate configuration, and restart the stack. The migration runner creates a verified backup before applying pending migrations.
- Keep `RESPONSE_MODE=simulation`. This release does not add a production response executor.

## Clean-clone setup

Clone and select the release:

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
git checkout v0.8.0
```

Create the local environment file:

```powershell
Copy-Item .env.example .env
```

Validate, build, train, and start:

```bash
docker compose run --rm dashboard python -m tools.validate_config
docker compose build
docker compose --profile train run --rm train
docker compose up -d
docker compose exec dashboard python tools/manage_dashboard_user.py admin admin
```

Open <http://localhost:5000>, then verify `docker compose ps` and `curl http://localhost:5000/health`.

## Secure deployment profile

For a network-exposed lab, configure production secrets and the public URL, then use the optional HTTPS profile:

```dotenv
DEPLOYMENT_ENV=production
DASHBOARD_PUBLIC_URL=
DASHBOARD_SESSION_SECRET_FILE=
METRICS_BEARER_TOKEN_FILE=
```

```bash
docker compose -f docker-compose.yml -f docker-compose.https.yml up -d
```

The profile terminates TLS with Caddy, redirects HTTP, limits request bodies, trusts one proxy hop, enables secure cookies, and removes the direct dashboard host port. See [HTTPS deployment](HTTPS_DEPLOYMENT.md) and [file secrets](FILE_SECRETS.md) before exposing the lab beyond localhost.

## Supply-chain and recovery checks

- `requirements.txt` exactly pins direct and transitive production dependencies; CI runs `pip check` and weekly grouped Dependabot updates.
- CI generates an SPDX inventory from the smoke-tested image, verifies Python and Debian packages, scans HIGH/CRITICAL vulnerabilities, and emits a SHA-256 manifest.
- GitHub Release publication re-verifies the checksum before attaching the SBOM and checksum artifacts.
- `python -m tools.migrate_db --dry-run` inspects pending schema changes without writing; the normal command is backup-first.
- `python -m tests.test_restore_drill` verifies isolated backup, damage, restore, integrity, schema history, application state, and audit-chain preservation.
- `python -m tests.test_historical_upgrades` covers representative v0.6.0, v0.7.0, v0.8.0, and fresh databases.

## Regression command

Run all executable modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

## Release verification record

| Check | Result |
|---|---|
| Semantic version | `v0.8.0` selected for Platform and Supply-chain Hardening |
| Secure deployment | Config validator, HTTPS proxy, file secrets, and security regression contracts passed |
| Supply chain | Exact pins, SPDX/checksum workflow, deny-by-default Grype policy, and publication path validated |
| Database recovery | Versioned migration, backup-first execution, restore drill, and historical upgrade matrix passed |
| Regression | 61/61 executable test modules passed locally in the existing image |
| Release artifacts | README, changelog, standalone notes, history, Compose, and tracked-file checks passed |
| GitHub Actions | The release commit and tag remain blocked until baseline, Docker smoke, security, container scan, and release gate are green |
| Secret review | No active Gitleaks exception; `.env`, `data/`, and `logs/` remain untracked |
| Runtime | Agent, dashboard, database, and public `/health` are healthy |

## Known limitations

- This remains an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- The bundled Caddy profile uses its local CA for lab deployment; public certificates, DNS, firewall, and network policy remain operator responsibilities.
- File-backed secrets improve delivery but are not a centralized secret manager; rotation and host-file permissions remain operator responsibilities.
- The vulnerability database changes over time. HIGH/CRITICAL findings block CI and require dependency/base-image remediation or a narrowly reviewed, expiring exception.
- SQLite migration and recovery are single-node procedures. Automatic failover, point-in-time recovery, and remote backup replication are not included.
- Historical fixtures validate supported schema and representative state, not every possible production dataset.
- Dashboard identity remains local-file based; SSO, MFA, password recovery, multi-tenant isolation, and distributed session revocation are not included.
- AI uses one shared worker with bounded primary/fallback attempts and no durable queue. AI output remains advisory.
- Response actions remain allowlisted workflow simulations; no production executor is bundled.

## Tag and publish

Create the annotated tag only after the release commit's GitHub Actions `release-gate` is green:

```bash
git status --short
git tag -a v0.8.0 -m "Mini-SIEM v0.8.0"
git push origin feature/blue-team-baseline
git push origin v0.8.0
```

The pushed tag must pass the same GitHub Actions workflow before publication is complete. The GitHub Release event then attaches the verified SBOM and checksum.
