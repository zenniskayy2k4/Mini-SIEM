# Mini-SIEM v0.6.0 Release Checklist

`v0.6.0` adds manual external case integrations and role-focused viewer, analyst, and administrator workspaces to the single-node Blue Team lab. Detector evidence remains authoritative, external export remains opt-in, and response execution remains simulation-first.

Older release notes are consolidated in [Release History](RELEASE_HISTORY.md).

## Upgrade from v0.5.0

- Back up `data/mini_siem.db`, `data/dashboard_users.json`, and `data/analyst_audit.jsonl` before upgrading.
- Rebuild the application image once, then restart the stack. Existing alerts, assets, rules, models, users, and audit records remain compatible; no manual database migration is required.
- Copy the optional `CASE_EXPORT_*`, `THEHIVE_*`, and `JIRA_*` settings from `.env.example`. Case export remains disabled until explicitly enabled and configured.
- Existing dashboard sessions are invalidated by the password-reset hardening and must sign in again after upgrade.
- Administrators can create, reset, and delete local dashboard accounts from `/settings`; the active administrator cannot self-demote or self-delete.
- Keep `RESPONSE_MODE=simulation`. This release does not add a production response executor.

## Clean-clone setup

Clone and select the release:

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
git checkout v0.6.0
```

Create the local environment file on PowerShell:

```powershell
Copy-Item .env.example .env
```

Or on a POSIX shell:

```bash
cp .env.example .env
```

Build, train, and start:

```bash
docker compose build
docker compose --profile train run --rm train
docker compose up -d
docker compose exec dashboard python tools/manage_dashboard_user.py admin admin
```

The user command prompts for a password. Open <http://localhost:5000> and verify:

```bash
docker compose ps
curl http://localhost:5000/health
```

Rules, local ML, storage, dashboards, analytics, reporting, offline STIX, GeoIP handling, and the AI evaluation corpus work without paid-provider keys.

## Optional external case export

Case export is manual and disabled by default. Configure exactly one provider with a dedicated least-privilege account:

```dotenv
CASE_EXPORT_ENABLED=false
CASE_EXPORT_PROVIDER=
CASE_EXPORT_TIMEOUT_SECONDS=5
CASE_EXPORT_MAX_ATTEMPTS=2
THEHIVE_URL=
THEHIVE_API_KEY=
JIRA_URL=
JIRA_USER_EMAIL=
JIRA_API_TOKEN=
JIRA_PROJECT_KEY=
JIRA_ISSUE_TYPE=
```

The shared connector sends only an allowlisted incident summary, enforces bounded retries and timeout, stores the external ID, prevents duplicate export, and appends a secret-free audit event. It never exports automatically.

## Role-focused workspaces

| Role | Workspace |
|---|---|
| `viewer` | Read-only alerts, incident status, SOC KPIs, graphs, and detection coverage |
| `analyst` | Viewer access plus investigation queues, assignment, notes, response proposals, and TI/AI context |
| `admin` | Analyst access plus user, runtime, rule/Sigma, health, integration, audit, and maintenance status |

Authorization is enforced server-side. Mutation controls hidden by the UI are not the security boundary. Password resets revoke existing sessions, user-file changes are serialized in the single dashboard process, and failed audit writes roll back user changes.

## Regression command

Run all executable modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

## Release verification record

| Check | Result |
|---|---|
| Semantic version | `v0.6.0` selected for SOC Integrations and Role-focused Workspaces |
| Regression | 43/43 executable test modules passed |
| External cases | Disabled-by-default shared connector, TheHive, Jira, deduplication, timeout/retry, and audit paths passed |
| Workspaces | Viewer read-only, analyst investigation, and administrator control/status contracts passed |
| Security hardening | RBAC/CSRF, secret-safe output, session revocation, bounded input, serialized user changes, and audit rollback passed |
| GitHub Actions | Pre-release head `e85e640` passed baseline, Docker smoke, security, and release gate in run `32485307261` |
| Clean clone | GitHub Actions validates Compose, syntax, regression, security, and a clean Docker build from each pushed repository snapshot |
| Secret review | No active Gitleaks exception; `.env`, `data/`, and `logs/` remain untracked |
| Runtime | Existing agent/dashboard stack and public `/health` are healthy without a local image rebuild |

## Known limitations

- This remains an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- Dashboard identity is local-file based; SSO, MFA, password recovery, multi-tenant isolation, and distributed session revocation are not included.
- The user store lock and login throttling are process-local because the bundled dashboard runs as one process. Use transactional shared storage before scaling to multiple workers.
- External case export is manual and supports one selected provider at a time. Provider permissions, TLS, availability, and remote retention remain operator responsibilities.
- TLS, reverse proxy, network policy, and centralized secret management are not bundled.
- AI uses one shared worker with bounded primary/fallback attempts and no durable queue. AI output remains advisory.
- Response actions remain allowlisted workflow simulations; no production executor is bundled.
- Windows collection remains polling-based and NIDS visibility remains Linux-oriented.

## Tag and publish

Create the annotated tag only after the release commit's GitHub Actions `release-gate` is green:

```bash
git status --short
git tag -a v0.6.0 -m "Mini-SIEM v0.6.0"
git push origin feature/blue-team-baseline
git push origin v0.6.0
```

The pushed tag must pass the same GitHub Actions workflow before publication is complete.
