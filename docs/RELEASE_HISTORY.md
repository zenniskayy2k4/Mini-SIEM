# Mini-SIEM Release History

Archived release notes for versions older than the current standalone release. See [v0.9.0](RELEASE_v0.9.0.md) for the latest release.

## Mini-SIEM v0.7.0 Release Checklist

`v0.7.0` adds deterministic detection validation, analyst feedback and tuning controls, versioned event envelopes, observable ingestion failures and metrics, and stale Windows collector detection. Detector evidence remains authoritative, replay remains offline, and tuning never deletes the underlying telemetry.

### Upgrade from v0.6.0

- Back up `data/mini_siem.db`, `data/dashboard_users.json`, and `data/analyst_audit.jsonl` before upgrading.
- Rebuild the application image once and restart the dashboard and agent. SQLite creates the feedback, exception, suppression, ingestion diagnostic, metric, and heartbeat tables automatically; no manual migration command is required.
- Copy `INGESTION_FAILURE_RETENTION_DAYS` and `WINDOWS_COLLECTOR_STALE_SECONDS` from `.env.example` when their defaults of 30 days and 60 seconds are unsuitable.
- Redeploy `tools/windows_event_collector.ps1` to Windows endpoints to enable idle and endpoint-availability heartbeats. Legacy non-empty event batches remain accepted, but they cannot report an idle endpoint between events.
- Review existing suppression policies and exact-match exceptions after upgrade. Changes are audited and suppressed events remain queryable telemetry.
- Keep `RESPONSE_MODE=simulation`. This release does not add a production response executor.

### Clean-clone setup

Clone and select the release:

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
git checkout v0.7.0
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

The user command prompts securely for a password. Open <http://localhost:5000> and verify:

```bash
docker compose ps
curl http://localhost:5000/health
```

Rules, local ML, storage, dashboards, replay scenarios, reporting, ingestion diagnostics, offline STIX, GeoIP handling, and the AI evaluation corpus work without paid-provider keys.

### Detection validation and tuning

- `python tools/replay_scenario.py tests/scenarios` replays the versioned 18-scenario corpus without starting sensors, calling Ollama, or using external providers.
- `docs/DETECTION_VALIDATION_COVERAGE.md` and its JSON companion show deterministic scenario coverage separately from runtime hit counts.
- Analysts can record `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `NEEDS_TUNING` feedback without changing stored evidence.
- Exact-match exceptions and bounded suppression policies are server-authorized and hash-chain audited. Wildcards and unbounded suppression are rejected.
- Rule quality reports classified and unclassified sample sizes. It does not claim statistical precision or recall from the curated corpus.

### Ingestion health

Set a dedicated collector secret and calibrate the stale threshold above the endpoint poll interval:

```dotenv
WINDOWS_COLLECTOR_SECRET=
WINDOWS_COLLECTOR_STALE_SECONDS=60
INGESTION_FAILURE_RETENTION_DAYS=30
```

The collector sends authenticated empty heartbeats while idle and reports whether at least one configured Windows event channel is readable. Admin diagnostics distinguish `healthy`, `idle`, `endpoint_unavailable`, and `offline`; public `/health` exposes only the aggregate ingestion state. Parser previews are secret-redacted, metric labels remain bounded, and stored heartbeat identities are capped at 100 collectors.

### Regression command

Run all executable modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

### Release verification record

| Check | Result |
|---|---|
| Semantic version | `v0.7.0` selected for Detection Validation and Data Quality |
| Scenario validation | 18 deterministic Linux, Windows, Sigma, NIDS, and cross-source scenarios passed offline |
| Regression | 53/53 executable test modules passed on source and the built image |
| Tuning controls | Feedback, quality metrics, exact exceptions, suppression, authorization, and audit paths passed |
| Data quality | Event envelope, redacted failure retention, bounded metrics, heartbeat, and gap-state paths passed |
| GitHub Actions | Pre-release head `ac5f0ec` passed baseline, Docker smoke, security, and release gate in run `32956979463` |
| Clean clone | Release gate validates artifacts, Compose, syntax, regression, security, and a clean Docker build from each pushed snapshot |
| Secret review | No active Gitleaks exception; `.env`, `data/`, and `logs/` remain untracked |
| Runtime | Agent, dashboard, database, and public `/health` are healthy after the release image rollout |

### Known limitations

- This remains an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- The curated scenario corpus validates known contracts; it does not measure real-world detection accuracy, precision, recall, or coverage of every attack variation.
- Feedback quality metrics depend on analyst classification and report unclassified samples explicitly; they are not autonomous rule optimization.
- Exceptions are exact-match and suppression is process-local/runtime-oriented. Distributed policy evaluation is not included.
- Windows collection remains polling-based. Heartbeats show collector and configured-channel availability, not full endpoint integrity or guaranteed event delivery.
- Dashboard identity is local-file based; SSO, MFA, password recovery, multi-tenant isolation, and distributed session revocation are not included.
- TLS, reverse proxy, network policy, and centralized secret management are not bundled.
- AI uses one shared worker with bounded primary/fallback attempts and no durable queue. AI output remains advisory.
- Response actions remain allowlisted workflow simulations; no production executor is bundled.

### Tag and publish

Create the annotated tag only after the release commit's GitHub Actions `release-gate` is green:

```bash
git status --short
git tag -a v0.7.0 -m "Mini-SIEM v0.7.0"
git push origin feature/blue-team-baseline
git push origin v0.7.0
```

The pushed tag must pass the same GitHub Actions workflow before publication is complete.

## Mini-SIEM v0.6.0 Release Checklist

`v0.6.0` adds manual external case integrations and role-focused viewer, analyst, and administrator workspaces to the single-node Blue Team lab. Detector evidence remains authoritative, external export remains opt-in, and response execution remains simulation-first.

### Upgrade from v0.5.0

- Back up `data/mini_siem.db`, `data/dashboard_users.json`, and `data/analyst_audit.jsonl` before upgrading.
- Rebuild the application image once, then restart the stack. Existing alerts, assets, rules, models, users, and audit records remain compatible; no manual database migration is required.
- Copy the optional `CASE_EXPORT_*`, `THEHIVE_*`, and `JIRA_*` settings from `.env.example`. Case export remains disabled until explicitly enabled and configured.
- Existing dashboard sessions are invalidated by the password-reset hardening and must sign in again after upgrade.
- Administrators can create, reset, and delete local dashboard accounts from `/settings`; the active administrator cannot self-demote or self-delete.
- Keep `RESPONSE_MODE=simulation`. This release does not add a production response executor.

### Clean-clone setup

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

### Optional external case export

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

### Role-focused workspaces

| Role | Workspace |
|---|---|
| `viewer` | Read-only alerts, incident status, SOC KPIs, graphs, and detection coverage |
| `analyst` | Viewer access plus investigation queues, assignment, notes, response proposals, and TI/AI context |
| `admin` | Analyst access plus user, runtime, rule/Sigma, health, integration, audit, and maintenance status |

Authorization is enforced server-side. Mutation controls hidden by the UI are not the security boundary. Password resets revoke existing sessions, user-file changes are serialized in the single dashboard process, and failed audit writes roll back user changes.

### Regression command

Run all executable modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

### Release verification record

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

### Known limitations

- This remains an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- Dashboard identity is local-file based; SSO, MFA, password recovery, multi-tenant isolation, and distributed session revocation are not included.
- The user store lock and login throttling are process-local because the bundled dashboard runs as one process. Use transactional shared storage before scaling to multiple workers.
- External case export is manual and supports one selected provider at a time. Provider permissions, TLS, availability, and remote retention remain operator responsibilities.
- TLS, reverse proxy, network policy, and centralized secret management are not bundled.
- AI uses one shared worker with bounded primary/fallback attempts and no durable queue. AI output remains advisory.
- Response actions remain allowlisted workflow simulations; no production executor is bundled.
- Windows collection remains polling-based and NIDS visibility remains Linux-oriented.

### Tag and publish

The release commit is tagged with annotated tag `v0.6.0`:

```bash
git push origin feature/blue-team-baseline
git push origin v0.6.0
```

## Mini-SIEM v0.5.0 Release Checklist

`v0.5.0` adds asset-aware risk, SOC analytics/reporting, operational metrics, and resilient AI providers to the single-node Blue Team lab. Detector evidence and severity remain authoritative; assets, threat intelligence, and AI add explainable context without automatically changing incident outcomes.

### Upgrade from v0.4.0

- Back up `data/mini_siem.db` before upgrading. The release adds tables/indexes and optional JSON fields without requiring a manual migration command.
- Rebuild the application image once, then restart the stack. Mounted alerts, users, audit data, rules, logs, and trained models remain compatible.
- Copy new optional settings from `.env.example`: `RISK_WEIGHT_*`, `METRICS_BEARER_TOKEN`, `AI_FALLBACK_PROVIDER`, `OLLAMA_LOCAL_BASE_URL`, and `OLLAMA_LOCAL_MODEL`.
- Empty `AI_FALLBACK_PROVIDER` preserves the existing single-provider path. Mini-SIEM never installs Ollama, starts it, or downloads a local model.
- Asset inventory is initially empty. Administrators can add assets through `/assets`; existing alerts remain valid without an `asset_id`.
- Review metrics exposure before binding the dashboard beyond a local lab. Set `METRICS_BEARER_TOKEN` and enforce network/TLS controls externally.

### Clean-clone setup

Clone and select the release:

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
git checkout v0.5.0
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

Rules, local ML, storage, dashboard, asset/risk context, analytics, reporting, offline STIX, GeoIP handling, and the AI evaluation corpus work without paid-provider keys. Keep `RESPONSE_MODE=simulation` for the lab.

### Optional resilient AI setup

Ollama Cloud remains the default:

```dotenv
AI_PROVIDER=ollama_cloud
AI_FALLBACK_PROVIDER=
OLLAMA_API_KEY=
OLLAMA_BASE_URL=https://ollama.com/api
OLLAMA_MODEL=gemma4:cloud
```

To use a manually installed local model as a bounded fallback:

```dotenv
AI_PROVIDER=ollama_cloud
AI_FALLBACK_PROVIDER=ollama_local
OLLAMA_LOCAL_BASE_URL=http://host.docker.internal:11434/api
OLLAMA_LOCAL_MODEL=gemma3:4b
```

The primary and fallback are each attempted at most once inside the same one-worker task. No second queue or automatic model pull is created. The actual provider/model is persisted and fallback outcomes are exposed through authenticated system diagnostics.

### Regression command

Run all executable modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

The eight-case AI corpus is offline and does not call Ollama:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard python -m tests.test_ai_evaluation_corpus
```

### Release verification record

| Check | Result |
|---|---|
| Semantic version | `v0.5.0` selected for Asset-aware SOC Analytics and Resilient AI |
| Regression | 37/37 executable test modules passed |
| Asset and risk | Inventory CRUD/linking and deterministic explainable scoring passed |
| Observability | Prometheus metrics, KPI API, responsive analytics, and PDF reports passed |
| AI resilience | Provider abstraction, optional local adapter, bounded fallback, diagnostics, and offline evaluation corpus passed |
| GitHub Actions | Release commit and pushed tag passed baseline, Docker smoke, security, and release gate before publication |
| Clean clone | GitHub Actions validated Compose, syntax, regression, security, and a clean Docker build from the repository snapshot |
| Secret review | No active Gitleaks exception; `.env`, `data/`, and `logs/` remain untracked |
| Runtime | Existing agent/dashboard stack and public `/health` are healthy without a local rebuild |

### Known limitations

- This remains an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- Asset inventory is local and manually managed; there is no CMDB discovery, synchronization, or multi-tenant isolation.
- Risk scoring uses configured deterministic weights. It is prioritization context, not proof of compromise.
- Analytics use local SQLite and bounded date ranges; there is no distributed warehouse or long-term metrics backend.
- Prometheus authentication is optional bearer-token protection. TLS, reverse proxy, and network policy are not bundled.
- PDF reports use dependency-free base fonts and may transliterate non-ASCII text.
- Local Ollama must be installed and sized separately. Its model health is cached at startup, so restart the agent after installing or changing a model.
- AI still uses one worker with no durable queue. The offline corpus protects application semantics but does not certify every live-model response.
- Fallback is deliberately limited to one primary and one secondary provider, each attempted once.
- External case management, role-specific workspaces, SSO, MFA, and password recovery are not included.
- Response actions remain allowlisted workflow simulations; no production executor is bundled.
- Windows collection remains polling-based and NIDS visibility remains Linux-oriented.

### Tag and publish

The annotated tag was created after the release commit's GitHub Actions `release-gate` passed:

```bash
git status --short
git tag -a v0.5.0 -m "Mini-SIEM v0.5.0"
git push origin feature/blue-team-baseline
git push origin v0.5.0
```

Published tag `v0.5.0` points to verified commit `c220596`.

---

## Mini-SIEM v0.4.0 Release Checklist

`v0.4.0` adds CI-backed detection engineering and normalized threat intelligence to the single-node Blue Team lab. Native detections remain authoritative; Sigma and external intelligence add provenance and context without silently rewriting severity.

### Upgrade from v0.3.0

- No alert-database migration is required; SQLite and JSON compatibility remain unchanged.
- Rebuild the image so the Sigma and threat-intelligence modules are included, then restart the stack.
- Copy new optional settings from `.env.example`. Empty AbuseIPDB, VirusTotal, and TAXII credentials keep those providers disabled.
- Existing native rules, dashboard users, alerts, models, and audit data under mounted directories remain compatible.
- Review the supported Sigma subset in [Sigma rule support](SIGMA_RULES.md) before adding third-party rules.

### Clean-clone setup

Clone and select the release:

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
git checkout v0.4.0
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

Rules, local ML, storage, dashboard, offline STIX, and GeoIP handling work without paid-provider keys. Keep `RESPONSE_MODE=simulation` for the lab.

### Optional threat-intelligence setup

Configure only providers you intend to use:

```dotenv
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
STIX_BUNDLE_FILE=
TAXII_COLLECTION_URL=
TAXII_BEARER_TOKEN=
TAXII_FEED_SOURCE=taxii
TAXII_PULL_INTERVAL_SECONDS=3600
```

Place offline bundles under a mounted path such as `data/`, then import manually when needed:

```bash
docker compose exec agent python tools/import_stix.py /app/data/feed.json --source lab-feed
```

Only exact STIX equality indicators for IPv4, domain, SHA-256, and MD5 are active in this release. VirusTotal performs hash metadata lookups only and never uploads files.

### Regression command

Run all executable modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

### Release verification record

| Check | Result |
|---|---|
| Semantic version | `v0.4.0` selected for Detection Engineering and Threat Intelligence |
| Regression | 25/25 executable test modules passed, including the responsive dashboard contract |
| Sigma | Parser, mapping, lifecycle, provenance, coverage, and offline corpus passed |
| Threat intelligence | Provider, GeoIP, AbuseIPDB, VirusTotal, dashboard, STIX/TAXII, expiry, and failure paths passed |
| GitHub Actions | Responsive stabilization run `32123583216` passed baseline, Docker smoke, security, and release gate |
| Clean clone | Required release files, Compose configuration, syntax, and the original 24/24 release-snapshot regression modules passed |
| Secret review | No active Gitleaks exception; `.env`, `data/`, and `logs/` remain untracked |
| Runtime | Existing agent/dashboard stack and public `/health` are healthy |

The clean-clone verification reuses the existing local image to avoid a duplicate multi-gigabyte build. GitHub Actions independently performs the clean Docker build and smoke test.

### Known limitations

- This remains an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- The supported Sigma grammar is deliberately limited; unsupported modifiers, aggregations, wildcards, and complex conditions are disabled with a reason.
- GeoIP is context, not a maliciousness decision. AbuseIPDB and VirusTotal depend on external quotas and credentials.
- STIX phase 1 accepts exact IPv4/domain/hash equality patterns only. TAXII expects a collection objects URL and supports bearer-token authentication, not every discovery/authentication profile.
- Threat-intelligence caches and stores are local. Concurrent multi-process writers and distributed feed coordination are out of scope.
- VirusTotal never uploads, rescans, or downloads files; domain/IP VirusTotal lookups are not enabled.
- Ollama Cloud uses one shared worker with no durable AI queue or local fallback. AI output remains advisory.
- Response actions remain allowlisted workflow simulations; no production executor is bundled.
- Dashboard identity is local-file based with no SSO, MFA, password recovery, or user-administration UI.
- TLS/reverse-proxy configuration is not bundled. Protect collector and dashboard traffic before crossing untrusted networks.
- Windows collection remains polling-based and NIDS visibility remains Linux-oriented.

### Tag and publish

The annotated tag was created after the release commit's GitHub Actions `release-gate` passed:

```bash
git status --short
git tag -a v0.4.0 -m "Mini-SIEM v0.4.0"
git push origin feature/blue-team-baseline
git push origin v0.4.0
```

Published tag `v0.4.0` points to verified commit `1c41462`.

---

## Mini-SIEM v0.3.0 Release Checklist

`v0.3.0` is the first versioned Blue Team portfolio release. The minor version reflects substantial new detection, incident, storage, response, Windows, and reliability capabilities while the project remains pre-1.0 and lab-focused.

### Clean-clone setup

Clone and select the release:

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
git checkout v0.3.0
```

Create the local environment file on PowerShell:

```powershell
Copy-Item .env.example .env
```

Or on a POSIX shell:

```bash
cp .env.example .env
```

Add `OLLAMA_API_KEY` to `.env` if AI triage is required. Rules, local ML, storage, and the dashboard continue to work without it. Keep `RESPONSE_MODE=simulation` for the lab.

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

Expected public health state is `healthy` for the dashboard, agent, alert store, and database.

### Regression command

The tests are executable modules rather than `unittest.TestCase` classes. Run all modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

### Release verification record

| Check | Result |
|---|---|
| Semantic version | `v0.3.0` selected; no earlier repository tag existed |
| Regression | 14/14 executable test modules passed |
| Live demo | SSH threshold, one Ollama analysis, analyst lifecycle, response simulation, and audit passed |
| Storage | Final demo alert matched between SQLite and JSON |
| Audit | Hash chain returned `(True, 'Audit chain is valid')` |
| Clean clone | Required files present and `docker compose --profile train config --quiet` passed |
| Secret review | Latest 30 commits: no known token/private-key pattern; `.env`, `data/`, and `logs/` are untracked |
| Runtime | Agent/dashboard and `/health` healthy |

The clean-clone check intentionally validated configuration without rebuilding a second image on the release machine. The commands above document the full first-time build path.

### Known limitations

- This is an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- Response modes record allowlisted workflow actions; `simulation` makes no host change, and no production executor is bundled.
- Ollama Cloud uses one shared worker. Alerts arriving while it is busy are marked `busy`; there is no durable AI queue or local Ollama fallback.
- AI wording and confidence are nondeterministic. Analysts must validate evidence, and system severity remains authoritative.
- Coordination locks, login throttling, AI state, and some runtime settings are process-local and are not designed for multi-worker scaling.
- SQLite and JSON are local storage paths without clustering, multi-tenancy, or remote disaster recovery.
- Dashboard accounts use a local file store; SSO, MFA, password recovery, and a full user-administration UI are not included.
- TLS/reverse-proxy configuration is not bundled. Windows collector traffic must be placed behind HTTPS on untrusted networks.
- Windows collection is polling-based and covers a selected Sysmon/Security/Defender subset, not every channel or event ID.
- NIDS packet visibility is Linux-oriented. Docker Desktop normally cannot observe all physical Windows host traffic.
- Detection and local ML models are lab baselines and may produce false positives or miss attacks outside their training/rule coverage.
- Webhooks are best-effort generic/Discord notifications, not a durable case-management integration.

### Release operation

The release commit is tagged locally with annotated tag `v0.3.0`. Publishing the branch and tag remains an explicit repository-owner action:

```bash
git push origin feature/blue-team-baseline
git push origin v0.3.0
```
