# Mini-SIEM v0.5.0 Release Checklist

`v0.5.0` adds asset-aware risk, SOC analytics/reporting, operational metrics, and resilient AI providers to the single-node Blue Team lab. Detector evidence and severity remain authoritative; assets, threat intelligence, and AI add explainable context without automatically changing incident outcomes.

Older release notes are consolidated in [Release History](RELEASE_HISTORY.md).

## Upgrade from v0.4.0

- Back up `data/mini_siem.db` before upgrading. The release adds tables/indexes and optional JSON fields without requiring a manual migration command.
- Rebuild the application image once, then restart the stack. Mounted alerts, users, audit data, rules, logs, and trained models remain compatible.
- Copy new optional settings from `.env.example`: `RISK_WEIGHT_*`, `METRICS_BEARER_TOKEN`, `AI_FALLBACK_PROVIDER`, `OLLAMA_LOCAL_BASE_URL`, and `OLLAMA_LOCAL_MODEL`.
- Empty `AI_FALLBACK_PROVIDER` preserves the existing single-provider path. Mini-SIEM never installs Ollama, starts it, or downloads a local model.
- Asset inventory is initially empty. Administrators can add assets through `/assets`; existing alerts remain valid without an `asset_id`.
- Review metrics exposure before binding the dashboard beyond a local lab. Set `METRICS_BEARER_TOKEN` and enforce network/TLS controls externally.

## Clean-clone setup

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

## Optional resilient AI setup

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

## Regression command

Run all executable modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

The eight-case AI corpus is offline and does not call Ollama:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard python -m tests.test_ai_evaluation_corpus
```

## Release verification record

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

## Known limitations

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

## Tag and publish

The annotated tag is created only after the release commit's GitHub Actions `release-gate` is green:

```bash
git status --short
git tag -a v0.5.0 -m "Mini-SIEM v0.5.0"
git push origin feature/blue-team-baseline
git push origin v0.5.0
```

The pushed tag must pass the same GitHub Actions workflow before publication is considered complete.
