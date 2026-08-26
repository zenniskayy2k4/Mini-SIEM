# Mini-SIEM v0.7.0 Release Checklist

`v0.7.0` adds deterministic detection validation, analyst feedback and tuning controls, versioned event envelopes, observable ingestion failures and metrics, and stale Windows collector detection. Detector evidence remains authoritative, replay remains offline, and tuning never deletes the underlying telemetry.

Older release notes are consolidated in [Release History](RELEASE_HISTORY.md).

## Upgrade from v0.6.0

- Back up `data/mini_siem.db`, `data/dashboard_users.json`, and `data/analyst_audit.jsonl` before upgrading.
- Rebuild the application image once and restart the dashboard and agent. SQLite creates the feedback, exception, suppression, ingestion diagnostic, metric, and heartbeat tables automatically; no manual migration command is required.
- Copy `INGESTION_FAILURE_RETENTION_DAYS` and `WINDOWS_COLLECTOR_STALE_SECONDS` from `.env.example` when their defaults of 30 days and 60 seconds are unsuitable.
- Redeploy `tools/windows_event_collector.ps1` to Windows endpoints to enable idle and endpoint-availability heartbeats. Legacy non-empty event batches remain accepted, but they cannot report an idle endpoint between events.
- Review existing suppression policies and exact-match exceptions after upgrade. Changes are audited and suppressed events remain queryable telemetry.
- Keep `RESPONSE_MODE=simulation`. This release does not add a production response executor.

## Clean-clone setup

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

## Detection validation and tuning

- `python tools/replay_scenario.py tests/scenarios` replays the versioned 18-scenario corpus without starting sensors, calling Ollama, or using external providers.
- `docs/DETECTION_VALIDATION_COVERAGE.md` and its JSON companion show deterministic scenario coverage separately from runtime hit counts.
- Analysts can record `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `NEEDS_TUNING` feedback without changing stored evidence.
- Exact-match exceptions and bounded suppression policies are server-authorized and hash-chain audited. Wildcards and unbounded suppression are rejected.
- Rule quality reports classified and unclassified sample sizes. It does not claim statistical precision or recall from the curated corpus.

## Ingestion health

Set a dedicated collector secret and calibrate the stale threshold above the endpoint poll interval:

```dotenv
WINDOWS_COLLECTOR_SECRET=
WINDOWS_COLLECTOR_STALE_SECONDS=60
INGESTION_FAILURE_RETENTION_DAYS=30
```

The collector sends authenticated empty heartbeats while idle and reports whether at least one configured Windows event channel is readable. Admin diagnostics distinguish `healthy`, `idle`, `endpoint_unavailable`, and `offline`; public `/health` exposes only the aggregate ingestion state. Parser previews are secret-redacted, metric labels remain bounded, and stored heartbeat identities are capped at 100 collectors.

## Regression command

Run all executable modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

## Release verification record

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

## Known limitations

- This remains an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- The curated scenario corpus validates known contracts; it does not measure real-world detection accuracy, precision, recall, or coverage of every attack variation.
- Feedback quality metrics depend on analyst classification and report unclassified samples explicitly; they are not autonomous rule optimization.
- Exceptions are exact-match and suppression is process-local/runtime-oriented. Distributed policy evaluation is not included.
- Windows collection remains polling-based. Heartbeats show collector and configured-channel availability, not full endpoint integrity or guaranteed event delivery.
- Dashboard identity is local-file based; SSO, MFA, password recovery, multi-tenant isolation, and distributed session revocation are not included.
- TLS, reverse proxy, network policy, and centralized secret management are not bundled.
- AI uses one shared worker with bounded primary/fallback attempts and no durable queue. AI output remains advisory.
- Response actions remain allowlisted workflow simulations; no production executor is bundled.

## Tag and publish

Create the annotated tag only after the release commit's GitHub Actions `release-gate` is green:

```bash
git status --short
git tag -a v0.7.0 -m "Mini-SIEM v0.7.0"
git push origin feature/blue-team-baseline
git push origin v0.7.0
```

The pushed tag must pass the same GitHub Actions workflow before publication is complete.
