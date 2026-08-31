# Mini-SIEM v0.9.0 Release Checklist

`v0.9.0` measures single-node capacity, makes overload bounded and observable, optimizes SQLite query and write performance, and hardens collector reliability with stable identity, bounded buffering, an explicit protocol version, and an end-to-end outage recovery path. Detection evidence remains authoritative, response execution remains simulation-first, and release publication remains gated by CI.

Older release notes are consolidated in [Release History](RELEASE_HISTORY.md).

## Upgrade from v0.8.0

- Back up `data/mini_siem.db`, `data/dashboard_users.json`, and `data/analyst_audit.jsonl` before upgrading.
- Copy any new settings from `.env.example`; migration versions v2–v4 add query indexes, collector identity, and collector buffer diagnostics. The v0.8.0 migration baseline (v1) is unchanged.
- Inspect and apply the versioned SQLite migration before starting the upgraded stack:

```bash
docker compose run --rm dashboard python -m tools.migrate_db --dry-run
docker compose run --rm dashboard python -m tools.migrate_db
```

- Rebuild the application image once, validate configuration, and restart the stack. The migration runner creates a verified backup before applying pending migrations.
- Keep `RESPONSE_MODE=simulation`. This release does not add a production response executor.
- A legacy collector that does not send `protocol_version` remains accepted as version `0`; a v0.9.0 collector sends `protocol_version: 1`. Future versions are rejected with HTTP 400. See [Collector Protocol](COLLECTOR_PROTOCOL.md).

## Clean-clone setup

Clone and select the release:

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
git checkout v0.9.0
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

## Performance and resilience

- `tools/generate_telemetry_load.py` produces deterministic local-only JSONL telemetry across `steady`, `burst`, `mixed-source`, `windows-heavy`, and `authentication-heavy` modes with no exploit traffic, AI, or provider calls.
- `tools/benchmark_throughput.py` measures events/sec, normalization/detection/SQLite latency, dashboard API latency, CPU, memory, queue depth, and dropped/rejected events against a temporary database.
- A bounded stdlib ingestion queue applies explicit overload policy: backpressure on a full queue, worker-failure counting, explicit rejection when stopped, and saturation surfaces in agent heartbeat, system status, and public health.
- Graceful degradation has explicit `healthy`, `degraded`, and `saturated` states: core detection and persistence always have priority; AI and external TI skip new work under load; notifications are serialized and skip the network with an `SKIPPED_OVERLOAD` audit at saturation.
- SQLite query plans are optimized with justified indexes, and durable dual-write uses bounded batched writes (batch size 10, maximum 50 ms flush). See [SQLITE_QUERY_PLAN_AUDIT.md](SQLITE_QUERY_PLAN_AUDIT.md) and [SQLITE_WRITE_BATCHING.md](SQLITE_WRITE_BATCHING.md).
- The [large-history benchmark](LARGE_HISTORY_BENCHMARK.md) isolates 10k/50k/100k alert corpora and verifies alert/search paths, analytics, coverage, incident workspace, PDF generation, and retention.

## Collector reliability

- A stable generated `collector_id` is persisted atomically beside cursor and buffer state; the server tracks version, hostname, source type, and last seen, and warns on duplicate IDs from a different host without replacing host identity.
- Each collector cross-channel buffer is bounded to 500 events, replayed oldest-first, retained on failure, and deleted only after acknowledgement; corrupt buffers are quarantined for inspection, and all metrics surface through admin diagnostics.
- The collector payload carries an explicit `protocol_version`; the server accepts `0`/`1`, echoes the negotiated version, and rejects future versions clearly. The battery of outage recovery steps — buffering, replay, dedup, cursor advance, and no silent loss — is covered by an offline deterministic regression.

## Regression command

Run all executable modules with the current source mounted into the existing image:

```bash
docker compose run --rm -v "${PWD}:/app" dashboard sh -c \
  'for test in tests/test_*.py; do module=$(printf "%s" "${test%.py}" | tr "/" "."); python -m "$module" || exit 1; done'
```

## Release verification record

| Check | Result |
|---|---|
| Semantic version | `v0.9.0` selected for Performance & Operational Resilience |
| Load & backpressure | Synthetic generator, throughput benchmark, bounded queue, and graceful degradation passed |
| Storage performance | Query-plan audit, bounded batched writes, and large-history benchmark passed |
| Collector resilience | Identity, buffer diagnostics, protocol version, and outage recovery passed |
| Database | Migration versions v1–v4 and the historical upgrade matrix passed |
| Regression | 70/70 executable test modules passed locally in the existing image |
| Release artifacts | README, changelog, standalone notes, history, Compose, and tracked-file checks passed |
| GitHub Actions | The release commit and tag remain blocked until baseline, Docker smoke, security, container scan, and release gate are green |
| Secret review | No active Gitleaks exception; `.env`, `data/`, and `logs/` remain untracked |
| Runtime | Agent, dashboard, database, and public `/health` are healthy |

## Known limitations

- This remains an educational single-node lab, not a production SIEM, EDR, firewall, or high-availability service.
- Measured single-node capacity reflects the development machine; production sizing requires deployment-specific benchmark runs.
- The bounded queue and graceful degradation preserve core detection/persistence but do not provide durable remote buffering, replay from disk on the server side, or a multi-node ingestion fabric.
- The Windows collector is polling-based and covers a blue-team lab subset; offline buffering bounds and diagnostics are collector-local and transport remains shared-secret authenticated (place it behind HTTPS across untrusted networks).
- SQLite write batching only applies to the durable JSON dual-write profile; single-write SQLite and incident paths keep smaller, ordered commits for safety.
- Historical fixtures validate supported schema and representative state, not every possible production dataset.
- Dashboard identity remains local-file based; SSO, MFA, multi-tenant isolation, and distributed session revocation are not included.
- AI uses one shared worker with bounded primary/fallback attempts and no durable queue. AI output remains advisory.
- Response actions remain allowlisted workflow simulations; no production executor is bundled.

## Tag and publish

Create the annotated tag only after the release commit's GitHub Actions `release-gate` is green:

```bash
git status --short
git tag -a v0.9.0 -m "Mini-SIEM v0.9.0"
git push origin feature/blue-team-baseline
git push origin v0.9.0
```

The pushed tag must pass the same GitHub Actions workflow before publication is complete. The GitHub Release event then attaches the verified SBOM and checksum.
