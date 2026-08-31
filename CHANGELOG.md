# Changelog

All notable changes to Mini-SIEM are documented here. The project follows semantic versioning while remaining pre-1.0.

## [Unreleased]

## [0.9.0] - 2026-08-31

Performance and Operational Resilience release.

### Added

- A deterministic synthetic telemetry load generator with `steady`, `burst`, `mixed-source`, `windows-heavy`, and `authentication-heavy` modes that produces local-only versioned envelopes with no exploit traffic, AI, or provider calls.
- A single-node throughput benchmark measuring events/sec, normalization/detection/SQLite latency, dashboard API latency, CPU, memory, queue depth, and dropped/rejected events at 10/50/100/250 events/s and burst profiles.
- A bounded stdlib ingestion queue with explicit overload policy: backpressure on a full queue, worker-failure counting, explicit rejection when stopped, and saturation surfaced in agent heartbeat, system status, and public health.
- Graceful degradation across `healthy`, `degraded`, and `saturated` states that keeps core detection and persistence active while AI/external TI skip new work and notifications become serialized or audit `SKIPPED_OVERLOAD` without network calls.
- Justified SQLite query indexes with an `EXPLAIN QUERY PLAN` audit and bounded batched writes (batch size 10, maximum 50 ms flush) for the durable JSON dual-write profile.
- Stable collector identity with atomic ID persistence, server-side version/hostname/source/last-seen tracking, and duplicate-ID warning on host change.
- Bounded per-channel collector buffer diagnostics (500-event cap, oldest-first replay, delete-only-after-acknowledgement, corrupt-buffer quarantine) and a versioned collector ingest protocol that keeps legacy payloads accepted.
- An offline deterministic outage recovery regression covering buffering, replay, deduplication, cursor advance, and no silent loss.

### Changed

- SQLite telemetry/incident transaction time reduced by 88.9%/87.8% and end-to-end dual-write time by 44.4%/36.7% at the measured batch/flush settings.
- Collector payloads now send `protocol_version: 1`; missing fields negotiate to legacy `0` and future versions are rejected with HTTP 400.
- The 100k alert API/search paths remain below 50 ms while the analytics ceiling is recorded in the large-history benchmark.

### Security

- Overload-degradation evidence is explicit and audited: AI/TI skip new work under load, notifications write `SKIPPED_OVERLOAD` without network calls, and core detection/persistence always have priority.
- Collector buffer metrics and heartbeat diagnostics are bounded and surfaced only through authenticated admin diagnostics; protocol and buffer fields are strictly validated at the collector API trust boundary.

### Verification

- All 70 executable regression modules pass locally in the existing image without Ollama, paid-provider, or network-dependent test calls.
- Python, PowerShell, Compose, runtime health, and migration regressions pass; the deterministic outage recovery, throughput, large-history, and query-plan modules are covered.
- GitHub Actions must pass baseline, Docker smoke, security, container scan, and release gate on this release commit before `v0.9.0` is tagged.

See the [v0.9.0 release checklist](docs/RELEASE_v0.9.0.md) for setup, upgrade notes, verification details, and known limitations.

## [0.8.0] - 2026-08-29

Platform and Supply-chain Hardening release.

### Added

- Deployment configuration validation, an optional Caddy HTTPS reverse-proxy profile, secure-cookie/trusted-proxy handling, request limits, and generic file-backed application secrets.
- A focused security regression pack covering authentication, authorization, CSRF, session revocation, throttling, XSS escaping, oversized requests, collector authentication, and HTTPS cookies.
- CI-generated SPDX container SBOMs, SHA-256 manifests, and HIGH/CRITICAL Grype gating with reviewable, expiring exception policy.
- Versioned SQLite schema history, a backup-first migration runner with dry-run inspection, an isolated restore drill, and historical v0.6.0/v0.7.0/v0.8.0 upgrade fixtures.

### Changed

- Production dependencies and transitive packages are exactly pinned and checked consistently by Docker and CI.
- Release publication verifies the SBOM checksum before attaching both artifacts to the GitHub Release.

### Security

- Production validation fails closed on missing or weak secrets, unsafe TLS/cookie combinations, conflicting secret sources, invalid response modes, and unsafe public bindings.
- Secret files reject missing, empty, multi-line, non-UTF-8, and oversized values without logging their contents or paths.
- Container vulnerability exceptions are deny-by-default, narrowly scoped, owned, justified, linked, and limited to 30 days.

### Verification

- All 61 executable regression modules pass locally in the existing image without Ollama, paid-provider, or network-dependent test calls.
- Base and HTTPS Compose profiles, configuration validation, schema upgrades, backup/restore integrity, and release-artifact consistency pass locally.
- GitHub Actions must pass baseline, Docker smoke, security, container scan, and release gate on this release commit before `v0.8.0` is tagged.

See the [v0.8.0 release history](docs/RELEASE_HISTORY.md#mini-siem-v080-release-checklist) for setup, upgrade notes, verification details, and known limitations.

## [0.7.0] - 2026-08-26

Detection Validation and Data Quality release.

### Added

- Time-filtered per-rule quality metrics from the latest analyst feedback per alert, including explicit classified/unclassified sample sizes and deterministic validation scenario context without precision/recall claims.
- Analyst detection feedback with SQLite-backed rule/alert linkage, session-derived actor identity, false-positive reason enforcement, read-only viewer visibility, and hash-chained audit records without altering alert evidence.
- Versioned offline detection scenarios with an 18-case Linux, Windows, Sigma, NIDS, and cross-source corpus, deterministic replay through existing detection paths, isolated temporary state, normalized CI output, generated Markdown/JSON rule-validation coverage separate from runtime hit counts, and a required provider-disabled CI gate with failure artifacts.
- Audited, exact-match detection exceptions; deterministic time-window suppression policies; and an analyst tuning workspace that preserves suppressed telemetry without notifying.
- A versioned normalized event envelope with stable event and collector identities plus backward-compatible unwrap validation.
- Retained, secret-redacted parser/schema/unsupported ingestion diagnostics and bounded Prometheus ingestion-health metrics.
- Authenticated Windows collector heartbeats with a configurable stale threshold and offline, idle, endpoint-unavailable, and healthy diagnostic states.

### Security

- Detection feedback, exceptions, suppression changes, and collector health remain server-authorized; untrusted diagnostics are redacted before storage and escaped before rendering.
- Ingestion metrics use bounded labels, heartbeat identities are admin-only, and persisted collector state is capped to prevent unbounded cardinality.

### Verification

- All 53 executable regression modules pass on source and the built image, including the deterministic 18-scenario replay corpus.
- GitHub Actions pre-release head `ac5f0ec` passed baseline, Docker smoke, security, and release gate in run `32956979463`.
- Python, JavaScript, PowerShell, Compose, runtime health, tracked-file, and secret checks pass without an Ollama/network-dependent test.

See the [v0.7.0 release history](docs/RELEASE_HISTORY.md#mini-siem-v070-release-checklist) for setup, upgrade notes, verification details, and known limitations.

## [0.6.0] - 2026-08-23

SOC Integrations and Role-focused Workspaces release.

### Added

- Disabled-by-default external case connector contract with manual analyst export, allowlisted payloads, bounded timeout/retries, persisted external IDs, idempotency, and immutable audit events.
- Optional TheHive 5 API v1 export with deterministic severity/risk mapping, IP observables, remote/local duplicate suppression, stored case IDs, and a manual dashboard action.
- Optional Jira Cloud REST v3 export with provider selection, ADF descriptions, deterministic labels, remote/local duplicate suppression, stored issue keys, and immutable audit events.
- Read-only viewer workspace with 24-hour SOC KPIs, alert and incident visibility, detection coverage, role-aware navigation, and server-enforced mutation denial.
- Analyst workspace with human-review, assigned, unassigned, and open-incident queues plus the existing investigation, notes, response proposal, and TI/AI context workflows.
- Admin workspace with audited user management, runtime and rule controls, health, secret-safe integration readiness, audit-chain verification, and retention/backup status.

### Security

- Dashboard user changes are serialized and audit-safe, password resets revoke existing sessions, and bounded request/password sizes reduce resource-exhaustion risk.

## [0.5.0] - 2026-08-20

Asset-aware SOC Analytics and Resilient AI release.

### Added

- SQLite-backed asset inventory data model with stable IDs, normalized hostname/IP lookup, duplicate constraints, CRUD operations, and immutable audit events.
- Responsive admin asset management UI and CSRF-protected API with search, environment/state/criticality filters, ownership, tags, and bounded validation.
- Fail-open alert enrichment with a compact `asset_id` reference and admin dashboard links to matching inventory records.
- Deterministic asset-aware risk scoring with configurable contribution ceilings, persisted factors, async TI/AI recomputation, and dashboard explanations.
- Prometheus text exposition for alerts, incidents, detections, AI/TI/notification outcomes, response simulations, heartbeat age, and worker backlog, with optional bearer authentication.
- Indexed, time-bounded SOC KPI API for MTTD/MTTA/MTTR, incident counts, false positives, rule volume, human review, and AI enrichment success with explicit sample availability.
- Responsive SOC analytics dashboard with range presets, KPI availability states, alert and false-positive trends, incident distribution, and top rule/MITRE charts.
- Deterministic incident PDF downloads with allowlisted sections, UTC timestamps, explicit AI/TI provenance, and secret/raw-payload exclusion.
- Provider-neutral AI analyst interface with a validated Ollama Cloud adapter while preserving the existing result, cache, rate-limit, and single-worker contracts.
- Optional configurable local Ollama adapter with one startup model-health check, no automatic model download, and unchanged AI result/worker behavior.
- Optional two-provider AI fallback with one attempt per provider, actual-provider persistence, and fallback diagnostics on the existing single worker.
- Offline eight-case AI triage evaluation corpus for output shape, evidence grounding, MITRE consistency, secret leakage, unsupported claims, and severity semantics.

### Security

- AI prompt fields now share secret-like text redaction and explicitly treat alert-provided instructions as untrusted evidence.

### Verification

- All 37 executable regression modules pass with Python syntax and Docker Compose validation.
- GitHub Actions passed baseline, Docker smoke, security, and release gate for the release commit and pushed tag.
- The live agent/dashboard stack remained healthy without a local image rebuild, Ollama model download, or AI corpus network call.
- No active Gitleaks exception or tracked `.env`, `data/**`, or `logs/**` runtime file exists.

See the [v0.5.0 release history](docs/RELEASE_HISTORY.md#mini-siem-v050-release-checklist) for setup, verification details, upgrade notes, and known limitations.

## [0.4.0] - 2026-08-18

Detection Engineering and Threat Intelligence release.

### Added

- GitHub Actions baseline, Docker smoke, security, dependency-audit, and release-gate jobs.
- A documented Sigma subset with UUID provenance, selection mapping, lifecycle controls, coverage, and an offline regression corpus.
- A normalized threat-intelligence provider contract with bounded workers, timeout/retry handling, rate limits, and cache metadata.
- GeoIP context for public addresses plus optional AbuseIPDB IP reputation and VirusTotal hash metadata providers.
- A dashboard Threat Intelligence panel that separates observed IOCs from third-party context without changing system severity.
- Offline STIX 2.1 IPv4/domain/hash import, normalized persistence, expiry/deduplication, alert matching, and optional bounded TAXII collection pulls.

### Changed

- Detection rules now preserve native/Sigma provenance and reload administrator lifecycle changes.
- Threat-intelligence failures remain non-blocking and provider payloads are reduced to allowlisted fields before persistence or display.
- The login page no longer issues an authenticated favicon request that could race its CSRF session.
- The dashboard now adapts its navigation, cards, filters, dense tables, graph, settings, and login layout across desktop, tablet, and mobile widths.

### Security

- VirusTotal is metadata-only: there is no upload, rescan, download, or raw-file path.
- API keys and TAXII bearer tokens are environment-only and excluded from normalized alert data.
- CI rejects tracked `.env`, `data/**`, and `logs/**`, scans repository history for secrets, and audits Python dependencies.

### Verification

- All 25 executable regression modules pass with Python/JavaScript syntax and Docker Compose validation.
- GitHub Actions run `32123583216` passed baseline, Docker smoke, security, and release gate before tag `v0.4.0` was published.
- The release path is verified from a clean local clone without rebuilding a duplicate image.
- No active Gitleaks exception or tracked runtime file exists.

See the [v0.4.0 release history](docs/RELEASE_HISTORY.md#mini-siem-v040-release-checklist) for setup, verification details, upgrade notes, and known limitations.

## [0.3.0] - 2026-08-15

First versioned Blue Team portfolio release.

### Added

- Ollama Cloud analyst with a validated JSON contract, bounded cache/rate limit, and one shared worker.
- Threshold and multi-source correlation with campaign evidence and MITRE ATT&CK mappings.
- Incident lifecycle, assignee, analyst notes, timeline, search, filtering, and coverage reporting.
- SQLite primary storage with JSON migration fallback and dual-write compatibility.
- YAML rule loading, validation, enable/disable audit, and Windows/Sysmon detections.
- Offline Windows event import and a polling collector with authenticated, deduplicated ingestion.
- Allowlisted response actions, simulation, analyst approval, rollback metadata, and optional webhooks.
- Dashboard authentication, viewer/analyst/admin roles, CSRF protection, and immutable audit chaining.
- Health diagnostics, agent heartbeat, alert retention, SQLite backups, and log rotation.
- Reproducible [end-to-end Blue Team demo](docs/DEMO_SCENARIO.md).

### Changed

- Replaced the former Groq integration and documentation with Ollama Cloud `gemma4:cloud`.
- Kept detector severity authoritative while exposing AI severity as a separate recommendation.
- Made response simulation the safe default and prevented arbitrary AI-generated command execution.
- Synchronized the README, environment template, architecture, and operational guidance with the implementation.

### Verification

- All 14 regression modules pass in the release image.
- Live SSH campaign → Ollama → analyst lifecycle → `BLOCK_IP` simulation → audit workflow passes.
- Clean-clone Compose configuration validation passes.
- No credential pattern or sensitive runtime file was found in the latest 30 commits.

See the [v0.3.0 release history](docs/RELEASE_HISTORY.md#mini-siem-v030-release-checklist) for setup, verification details, and known limitations.
