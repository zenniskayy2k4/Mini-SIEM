# Mini-SIEM Blue Team — Roadmap from v0.6.0 to v1.0.0

> **Repository:** `zenniskayy2k4/Mini-SIEM`
> **Starting point:** `v0.6.0`
> **Scope:** `v0.7.0` → `v0.8.0` → `v0.9.0` → `v1.0.0`
> **Environment:** Windows + Docker Desktop
> **Architecture:** Lightweight, single-node first
> **Storage:** SQLite primary + compatibility fallback
> **AI:** Ollama Cloud + optional bounded local Ollama fallback
> **Created:** 2026-08-23

---

## 1. Starting Baseline

The previous roadmap is complete through `v0.6.0`.

Mini-SIEM already includes:

- HIDS / NIDS / Honeypot telemetry.
- Windows Event Log / Sysmon collection.
- Native YAML and Sigma detection rules.
- Detection coverage tracking.
- Correlation, thresholding, deduplication, and cooldown.
- Standardized alert contract.
- SQLite storage.
- Incident lifecycle and analyst workflow.
- AI-assisted triage.
- Threat intelligence enrichment.
- Asset inventory and explainable risk scoring.
- Safe response simulation and analyst approval.
- Webhook notifications.
- TheHive and Jira export.
- Viewer / Analyst / Admin workspaces.
- Authentication, RBAC, CSRF, and session protections.
- Immutable analyst audit chain.
- Prometheus metrics and SOC analytics.
- PDF incident reports.
- Health diagnostics.
- Retention, backup, and restore.
- GitHub Actions CI and security checks.
- 43 executable regression modules at the `v0.6.0` release gate.

The next phase should focus on:

```text
Detection Validation
+ Detection Tuning
+ Data Quality
+ Platform Hardening
+ Supply-chain Security
+ Reliability
+ Performance
+ Stable Contracts
+ Upgrade Safety
```

The target is no longer “add more SOC features”. The target is:

```text
Reliable, testable, maintainable single-node SIEM
```

---

## 2. Do Not Start Multi-tenancy Yet

Multi-tenancy remains optional.

Do not implement it unless there is a concrete requirement for multiple isolated teams or organizations.

Also do not prioritize:

```text
Kubernetes
Kafka
Elasticsearch/OpenSearch
Full SOAR automation
Automatic production response
Custom EDR
Large distributed collector fleet
Microservice decomposition
```

Measure the current architecture before replacing it.

---

## 3. Release Strategy

### v0.7.0 — Detection Validation & Data Quality

```text
M19 — Adversary Replay & Detection Validation
M20 — Detection Tuning & Exception Management
M21 — Event Quality & Ingestion Reliability
```

### v0.8.0 — Platform & Supply-chain Hardening

```text
M22 — Secure Deployment Profile
M23 — Software Supply-chain Security
M24 — Database Migration & Disaster Recovery
```

### v0.9.0 — Performance & Operational Resilience

```text
M25 — Load Testing & Backpressure
M26 — Storage & Query Performance
M27 — Collector Reliability & Offline Recovery
```

### v1.0.0 — Stable Product Contract

```text
M28 — API & Schema Versioning
M29 — Operator Experience & Accessibility
M30 — Stable Release Qualification
```

### Optional after v1.0

```text
M31 — Multi-tenancy Discovery
```

---

## 4. Tracking Overview

| Milestone | Scope | Target | Status |
|---|---|---|---|
| M19 | Adversary Replay & Detection Validation | v0.7.0 | ✅ Complete |
| M20 | Detection Tuning & Exception Management | v0.7.0 | 🟠 In Progress |
| M21 | Event Quality & Ingestion Reliability | v0.7.0 | ⬜ |
| M22 | Secure Deployment Profile | v0.8.0 | ⬜ |
| M23 | Software Supply-chain Security | v0.8.0 | ⬜ |
| M24 | Database Migration & Disaster Recovery | v0.8.0 | ⬜ |
| M25 | Load Testing & Backpressure | v0.9.0 | ⬜ |
| M26 | Storage & Query Performance | v0.9.0 | ⬜ |
| M27 | Collector Reliability & Offline Recovery | v0.9.0 | ⬜ |
| M28 | API & Schema Versioning | v1.0.0 | ⬜ |
| M29 | Operator Experience & Accessibility | v1.0.0 | ⬜ |
| M30 | Stable Release Qualification | v1.0.0 | ⬜ |
| M31 | Multi-tenancy Discovery | Optional | ⬜ |

---

# M19 — Adversary Replay & Detection Validation

## M19.1 — Scenario Manifest Contract

**Status:** ✅ Complete — local verification passed

### Goal

Define a repository-native format for deterministic detection-validation scenarios.

### Proposed structure

```text
tests/scenarios/
├── linux/
├── windows/
├── network/
└── cross_source/
```

Example:

```yaml
id: SCN-SSH-BRUTE-001
title: SSH password guessing campaign
source: linux_auth
events: fixtures/ssh_bruteforce.jsonl

expected:
  rule_ids:
    - DET-SSH-001
  alert_count:
    min: 1
    max: 1
  severity: HIGH
  fields:
    event_count:
      min: 5

negative_expectations:
  rule_ids:
    - DET-LNX-002
```

### Tasks

- [x] Define scenario ID format.
- [x] Define metadata schema.
- [x] Define fixture path.
- [x] Define expected rule IDs.
- [x] Define expected severity.
- [x] Define alert count range.
- [x] Define expected alert fields.
- [x] Define negative expectations.
- [x] Validate duplicate IDs.
- [x] Reject malformed manifests clearly.
- [x] Keep validation offline.

### Definition of Done

- [x] One Linux scenario loads.
- [x] One Windows scenario loads.
- [x] Invalid scenario fails cleanly.
- [x] Duplicate ID is detected.
- [x] No runtime service is needed for manifest validation.

### Local verification — 2026-08-23

| Check | Result |
|---|:---:|
| Versioned schema, ID, source, expectations, field constraints | PASS |
| Linux SSH and Windows PowerShell manifests | PASS |
| Fixture existence/type and repository path boundary | PASS |
| Malformed YAML types and unknown/missing fields | PASS |
| Duplicate and overlapping rule IDs | PASS |
| Offline executable regression module | PASS |
| README release badge synchronized to v0.6.0 | PASS |
| 44 executable regression modules | PASS |
| Python/JavaScript syntax and Docker Compose validation | PASS |
| No provider call, runtime restart, dependency, or image build | PASS |

### Suggested commit

```text
test: add detection validation scenario contract
```

---

## M19.2 — Offline Event Replay Engine

**Status:** ✅ Complete

### Tool

```text
tools/replay_scenario.py
```

### Tasks

- [x] Load scenario manifest.
- [x] Load fixture events.
- [x] Preserve event ordering.
- [x] Support relative timestamps.
- [x] Feed events through existing detection paths.
- [x] Disable external AI/TI by default.
- [x] Disable notifications.
- [x] Disable response actions.
- [x] Use isolated temporary storage.
- [x] Produce JSON result.
- [x] Produce human-readable summary.

### Definition of Done

- [x] Replay is deterministic.
- [x] Same fixture gives the same result twice.
- [x] Replay cannot trigger live response execution.
- [x] Output can be consumed by CI.

### Local verification — 2026-08-23

| Check | Result |
|---|---|
| Linux and Windows fixtures replay through existing rule paths | PASS |
| Same corpus produces identical normalized results twice | PASS |
| Network calls blocked during executable regression | PASS |
| AI/TI, notification, response, and runtime persistence not initialized | PASS |
| Human-readable and stable JSON outputs | PASS |
| 45 executable regression modules | PASS |
| Python syntax and Docker Compose validation | PASS |
| No dependency, image build, runtime restart, or live data write | PASS |

### Suggested commit

```text
test: add offline detection scenario replay engine
```

---

## M19.3 — Detection Validation Corpus

**Status:** ✅ Complete

### Linux

- [x] SSH brute-force positive.
- [x] Single failed SSH negative.
- [x] Suspicious sudo.
- [x] Account creation.
- [x] Benign authentication.

### Windows

- [x] Encoded PowerShell.
- [x] Suspicious LOLBin.
- [x] Benign LOLBin negative.
- [x] Account creation.
- [x] Scheduled task.
- [x] Defender tampering.
- [x] LSASS access.
- [x] Office child process.

### Network

- [x] Existing NIDS positive cases for SYN scanning and ARP spoofing.
- [x] Benign network negative case.

### Cross-source

- [x] Same source IP across multiple telemetry sources.
- [x] Correlation produces one campaign instead of duplicate alerts.

### Definition of Done

- [x] Every high-value rule has a positive scenario.
- [x] Noisy rules have negative scenarios.
- [x] Sigma-backed detections are represented.
- [x] Corpus requires no Internet.

### Local verification — 2026-08-23

| Check | Result |
|---|:---:|
| 18 deterministic scenario manifests | PASS |
| 14 positive native, Sigma, NIDS, and correlation rule outcomes | PASS |
| Four Linux/Windows/network negative scenarios | PASS |
| Existing detector, NetworkMonitor, and AlertCorrelator paths | PASS |
| Sigma provenance and negative expectations | PASS |
| Same corpus produces identical results twice | PASS |
| 45 executable regression modules | PASS |
| Python syntax and Docker Compose validation | PASS |
| No Internet/provider call, response action, runtime write, or image build | PASS |

### Suggested commit

```text
test: add adversary replay validation corpus
```

---

## M19.4 — Validation Coverage Matrix

**Status:** ✅ Complete

### Model

```text
Rule
→ MITRE Technique
→ Scenarios
→ Last Validation Result
```

### Tasks

- [x] Add scenario count per rule.
- [x] Add validated/unvalidated state.
- [x] Distinguish rule hit from deterministic validation.
- [x] Generate Markdown/JSON coverage artifact.
- [x] Show unvalidated enabled rules.
- [x] Do not store CI-only state in runtime DB.

### Local verification — 2026-08-23

| Check | Result |
|---|:---:|
| 14 enabled native, Sigma, NIDS, and correlation rules inventoried | PASS |
| Positive/negative scenario counts and mappings | PASS |
| 14 validated, 0 failed, 0 unvalidated enabled rules | PASS |
| Runtime hit state explicitly remains `NOT_EVALUATED` | PASS |
| Markdown and JSON artifacts reproduce exactly with `--check` | PASS |
| 46 executable regression modules | PASS |
| Python/JavaScript syntax and Docker Compose validation | PASS |
| No runtime DB, provider, dependency, image build, or service restart | PASS |

### Suggested commit

```text
feat: add detection validation coverage matrix
```

---

## M19.5 — CI Scenario Gate

**Status:** ✅ Complete

### Tasks

- [x] Run replay corpus in GitHub Actions.
- [x] Fail on required scenario failure.
- [x] Save failure artifacts.
- [x] Print failed expectations clearly.
- [x] No Ollama/AbuseIPDB/VT/TAXII/Jira/TheHive calls.

### Local verification — 2026-08-23

| Check | Result |
|---|:---:|
| Workflow YAML parses with scenario gate and conditional upload steps | PASS |
| Exact replay, JSON artifact, human summary, and coverage check commands | PASS |
| Failed expectation returns exit 1 and retains human/JSON diagnostics | PASS |
| AI, GeoIP, AbuseIPDB, VT, TAXII, notification, Jira, and TheHive disabled | PASS |
| 46 executable regression modules | PASS |
| Python/JavaScript syntax and Docker Compose validation | PASS |
| No dependency, image build, service restart, or runtime data write | PASS |

### Suggested commit

```text
ci: gate detection changes with replay scenarios
```

---

# M20 — Detection Tuning & Exception Management

## M20.1 — Analyst Detection Feedback

**Status:** ✅ Complete

### Contract

```json
{
  "feedback_id": "FB-...",
  "alert_id": "ALT-...",
  "rule_id": "DET-...",
  "classification": "TRUE_POSITIVE|FALSE_POSITIVE|BENIGN_EXPECTED",
  "reason": "...",
  "actor": "...",
  "created_at": "..."
}
```

### Tasks

- [x] Add SQLite feedback table.
- [x] Analyst/Admin can classify.
- [x] Viewer remains read-only.
- [x] Reason required for false positive.
- [x] Store actor from session.
- [x] Add immutable audit event.
- [x] Do not mutate original evidence.

### Local verification — 2026-08-23

| Check | Result |
|---|:---:|
| SQLite feedback contract and alert/rule linkage | PASS |
| Analyst/Admin creation with session-derived actor | PASS |
| Viewer mutation blocked; latest classification remains visible | PASS |
| False-positive reason and request-field validation | PASS |
| Hash-chained audit event excludes reason text | PASS |
| Audit failure rolls back feedback transaction | PASS |
| Original alert evidence payload remains byte-for-byte unchanged | PASS |
| 47 executable regression modules | PASS |
| Python/JavaScript syntax and Docker Compose validation | PASS |
| Dashboard-only rollout and health smoke test | PASS |

### Suggested commit

```text
feat: add analyst detection feedback
```

---

## M20.2 — Rule Quality Metrics

**Status:** ✅ Complete

### Metrics

```text
alerts generated
true positives
false positives
benign expected
unclassified
false-positive rate
validation scenario count
last validation result
```

### Rules

- [x] Do not claim precision/recall without ground truth.
- [x] Show sample size.
- [x] Time-range filtering.
- [x] Distinguish unclassified from true positive.

### Local verification — 2026-08-25

| Check | Result |
|---|:---:|
| Latest feedback per alert prevents double counting | PASS |
| Alerts, true/false positive, benign, and unclassified counts | PASS |
| False-positive rate uses classified sample only | PASS |
| Existing `[from,to)` alert-created time range | PASS |
| Validation scenario count and last result merged from M19 artifact | PASS |
| Missing/malformed validation metadata degrades to `UNAVAILABLE` | PASS |
| Viewer-readable responsive table with explicit sample size | PASS |
| No reason, actor, precision, or recall exposed in metrics | PASS |
| 48 executable regression modules | PASS |
| Python/JavaScript syntax and Docker Compose validation | PASS |
| Dashboard-only rollout, 14-rule query, and health smoke test | PASS |
| Runtime alert evidence hash unchanged after analytics query | PASS |

### Suggested commit

```text
feat: add rule quality metrics
```

---

## M20.3 — Scoped Detection Exceptions

**Status:** ✅ Complete

### Initial scopes

- [x] hostname
- [x] source IP
- [x] user
- [x] process path
- [x] rule ID
- [x] asset ID

### Safety

- [x] Reason required.
- [x] Creator recorded.
- [x] Optional expiry.
- [x] Broad wildcard rejected by default.
- [x] All changes audited.
- [x] Exception match visible.
- [x] Raw event is never deleted.

### Local verification — 2026-08-25

| Check | Result |
|---|:---:|
| Exact matching for hostname, source IP, user, process path, rule ID, and asset ID | PASS |
| Required reason, session-derived creator, and optional future expiry | PASS |
| Empty, malformed, expired, relative-path, and wildcard scopes rejected | PASS |
| Admin-only API/UI with CSRF enforcement | PASS |
| Hash-chained create/delete audit; reason excluded from audit | PASS |
| Audit failure rolls back the database transaction | PASS |
| Match visible while original raw evidence remains stored | PASS |
| Matched telemetry skips incident creation, AI enrichment, and notification | PASS |
| Responsive admin exception workspace | PASS |
| 49 executable regression modules | PASS |
| Python/JavaScript syntax and Docker Compose validation | PASS |
| Dashboard/agent rollout, schema read, and health smoke test | PASS |
| Builder cache cleared to 0 B; Docker VHDX compacted from 15.55 GiB to 12.26 GiB | PASS |

### Suggested commit

```text
feat: add scoped detection exceptions
```

---

## M20.4 — Alert Suppression Windows

**Status:** ✅ Complete

### Principle

```text
Exception = known benign pattern should not alert.
Suppression = detection is valid, but repeated alerts should be grouped/rate-limited.
```

### Tasks

- [x] Scope by rule + correlation key.
- [x] Preserve suppressed count.
- [x] Preserve first/last seen.
- [x] Show suppression count.
- [x] Audit policy changes.

### Local verification — 2026-08-25

| Check | Result |
|---|:---:|
| Exact rule ID plus correlation-key policy scope | PASS |
| Missing, wildcard, duplicate, non-integer, and out-of-range policies rejected | PASS |
| Repeated alerts grouped inside the configured window | PASS |
| Alerts outside the window or exact scope remain independent | PASS |
| Suppressed count and aggregate event count preserved | PASS |
| First/last seen retained while representative evidence remains unchanged | PASS |
| Suppressed repeats skip response, AI enrichment, forwarding, and notification | PASS |
| Admin-only API/UI with CSRF enforcement | PASS |
| Hash-chained policy create/delete audit with rollback on audit failure | PASS |
| Responsive policy table and visible suppression summary | PASS |
| 50 executable regression modules | PASS |
| Python/JavaScript syntax and Docker Compose validation | PASS |
| Dashboard/agent rollout, empty policy-schema read, and health smoke test | PASS |
| Cache older than 24 hours pruned while fresh dependency cache was retained | PASS |
| Docker VHDX compacted from 13.67 GiB to 13.36 GiB | PASS |

### Suggested commit

```text
feat: add configurable alert suppression policies
```

---

## M20.5 — Detection Tuning Workspace

**Status:** ⬜

### UI

```text
Rule
├── status
├── hit count
├── validation status
├── feedback
├── exceptions
├── suppression
└── MITRE mapping
```

### Tasks

- [ ] Admin controls mutation.
- [ ] Analyst may submit feedback.
- [ ] CSRF/RBAC enforced.
- [ ] Active exception expiry visible.

### Suggested commit

```text
feat: add detection tuning workspace
```

---

# M21 — Event Quality & Ingestion Reliability

## M21.1 — Versioned Event Envelope

**Status:** ⬜

```json
{
  "event_schema_version": 1,
  "event_id": "EVT-...",
  "source_type": "WINDOWS_EVENT",
  "collector_id": "...",
  "received_at": "...",
  "observed_at": "...",
  "payload": {}
}
```

### Tasks

- [ ] Add schema version.
- [ ] Stable event ID.
- [ ] Collector/source identity.
- [ ] Separate receive and observed time.
- [ ] Backward compatibility.
- [ ] Document required/optional fields.

### Suggested commit

```text
refactor: version normalized event envelope
```

---

## M21.2 — Parser Failure / Dead-letter Diagnostics

**Status:** ⬜

### Store

```text
ingestion_failures
```

### Tasks

- [ ] Capture parser errors.
- [ ] Capture schema errors.
- [ ] Capture unsupported event types.
- [ ] Bound payload preview.
- [ ] Redact obvious secrets.
- [ ] Apply retention.
- [ ] Add metrics.
- [ ] Add admin diagnostics.

### Suggested commit

```text
feat: add ingestion dead-letter diagnostics
```

---

## M21.3 — Ingestion Health Metrics

**Status:** ⬜

```text
events_received_total
events_normalized_total
events_rejected_total
events_deduplicated_total
event_processing_seconds
collector_last_seen_seconds
```

### Rules

- [ ] No raw IP/user labels.
- [ ] Keep label cardinality bounded.

### Suggested commit

```text
feat: add telemetry ingestion health metrics
```

---

## M21.4 — Event Gap Detection

**Status:** ⬜

### Tasks

- [ ] Collector heartbeat state.
- [ ] Stale threshold.
- [ ] Distinguish offline / idle / endpoint unavailable.
- [ ] Add diagnostic state.
- [ ] Optional internal operational alert.
- [ ] Avoid repeated alert storm.

### Suggested commit

```text
feat: detect stale telemetry sources
```

---

## M21.5 — Release v0.7.0

**Status:** ⬜

```text
v0.7.0 — Detection Validation & Data Quality
```

### Release Gate

- [ ] Scenario validation exists.
- [ ] Replay is deterministic.
- [ ] Core detections have scenarios.
- [ ] Scenario CI gate runs.
- [ ] Detection feedback exists.
- [ ] Rule quality metrics exist.
- [ ] Exceptions and suppression are audited.
- [ ] Event envelope is versioned.
- [ ] Parser failures are observable.
- [ ] Ingestion metrics exist.
- [ ] Stale collectors are detectable.
- [ ] Existing regressions still pass.
- [ ] README/CHANGELOG/upgrade notes updated.
- [ ] Clean clone passes.
- [ ] Tag only after CI passes.

### Suggested commit

```text
docs: release v0.7.0
```

---

# M22 — Secure Deployment Profile

## M22.1 — Configuration Validator

**Status:** ⬜

### Command

```text
python -m tools.validate_config
```

### Validate

- [ ] Required secrets.
- [ ] Secret minimum length.
- [ ] Secure-cookie/TLS compatibility.
- [ ] AI provider conflicts.
- [ ] Retention values.
- [ ] Response mode.
- [ ] Webhook URL scheme.
- [ ] Unsafe bind warnings.
- [ ] Production debug mode forbidden.

### Suggested commit

```text
feat: add deployment configuration validator
```

---

## M22.2 — HTTPS Reverse-proxy Profile

**Status:** ⬜

### Architecture

```text
Browser → HTTPS Reverse Proxy → Dashboard
```

### Tasks

- [ ] TLS termination.
- [ ] HTTP → HTTPS redirect.
- [ ] Trusted proxy handling.
- [ ] Secure session cookie.
- [ ] Forwarded-header validation.
- [ ] Request/body limits.
- [ ] Local development certificate path documented.

### Suggested commit

```text
feat: add HTTPS reverse-proxy deployment profile
```

---

## M22.3 — File-based Secret Support

**Status:** ⬜

### Pattern

```text
*_FILE
```

Examples:

```text
OLLAMA_API_KEY_FILE
ABUSEIPDB_API_KEY_FILE
VT_API_KEY_FILE
DASHBOARD_SESSION_SECRET_FILE
```

### Tasks

- [ ] File secret loader.
- [ ] Conflict handling.
- [ ] Never log secret contents.
- [ ] Existing env behavior remains supported.

### Suggested commit

```text
feat: support file-based application secrets
```

---

## M22.4 — Security Regression Pack

**Status:** ⬜

### Cases

- [ ] RBAC denial.
- [ ] CSRF denial.
- [ ] Session revocation.
- [ ] Login throttling.
- [ ] XSS escaping.
- [ ] Oversized request rejection.
- [ ] Collector-secret rejection.
- [ ] Secure-cookie behavior under HTTPS.

### Suggested commit

```text
test: add deployment security regression pack
```

---

# M23 — Software Supply-chain Security

## M23.1 — Dependency Reproducibility

**Status:** ⬜

- [ ] Define pinning policy.
- [ ] Pin production dependencies reproducibly.
- [ ] Keep security update workflow.
- [ ] Avoid unnecessary dependencies.
- [ ] CI validates consistency.

### Suggested commit

```text
build: tighten dependency reproducibility
```

---

## M23.2 — SBOM Generation

**Status:** ⬜

### Output

```text
CycloneDX or SPDX
```

### Tasks

- [ ] Generate in CI.
- [ ] Include Python dependencies.
- [ ] Include container packages where feasible.
- [ ] Attach to releases.

### Suggested commit

```text
ci: generate release software bill of materials
```

---

## M23.3 — Container Vulnerability Scan

**Status:** ⬜

- [ ] Scan built image.
- [ ] Define severity gate.
- [ ] Document exceptions.
- [ ] Save artifact on failure.

### Suggested commit

```text
ci: scan Mini-SIEM container image
```

---

## M23.4 — Release Checksums

**Status:** ⬜

- [ ] Generate SHA-256 checksums.
- [ ] Verify before publication.
- [ ] Document verification.

### Suggested commit

```text
build: add release artifact checksums
```

---

# M24 — Database Migration & Disaster Recovery

## M24.1 — Schema Migration Table

**Status:** ⬜

```text
schema_migrations
```

Fields:

```text
version
name
applied_at
checksum
```

### Tasks

- [ ] Baseline current schema.
- [ ] Deterministic order.
- [ ] Idempotent detection.
- [ ] Failed migration not marked complete.

### Suggested commit

```text
refactor: add database schema migration tracking
```

---

## M24.2 — Migration Runner

**Status:** ⬜

```text
python -m tools.migrate_db
```

### Tasks

- [ ] Backup first.
- [ ] Validate source version.
- [ ] Ordered migrations.
- [ ] Transaction where possible.
- [ ] Integrity check.
- [ ] `--dry-run`.
- [ ] Print current/target version.

### Suggested commit

```text
feat: add versioned database migration runner
```

---

## M24.3 — Automated Restore Drill

**Status:** ⬜

### Flow

```text
Sample data
→ backup
→ damage/replace working copy
→ restore
→ integrity check
→ state verification
```

### Verify

- [ ] alerts
- [ ] incidents
- [ ] assets
- [ ] external case IDs
- [ ] schema version
- [ ] audit-related state as applicable

### Suggested commit

```text
test: automate database backup and restore drill
```

---

## M24.4 — Historical Upgrade Matrix

**Status:** ⬜

### Minimum

```text
v0.6.0 data → current
v0.7.0 data → current
fresh database → current
```

### Rules

- [ ] Extend for every new release.
- [ ] Upgrade failure blocks release.

### Suggested commit

```text
ci: validate historical database upgrades
```

---

## M24.5 — Release v0.8.0

**Status:** ⬜

```text
v0.8.0 — Platform & Supply-chain Hardening
```

### Release Gate

- [ ] Config validator.
- [ ] HTTPS profile.
- [ ] File secrets.
- [ ] Security regression pack.
- [ ] Reproducible dependencies.
- [ ] SBOM.
- [ ] Container scan.
- [ ] Checksums.
- [ ] Migration framework.
- [ ] Restore drill.
- [ ] Historical upgrade tests.
- [ ] Docs synchronized.
- [ ] Tag after CI passes.

### Suggested commit

```text
docs: release v0.8.0
```

---

# M25 — Load Testing & Backpressure

## M25.1 — Synthetic Telemetry Load Generator

**Status:** ⬜

### Modes

```text
steady
burst
mixed-source
windows-heavy
authentication-heavy
```

### Safety

- [ ] Local by default.
- [ ] Generate telemetry, not exploit traffic.
- [ ] AI/TI disabled.

### Suggested commit

```text
test: add synthetic telemetry load generator
```

---

## M25.2 — Throughput Benchmark

**Status:** ⬜

### Measure

```text
events/sec
normalization latency
detection latency
SQLite write latency
dashboard API latency
CPU
memory
queue depth
dropped/rejected events
```

### Candidate loads

```text
10 events/s
50 events/s
100 events/s
250 events/s
burst
```

Adjust to actual machine capability.

### Suggested commit

```text
perf: add single-node throughput benchmark
```

---

## M25.3 — Bounded Ingestion Queue

**Status:** ⬜

### Tasks

- [ ] Bounded queue.
- [ ] Queue-depth metric.
- [ ] Explicit overload policy.
- [ ] Prefer backpressure where supported.
- [ ] Never silently drop.
- [ ] Count rejected/dropped events.
- [ ] Health reports saturation.

### Suggested commit

```text
feat: add bounded ingestion backpressure
```

---

## M25.4 — Graceful Degradation

**Status:** ⬜

### States

```text
healthy
degraded
saturated
```

### Rules

- [ ] Core detection/persistence has priority.
- [ ] AI/TI can degrade first.
- [ ] Notifications remain bounded.
- [ ] Health exposes overload.

### Suggested commit

```text
feat: add graceful overload degradation
```

---

# M26 — Storage & Query Performance

## M26.1 — SQLite Query Plan Audit

**Status:** ⬜

### Audit

- [ ] alert list
- [ ] time range
- [ ] incident status
- [ ] rule coverage
- [ ] KPIs
- [ ] analytics
- [ ] assets
- [ ] feedback/rule quality

### Tasks

- [ ] Use `EXPLAIN QUERY PLAN`.
- [ ] Document scans.
- [ ] Add justified indexes only.
- [ ] Measure before/after.

### Suggested commit

```text
perf: optimize SQLite query indexes
```

---

## M26.2 — Bounded Batched Writes

**Status:** ⬜

Only implement if benchmarks show transaction overhead is significant.

- [ ] Safe batch size.
- [ ] Maximum flush delay.
- [ ] Flush on shutdown.
- [ ] Preserve required ordering.
- [ ] Benchmark improvement.

### Suggested commit

```text
perf: add bounded telemetry write batching
```

---

## M26.3 — Large-history Benchmark

**Status:** ⬜

### Dataset sizes

```text
10k alerts
50k alerts
100k alerts
```

### Verify

- [ ] alert API
- [ ] search
- [ ] analytics
- [ ] rule coverage
- [ ] incident workspace
- [ ] report generation
- [ ] retention

### Suggested commit

```text
perf: add large-history query benchmark
```

---

# M27 — Collector Reliability & Offline Recovery

## M27.1 — Collector Identity

**Status:** ⬜

Fields:

```text
collector_id
collector_version
hostname
source_type
last_seen
```

- [ ] Stable collector ID.
- [ ] Server tracks last seen.
- [ ] Version visible.
- [ ] Duplicate ID warning.

### Suggested commit

```text
feat: add collector identity and version tracking
```

---

## M27.2 — Buffer Diagnostics

**Status:** ⬜

### Metrics

```text
buffered_events
buffer_oldest_age
retry_attempts
delivery_failures
last_successful_delivery
```

### Tasks

- [ ] Bound buffer size.
- [ ] Oldest-first replay.
- [ ] Delete only after acknowledgement.
- [ ] Corrupt entry handled safely.
- [ ] Admin diagnostics.

### Suggested commit

```text
feat: add collector buffer diagnostics
```

---

## M27.3 — Collector Protocol Version

**Status:** ⬜

- [ ] Collector reports protocol/schema version.
- [ ] Unsupported future version rejected clearly.
- [ ] Supported legacy version accepted.
- [ ] Compatibility matrix documented.

### Suggested commit

```text
feat: version collector ingestion protocol
```

---

## M27.4 — Outage Recovery Scenario

**Status:** ⬜

```text
collector running
→ server unavailable
→ events buffered
→ server returns
→ replay
→ no duplicates
→ cursor advances
```

### Definition of Done

- [ ] No silent loss.
- [ ] Buffer drains.
- [ ] Dedup behaves correctly.
- [ ] Test is offline/deterministic.

### Suggested commit

```text
test: add collector outage recovery scenario
```

---

## M27.5 — Release v0.9.0

**Status:** ⬜

```text
v0.9.0 — Performance & Operational Resilience
```

### Release Gate

- [ ] Load generator.
- [ ] Throughput baseline.
- [ ] Explicit overload behavior.
- [ ] Queue health.
- [ ] Query plan audit.
- [ ] Large-history benchmark.
- [ ] Collector identity.
- [ ] Buffer diagnostics.
- [ ] Protocol version.
- [ ] Outage recovery regression.
- [ ] Migration regression.
- [ ] Tag after CI.

### Suggested commit

```text
docs: release v0.9.0
```

---

# M28 — API & Schema Versioning

## M28.1 — REST API v1

**Status:** ⬜

Example:

```text
/api/v1/alerts
/api/v1/incidents/...
/api/v1/assets
/api/v1/system/status
```

### Tasks

- [ ] Inventory current endpoints.
- [ ] Classify public/internal.
- [ ] Define v1 contracts.
- [ ] Add versioned routes.
- [ ] Temporary compatibility aliases.
- [ ] Deprecation documentation.

### Suggested commit

```text
refactor: introduce versioned REST API v1
```

---

## M28.2 — Alert Schema Version

**Status:** ⬜

- [ ] Add `alert_schema_version`.
- [ ] Document field semantics.
- [ ] Document nullable fields.
- [ ] Document enums.
- [ ] Define compatibility policy.
- [ ] Normalize legacy alerts through adapter.

### Suggested commit

```text
refactor: version persisted alert schema
```

---

## M28.3 — Machine-readable API Contract

**Status:** ⬜

Use OpenAPI or JSON Schema.

- [ ] Core endpoints.
- [ ] Auth requirements.
- [ ] Error model.
- [ ] Pagination.
- [ ] Request limits.
- [ ] CI schema validation.

### Suggested commit

```text
docs: add machine-readable API contract
```

---

## M28.4 — API Compatibility Regression

**Status:** ⬜

- [ ] Required response fields.
- [ ] Error status behavior.
- [ ] Permission boundaries.
- [ ] Pagination.
- [ ] Legacy alert normalization.

### Suggested commit

```text
test: add API compatibility regression suite
```

---

# M29 — Operator Experience & Accessibility

## M29.1 — Environment Doctor

**Status:** ⬜

```text
python -m tools.doctor
```

### Check

- [ ] required directories
- [ ] writable data path
- [ ] DB integrity
- [ ] admin user existence
- [ ] config validity
- [ ] optional integrations
- [ ] collector config
- [ ] AI readiness without consuming an analysis request

### Suggested commit

```text
feat: add Mini-SIEM environment doctor
```

---

## M29.2 — Unified Diagnostics View

**Status:** ⬜

Answer:

```text
Why am I not receiving events?
Why is AI unavailable?
Why did a rule not load?
Why did an integration fail?
Is the database healthy?
```

### Tasks

- [ ] Link health status.
- [ ] Link ingestion failures.
- [ ] Link rule-load failures.
- [ ] Link provider state.
- [ ] Link collector state.
- [ ] Never expose secrets.

### Suggested commit

```text
feat: add unified operator diagnostics view
```

---

## M29.3 — Accessibility Pass

**Status:** ⬜

- [ ] keyboard navigation
- [ ] visible focus
- [ ] semantic labels
- [ ] form error association
- [ ] table headers
- [ ] dialog focus
- [ ] color not sole status signal
- [ ] basic contrast
- [ ] mobile behavior retained

### Suggested commit

```text
fix: improve dashboard accessibility
```

---

## M29.4 — Operator Runbooks

**Status:** ⬜

Documents:

```text
docs/OPERATIONS.md
docs/UPGRADE.md
docs/TROUBLESHOOTING.md
docs/SECURITY.md
```

Cover:

- [ ] start/stop
- [ ] upgrade
- [ ] backup/restore
- [ ] collectors
- [ ] TLS
- [ ] secret rotation
- [ ] rule debugging
- [ ] AI/TI debugging
- [ ] integrations
- [ ] retention
- [ ] disaster recovery

### Suggested commit

```text
docs: add production-style operator runbooks
```

---

# M30 — v1.0 Stable Release Qualification

## M30.1 — Feature Freeze

**Status:** ⬜

Allowed:

```text
bug fixes
security fixes
documentation
performance regression fixes
release blockers
```

Not allowed:

```text
new major features
schema redesign
new external providers
new architectural layer
```

### Suggested commit

```text
docs: enter v1.0 release candidate freeze
```

---

## M30.2 — Full Regression Qualification

**Status:** ⬜

Required:

- [ ] existing regression modules
- [ ] detection replay corpus
- [ ] Sigma corpus
- [ ] AI evaluation corpus
- [ ] security regression pack
- [ ] API compatibility suite
- [ ] DB migration tests
- [ ] backup/restore drill
- [ ] collector outage recovery
- [ ] load smoke
- [ ] clean-clone Docker smoke

---

## M30.3 — Upgrade Qualification

**Status:** ⬜

Required paths:

```text
v0.6.0 → v1.0.0
v0.7.0 → v1.0.0
v0.8.0 → v1.0.0
v0.9.0 → v1.0.0
fresh install → v1.0.0
```

Verify:

- [ ] alerts
- [ ] incidents
- [ ] assets
- [ ] rule state
- [ ] Sigma overrides
- [ ] feedback
- [ ] audit state
- [ ] external case IDs
- [ ] retention config
- [ ] users

---

## M30.4 — Security Review

**Status:** ⬜

Review:

- [ ] authentication
- [ ] authorization
- [ ] CSRF
- [ ] session lifecycle
- [ ] file/path handling
- [ ] external HTTP
- [ ] webhook boundaries
- [ ] PDF output
- [ ] collector endpoint
- [ ] YAML/Sigma parsing
- [ ] STIX/TAXII parsing
- [ ] secrets
- [ ] backup/restore
- [ ] audit integrity
- [ ] response safety

Output:

```text
docs/SECURITY_REVIEW_v1.0.md
```

### Suggested commit

```text
docs: add v1.0 security review
```

---

## M30.5 — Release Candidate

**Status:** ⬜

```text
v1.0.0-rc.1
```

- [ ] publish RC
- [ ] fresh install smoke
- [ ] upgrade smoke
- [ ] demo scenario
- [ ] operator runbook walkthrough
- [ ] stabilization period without blocker

---

## M30.6 — Release v1.0.0

**Status:** ⬜

```text
v1.0.0 — Stable Single-node Blue Team SIEM
```

### Definition of Done

- [ ] API v1 documented.
- [ ] Alert schema versioned.
- [ ] Migration framework stable.
- [ ] Detection validation stable.
- [ ] Data-quality diagnostics stable.
- [ ] Secure deployment profile stable.
- [ ] Supply-chain checks stable.
- [ ] Load behavior measured.
- [ ] Collector recovery tested.
- [ ] Operator diagnostics available.
- [ ] Accessibility pass complete.
- [ ] Runbooks complete.
- [ ] Full regression qualification passes.
- [ ] Upgrade qualification passes.
- [ ] Security review complete.
- [ ] RC validated.
- [ ] README/CHANGELOG sync.
- [ ] No tracked secrets.
- [ ] SBOM generated.
- [ ] Checksums generated.
- [ ] Annotated tag points to CI-verified release commit.

### Suggested commit

```text
docs: release Mini-SIEM v1.0.0
```

---

# M31 — Multi-tenancy Discovery

**Status:** Optional / Do not implement automatically

Only start when there is a concrete multi-organization requirement.

## M31.1 — Requirement Discovery

- [ ] Define tenant.
- [ ] Can users belong to multiple tenants?
- [ ] Are rules tenant-specific?
- [ ] Are collectors tenant-bound?
- [ ] Are assets tenant-bound?
- [ ] Are TI feeds shared?
- [ ] Are AI providers shared?
- [ ] Are integrations tenant-specific?
- [ ] Is audit global or tenant-local?
- [ ] What data must never cross tenants?

## M31.2 — Threat Model

Review:

```text
cross-tenant leakage
IDOR
RBAC bypass
cache leakage
search leakage
metrics leakage
audit leakage
backup leakage
integration-secret leakage
collector impersonation
```

## M31.3 — Migration Design

Define tenant ownership for:

- alerts
- incidents
- assets
- users
- collectors
- rules
- exceptions
- feedback
- response actions
- integrations
- audit events

Do not implement multi-tenancy until M31.1–M31.3 are complete.

---

# 5. Mandatory Execution Order

```text
M19 Detection Replay & Validation
→ M20 Detection Tuning
→ M21 Event Quality
→ v0.7.0

→ M22 Secure Deployment
→ M23 Supply-chain Security
→ M24 Migration & Disaster Recovery
→ v0.8.0

→ M25 Load & Backpressure
→ M26 Storage Performance
→ M27 Collector Resilience
→ v0.9.0

→ M28 Stable API/Schema
→ M29 Operator Experience
→ M30 v1.0 Qualification
→ v1.0.0
```

Do not start M31 unless a multi-tenant requirement exists.

---

# 6. Start Here

```text
NEXT BATCH:
M20.5 — Detection Tuning Workspace
```

M20.4 established configurable alert suppression windows:

```text
exact rule + correlation-key policy
→ grouped repeat count + preserved first/last seen
→ no repeated response, AI, forwarding, or notification side effects
```

Next, add only M20.5 detection tuning workspace; keep event-envelope work in M21.1.

---

# 7. Batch Tracking Template

```markdown
## Batch Mxx.x — Name

**Status:** 🟠 In Progress
**Started:** YYYY-MM-DD
**Completed:**
**Commit:**
**CI Run:**

### Goal

...

### Scope

Included:
- ...

Not included:
- ...

### Files Changed

- `...`

### Tasks

- [ ] ...

### Verification

- [ ] Focused regression passes.
- [ ] Full regression passes where required.
- [ ] Python syntax passes.
- [ ] JavaScript syntax passes if applicable.
- [ ] Docker Compose validation passes.
- [ ] Relevant service smoke passes.
- [ ] No unexpected external call.
- [ ] No secret committed.
- [ ] Working tree clean after commit.
- [ ] GitHub Actions passes.

### Evidence

```text
<commands/results>
```

### Security Notes

- ...

### Known Limitations

- ...

### Follow-up

- ...
```

---

# 8. Pre-commit Checklist

```powershell
git status --short
git diff
git check-ignore .env
```

- [ ] No `.env` tracked.
- [ ] No API key/token.
- [ ] No runtime data/logs.
- [ ] No accidental temp fixture.
- [ ] No generated report unless intentional.
- [ ] Relevant regression passes.
- [ ] Docs updated for contract changes.
- [ ] One logical batch per commit.

---

# 9. Release Checklist

- [ ] CI green.
- [ ] Working tree clean.
- [ ] Version confirmed.
- [ ] README synchronized.
- [ ] CHANGELOG synchronized.
- [ ] `.env.example` synchronized.
- [ ] Upgrade notes written.
- [ ] Known limitations written.
- [ ] Clean-clone verification.
- [ ] Docker Compose validation.
- [ ] Runtime health smoke.
- [ ] Required regressions pass.
- [ ] No tracked secrets.
- [ ] DB migration path tested.
- [ ] Backup/restore tested where relevant.
- [ ] SBOM/checksums generated where required.
- [ ] Release commit passes CI.
- [ ] Annotated tag points to verified commit.

---

# 10. Quality Gates

## v0.7.0

```text
Detection behavior is reproducible.
Telemetry failures are observable.
Rule tuning is audited.
```

## v0.8.0

```text
Deployment is hardened.
Release artifacts are inspectable.
Database upgrades and recovery are tested.
```

## v0.9.0

```text
Single-node capacity is measured.
Overload is bounded.
Collector outages recover predictably.
```

## v1.0.0

```text
Contracts are versioned.
Upgrade paths are verified.
Security and operations are documented.
The release is stable rather than feature-driven.
```

---

# 11. Decision Log

| Date | Decision | Reason |
|---|---|---|
| 2026-08-23 | Treat `v0.6.0` as feature-complete SOC baseline | Core SOC, AI, TI, asset, integration, and workspace features already exist |
| 2026-08-23 | Do not automatically implement multi-tenancy | No concrete multi-organization requirement |
| 2026-08-23 | Prioritize detection replay | Existing rules need behavioral validation |
| 2026-08-23 | Add tuning before scaling | Noise management is detection-engineering maturity |
| 2026-08-23 | Version telemetry before v1.0 | Compatibility becomes harder after stable release |
| 2026-08-23 | Measure single-node capacity before changing architecture | Avoid premature Kafka/OpenSearch/microservices |
| 2026-08-23 | Degrade AI/TI before core detection under load | Detection and persistence have higher priority |
| 2026-08-23 | Add DB migrations before v1.0 | Persistent upgrades need repeatable safety |
| 2026-08-23 | Version REST API and alert schema before v1.0 | Stable release requires compatibility boundaries |
| 2026-08-23 | Require release candidate before final v1.0 | v1.0 is a stabilization milestone |

---

# 12. Roadmap Completion

This roadmap is complete when:

- [ ] `v0.7.0` ships with detection replay, tuning, and ingestion quality.
- [ ] `v0.8.0` ships with secure deployment, supply-chain checks, and tested migration/recovery.
- [ ] `v0.9.0` ships with measured performance and collector recovery.
- [ ] API v1 exists.
- [ ] Alert schema is explicitly versioned.
- [ ] Historical upgrade tests pass.
- [ ] Operator diagnostics and runbooks are complete.
- [ ] Accessibility pass is complete.
- [ ] Full security review is complete.
- [ ] `v1.0.0-rc.1` is validated.
- [ ] `v1.0.0` is tagged from a CI-verified release commit.
- [ ] Multi-tenancy remains separate unless a real requirement appears.

---

# 13. Current Next Action

```text
START:
M20.5 — Detection Tuning Workspace
```

M20.4 now groups exact repeated detections without hiding the valid representative alert. Success for the next batch is:

```text
rule status + hit and validation context
+ feedback, exception, suppression, and MITRE context
+ admin mutation, analyst feedback, CSRF/RBAC, and visible expiry
= cohesive detection tuning workspace
```
