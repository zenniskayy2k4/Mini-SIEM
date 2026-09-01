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
| M20 | Detection Tuning & Exception Management | v0.7.0 | ✅ Complete |
| M21 | Event Quality & Ingestion Reliability | v0.7.0 | ✅ Complete |
| M22 | Secure Deployment Profile | v0.8.0 | ✅ Complete |
| M23 | Software Supply-chain Security | v0.8.0 | ✅ Complete |
| M24 | Database Migration & Disaster Recovery | v0.8.0 | ✅ Complete |
| M25 | Load Testing & Backpressure | v0.9.0 | ✅ Complete |
| M26 | Storage & Query Performance | v0.9.0 | ✅ Complete |
| M27 | Collector Reliability & Offline Recovery | v0.9.0 | ✅ Complete |
| M28 | API & Schema Versioning | v1.0.0 | ✅ Complete |
| M29 | Operator Experience & Accessibility | v1.0.0 | 🟠 In Progress |
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

### Suggested commit

```text
feat: add configurable alert suppression policies
```

---

## M20.5 — Detection Tuning Workspace

**Status:** ✅ Complete

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

- [x] Admin controls mutation.
- [x] Analyst may submit feedback.
- [x] CSRF/RBAC enforced.
- [x] Active exception expiry visible.

### Local verification — 2026-08-25

| Check | Result |
|---|:---:|
| Analyst/admin tuning workspace with viewer access denied | PASS |
| Rule status, hit count, validation, feedback, exception, suppression, and MITRE context | PASS |
| Evidence-bound analyst feedback path through filtered alerts | PASS |
| Admin-only Sigma mutation with global CSRF enforcement | PASS |
| Active exception scopes and expiry visible; expired records excluded | PASS |
| Untrusted exception and rule values escaped before HTML rendering | PASS |
| Unsupported Sigma rules remain visible with an unmapped MITRE state | PASS |
| Responsive filter, rule table, exception table, and role-aware navigation | PASS |
| 51 executable regression modules on source and built image | PASS |
| Python/JavaScript syntax and Docker Compose validation | PASS |
| Dependency layers reused from cache without reinstalling packages | PASS |
| Dashboard-only rollout, 11-rule live payload read, and health smoke test | PASS |
| Age-bounded cache cleanup retained 12.72 MiB of fresh BuildKit cache | PASS |

### Suggested commit

```text
feat: add detection tuning workspace
```

---

# M21 — Event Quality & Ingestion Reliability

## M21.1 — Versioned Event Envelope

**Status:** ✅ Complete

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

- [x] Add schema version.
- [x] Stable event ID.
- [x] Collector/source identity.
- [x] Separate receive and observed time.
- [x] Backward compatibility.
- [x] Document required/optional fields.

### Local verification — 2026-08-25

| Check | Result |
|---|:---:|
| Strict v1 envelope shape, schema version, source type, and stable event identity | PASS |
| Collector identity validation and separate received/observed timestamps | PASS |
| Payload tampering, unsupported versions, unknown fields, and invalid IDs rejected | PASS |
| Legacy flat Windows records remain readable as schema version 0 | PASS |
| New and legacy collector API field names accepted during migration | PASS |
| Windows import, detection, replay, and deterministic deduplication compatibility | PASS |
| Required and source-specific optional fields documented | PASS |
| 52 executable regression modules on source and built image | PASS |
| Python syntax and Docker Compose validation | PASS |
| Dependency layers reused from cache without reinstalling packages | PASS |
| Dashboard and agent rollout, in-memory v1 validation, and health smoke test | PASS |
| No cache older than 24 hours or dangling image found; 22.13 MiB fresh BuildKit cache retained | PASS |

### Suggested commit

```text
refactor: version normalized event envelope
```

---

## M21.2 — Parser Failure / Dead-letter Diagnostics

**Status:** ✅ Complete

### Store

```text
ingestion_failures
```

### Tasks

- [x] Capture parser errors.
- [x] Capture schema errors.
- [x] Capture unsupported event types.
- [x] Bound payload preview.
- [x] Redact obvious secrets.
- [x] Apply retention.
- [x] Add metrics.
- [x] Add admin diagnostics.

### Local verification — 2026-08-25

| Check | Result |
|---|:---:|
| Parser, schema, and unsupported Windows events retained in SQLite | PASS |
| Payload previews bounded to 512 characters | PASS |
| Secret-like fields, bearer values, XML data, and URL credentials redacted before storage | PASS |
| Diagnostic storage failures do not block primary ingestion | PASS |
| Age-based retention applied during diagnostic reads and writes | PASS |
| Prometheus metrics use three bounded failure-type labels | PASS |
| Recent redacted failures visible only in the admin workspace | PASS |
| Untrusted diagnostic values escaped before HTML rendering | PASS |
| 53 executable regression modules on source and built image | PASS |
| Python/JavaScript syntax and Docker Compose validation | PASS |
| Dependency layers reused from cache without reinstalling packages | PASS |
| Dashboard and agent rollout, diagnostics schema check, and health smoke test | PASS |

### Suggested commit

```text
feat: add ingestion dead-letter diagnostics
```

---

## M21.3 — Ingestion Health Metrics

**Status:** ✅ Complete

```text
events_received_total
events_normalized_total
events_rejected_total
events_deduplicated_total
event_processing_seconds
collector_last_seen_seconds
```

### Rules

- [x] No raw IP/user labels.
- [x] Keep label cardinality bounded.

### Local verification — 2026-08-26

| Check | Result |
|---|:---:|
| Received, normalized, rejected, and deduplicated totals persisted in SQLite | PASS |
| Cumulative processing duration and collector last-seen age recorded | PASS |
| Stable zero-value Windows metric series available before first batch | PASS |
| Prometheus totals emitted as counters; duration and age emitted as gauges | PASS |
| Metrics use only the bounded `WINDOWS_EVENT` source label | PASS |
| No collector ID, raw IP, or user label exposed | PASS |
| Metric storage failure does not block primary ingestion | PASS |
| Regression ingestion writes isolated from live telemetry state | PASS |
| 53 executable regression modules on source and built image | PASS |
| Python/JavaScript syntax and Docker Compose validation | PASS |
| Dependency layers reused from cache without reinstalling packages | PASS |
| Dashboard and agent rollout, six-metric smoke check, and health verification | PASS |

### Suggested commit

```text
feat: add telemetry ingestion health metrics
```

---

## M21.4 — Event Gap Detection

**Status:** ✅ Complete

### Tasks

- [x] Collector heartbeat state.
- [x] Stale threshold.
- [x] Distinguish offline / idle / endpoint unavailable.
- [x] Add diagnostic state.
- [x] Optional internal operational alert deliberately omitted; diagnostic-only mode is sufficient.
- [x] Avoid repeated alert storm by keeping health evaluation side-effect free.

### Local verification — 2026-08-26

| Check | Result |
|---|:---:|
| Authenticated empty heartbeats and legacy event batches accepted | PASS |
| Heartbeat state persisted with a 100-collector safety bound | PASS |
| Calibrated 60-second stale threshold exposed through environment configuration | PASS |
| Offline, idle, endpoint-unavailable, and healthy states determined deterministically | PASS |
| Public health exposes only aggregate state; admin diagnostics retain collector detail | PASS |
| Diagnostic-only evaluation produces no operational-alert storm or external call | PASS |
| 53 executable regression modules on source and built image | PASS |
| Python, JavaScript, PowerShell syntax and Docker Compose validation | PASS |
| Dependency layers reused from cache without reinstalling packages | PASS |
| Dashboard and agent rollout plus live health verification | PASS |

### Suggested commit

```text
feat: detect stale telemetry sources
```

---

## M21.5 — Release v0.7.0

**Status:** ✅ Complete

```text
v0.7.0 — Detection Validation & Data Quality
```

### Release Gate

- [x] Scenario validation exists.
- [x] Replay is deterministic.
- [x] Core detections have scenarios.
- [x] Scenario CI gate runs.
- [x] Detection feedback exists.
- [x] Rule quality metrics exist.
- [x] Exceptions and suppression are audited.
- [x] Event envelope is versioned.
- [x] Parser failures are observable.
- [x] Ingestion metrics exist.
- [x] Stale collectors are detectable.
- [x] Existing regressions still pass.
- [x] README/CHANGELOG/upgrade notes updated.
- [x] Clean snapshot passes.
- [x] Tag only after CI passes.

### Release verification — 2026-08-26

| Check | Result |
|---|:---:|
| Deterministic offline replay corpus: 18 scenarios and 14 rules | PASS |
| Feedback, rule quality, exception, suppression, and audit contracts | PASS |
| Versioned envelope, redacted failures, bounded metrics, and stale-collector diagnostics | PASS |
| 53 executable regression modules on source and release image | PASS |
| Python/JavaScript/PowerShell syntax and Docker Compose validation | PASS |
| README, CHANGELOG, release notes, history, upgrade notes, and latest-release links | PASS |
| Release artifact gate and clean staged snapshot | PASS |
| Tracked runtime-file and secret review | PASS |
| Release commit and annotated tag gated by GitHub Actions | PASS |

### Suggested commit

```text
docs: release v0.7.0
```

---

# M22 — Secure Deployment Profile

## M22.1 — Configuration Validator

**Status:** ✅ Complete

### Command

```text
python -m tools.validate_config
```

### Validate

- [x] Required secrets.
- [x] Secret minimum length.
- [x] Secure-cookie/TLS compatibility.
- [x] AI provider conflicts.
- [x] Retention values.
- [x] Response mode.
- [x] Webhook URL scheme.
- [x] Unsafe bind warnings.
- [x] Production debug mode forbidden.

### Local verification — 2026-08-27

| Check | Result |
|---|:---:|
| Development and production profiles with conditional required secrets | PASS |
| App-owned secret minimum lengths without secret-value diagnostics | PASS |
| Secure-cookie, public HTTPS URL, unsafe bind, and production debug checks | PASS |
| AI provider/fallback, retention, response mode, and webhook validation | PASS |
| `.env` loading with process-environment precedence | PASS |
| 54 executable regression modules in the existing image | PASS |
| Deterministic offline corpus: 18 scenarios and 14 rules | PASS |
| Python syntax and Docker Compose validation | PASS |

### Suggested commit

```text
feat: add deployment configuration validator
```

---

## M22.2 — HTTPS Reverse-proxy Profile

**Status:** ✅ Complete

### Architecture

```text
Browser → HTTPS Reverse Proxy → Dashboard
```

### Tasks

- [x] TLS termination.
- [x] HTTP → HTTPS redirect.
- [x] Trusted proxy handling.
- [x] Secure session cookie.
- [x] Forwarded-header validation.
- [x] Request/body limits.
- [x] Local development certificate path documented.

### Local verification — 2026-08-27

| Check | Result |
|---|:---:|
| Caddy configuration validation with local-CA TLS termination | PASS |
| HTTPS health and permanent HTTP-to-HTTPS redirect | PASS |
| Dashboard host port removed and proxy-only Compose network | PASS |
| One trusted proxy hop, allowlisted forwarded host, and spoofed-header replacement | PASS |
| Secure session-cookie configuration and 2 MiB proxy/application body limits | PASS |
| Local CA public-certificate path and trust boundary documented | PASS |
| 55 executable regression modules in the existing image | PASS |
| Deterministic offline corpus: 18 scenarios and 14 rules | PASS |
| Python syntax and base/HTTPS Docker Compose validation | PASS |

### Suggested commit

```text
feat: add HTTPS reverse-proxy deployment profile
```

---

## M22.3 — File-based Secret Support

**Status:** ✅ Complete

### Pattern

```text
*_FILE
```

Examples:

```text
OLLAMA_API_KEY_FILE
ABUSEIPDB_API_KEY_FILE
VIRUSTOTAL_API_KEY_FILE
DASHBOARD_SESSION_SECRET_FILE
```

### Tasks

- [x] File secret loader.
- [x] Conflict handling.
- [x] Never log secret contents.
- [x] Existing env behavior remains supported.

### Local verification — 2026-08-27

| Check | Result |
|---|:---:|
| Existing direct environment secrets remain unchanged | PASS |
| Generic `*_FILE` loading for all persistent application secrets | PASS |
| Direct/file conflicts fail without secret value or path disclosure | PASS |
| Missing, empty, multi-line, non-UTF-8, and oversized files fail closed | PASS |
| Production configuration validator resolves file-backed session/metrics secrets | PASS |
| Native Docker Compose secret mount into `/run/secrets` | PASS |
| 56 executable regression modules in the existing image | PASS |
| Deterministic offline corpus: 18 scenarios and 14 rules | PASS |
| Python syntax and base/HTTPS Docker Compose validation | PASS |

### Suggested commit

```text
feat: support file-based application secrets
```

---

## M22.4 — Security Regression Pack

**Status:** ✅ Complete

### Cases

- [x] RBAC denial.
- [x] CSRF denial.
- [x] Session revocation.
- [x] Login throttling.
- [x] XSS escaping.
- [x] Oversized request rejection.
- [x] Collector-secret rejection.
- [x] Secure-cookie behavior under HTTPS.

### Local verification — 2026-08-27

| Check | Result |
|---|:---:|
| Eight deployment security boundary cases | PASS |
| Authentication, authorization, CSRF, session, and request limits | PASS |
| Collector authentication and HTTPS secure-cookie behavior | PASS |
| 57 executable regression modules in the existing image | PASS |
| Deterministic offline corpus: 18 scenarios and 14 rules | PASS |
| Python syntax and Docker Compose validation | PASS |

### Suggested commit

```text
test: add deployment security regression pack
```

---

# M23 — Software Supply-chain Security

## M23.1 — Dependency Reproducibility

**Status:** ✅ Complete

- [x] Define pinning policy.
- [x] Pin production dependencies reproducibly.
- [x] Keep security update workflow.
- [x] Avoid unnecessary dependencies.
- [x] CI validates consistency.

### Local verification — 2026-08-27

| Check | Result |
|---|:---:|
| 12 direct and 25 transitive production dependencies exactly pinned | PASS |
| Single-install Docker and CI path with official PyTorch CPU index | PASS |
| Native `pip check`, exact-pin CI gate, and weekly grouped Dependabot updates | PASS |
| No new Python dependency or local package installation | PASS |
| 57 executable regression modules in the existing image | PASS |
| Deterministic offline corpus: 18 scenarios and 14 rules | PASS |
| Python syntax and Docker Compose validation | PASS |

### Suggested commit

```text
build: tighten dependency reproducibility
```

---

## M23.2 — SBOM Generation

**Status:** ✅ Complete

### Output

```text
CycloneDX or SPDX
```

### Tasks

- [x] Generate in CI.
- [x] Include Python dependencies.
- [x] Include container packages where feasible.
- [x] Attach to releases.

### Local verification — 2026-08-28

| Check | Result |
|---|:---:|
| Existing Docker SBOM plugin generated valid SPDX JSON from `mini-siem:latest` | PASS |
| 55 Python/PyPI and 166 Debian package references discovered | PASS |
| CI generation runs only after HTTP/HTTPS image smoke checks | PASS |
| SPDX version plus Python and Debian package inventories gated with `jq` | PASS |
| Workflow artifact retained for 14 days | PASS |
| Published releases attach the verified artifact only after the release gate | PASS |
| Anchore action pinned to `v0.24.0`; no project dependency or local image build | PASS |
| 57 executable regression modules in the existing image | PASS |
| Deterministic offline corpus: 18 scenarios and 14 rules | PASS |
| Python syntax, workflow YAML, and Docker Compose validation | PASS |

### Suggested commit

```text
ci: generate release software bill of materials
```

---

## M23.3 — Container Vulnerability Scan

**Status:** ✅ Complete

- [x] Scan built image.
- [x] Define severity gate.
- [x] Document exceptions.
- [x] Save artifact on failure.

### Local verification — 2026-08-28

| Check | Result |
|---|:---:|
| Scan reuses the verified SPDX inventory from the smoke-tested image | PASS |
| HIGH and CRITICAL findings fail the build, including findings without fixes | PASS |
| Empty deny-by-default Grype exception list | PASS |
| Exact vulnerability/package scope, owner, reason, issue, and 30-day expiry policy | PASS |
| Failed JSON report retained for 7 days | PASS |
| Anchore scan action pinned to `v7.4.0` | PASS |
| Workflow and Grype YAML parsing | PASS |
| 57 executable regression modules in the existing image | PASS |
| Deterministic offline corpus: 18 scenarios and 14 rules | PASS |
| No local scanner/database download, dependency installation, or image build | PASS |

### Suggested commit

```text
ci: scan Mini-SIEM container image
```

---

## M23.4 — Release Checksums

**Status:** ✅ Complete

- [x] Generate SHA-256 checksums.
- [x] Verify before publication.
- [x] Document verification.

### Local verification — 2026-08-28

| Check | Result |
|---|:---:|
| Native SHA-256 manifest generation for the verified SPDX SBOM | PASS |
| Immediate checksum verification before CI artifact upload | PASS |
| Checksum verification repeated before GitHub Release publication | PASS |
| SBOM and checksum retained and published together | PASS |
| Operator verification command documented in README and release checklist | PASS |
| Workflow YAML parsing and checksum round-trip | PASS |
| No new dependency, local package installation, or image build | PASS |

### Suggested commit

```text
build: add release artifact checksums
```

---

# M24 — Database Migration & Disaster Recovery

## M24.1 — Schema Migration Table

**Status:** ✅ Complete

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

- [x] Baseline current schema.
- [x] Deterministic order.
- [x] Idempotent detection.
- [x] Failed migration not marked complete.

### Local verification — 2026-08-28

| Check | Result |
|---|:---:|
| Baseline v1 records the v0.7.0 schema name, UTC application time, and SHA-256 checksum | PASS |
| Integer primary key and ordered history query provide deterministic migration order | PASS |
| Repeated initialization retains exactly one baseline row | PASS |
| Changed baseline checksum is rejected | PASS |
| Invalid DDL rolls back both partial schema and migration history | PASS |
| 58 executable regression modules in the existing image | PASS |
| Python syntax validation | PASS |
| No new dependency, local package installation, or image build | PASS |

### Suggested commit

```text
refactor: add database schema migration tracking
```

---

## M24.2 — Migration Runner

**Status:** ✅ Complete

```text
python -m tools.migrate_db
```

### Tasks

- [x] Backup first.
- [x] Validate source version.
- [x] Ordered migrations.
- [x] Transaction where possible.
- [x] Integrity check.
- [x] `--dry-run`.
- [x] Print current/target version.

### Local verification — 2026-08-28

| Check | Result |
|---|:---:|
| Pending migration creates and validates a SQLite backup before database writes | PASS |
| Unknown versions, history gaps, and changed checksums are rejected | PASS |
| Central version-ordered registry with one transaction per migration | PASS |
| Post-migration and read-only preflight integrity checks | PASS |
| Dry-run reports source/target/pending state without changing the database | PASS |
| Current database CLI preflight reported source 1, target 1, and integrity `ok` | PASS |
| Already-current database is a no-op without a redundant backup | PASS |
| Migration operation documented in README and retention/backup runbook | PASS |
| 59 executable regression modules in the existing image | PASS |
| Python syntax validation | PASS |
| No new dependency, local package installation, or image build | PASS |

### Suggested commit

```text
feat: add versioned database migration runner
```

---

## M24.3 — Automated Restore Drill

**Status:** ✅ Complete

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

- [x] alerts
- [x] incidents
- [x] assets
- [x] external case IDs
- [x] schema version
- [x] audit-related state as applicable

### Local verification — 2026-08-29

| Check | Result |
|---|:---:|
| Deterministic sample alert, incident, asset, external case, note, and audit state | PASS |
| Integrity-checked SQLite backup created before damage | PASS |
| Working database and WAL/SHM state replaced with a damaged copy | PASS |
| Backup restore returned `PRAGMA integrity_check` result `ok` | PASS |
| Alert payload, incident workflow, asset, external case ID, and analyst note preserved | PASS |
| Schema migration version restored to v1 | PASS |
| External audit file remained unchanged and its hash chain stayed valid | PASS |
| Drill isolated entirely in a temporary directory and documented in the runbook | PASS |
| 60 executable regression modules in the existing image | PASS |
| Python syntax validation | PASS |
| No new dependency, local package installation, or image build | PASS |

### Suggested commit

```text
test: automate database backup and restore drill
```

---

## M24.4 — Historical Upgrade Matrix

**Status:** ✅ Complete

### Minimum

```text
v0.6.0 data → current
v0.7.0 data → current
fresh database → current
```

### Rules

- [x] Extend for every new release.
- [x] Upgrade failure blocks release.

### Local verification — 2026-08-29

| Check | Result |
|---|---|
| Frozen representative v0.6.0 fixture → current | PASS |
| Frozen representative v0.7.0 fixture → current | PASS |
| Frozen representative v0.8.0 fixture → current | PASS |
| Fresh database → current | PASS |
| Required migration backups preserve their source schema version | PASS |
| Historical alert, incident, asset, and external-case state preserved | PASS |
| v0.7.0 detection feedback and ingestion-health state preserved | PASS |
| `CHANGELOG.md`-derived fixture coverage rejects an unrepresented release | PASS |
| Baseline failure propagates to the release gate | PASS |
| 61 executable regression modules | PASS |
| Python syntax validation | PASS |
| No new dependency, local package installation, or image build | PASS |

### Suggested commit

```text
ci: validate historical database upgrades
```

---

## M24.5 — Release v0.8.0

**Status:** ✅ Complete

```text
v0.8.0 — Platform & Supply-chain Hardening
```

### Release Gate

- [x] Config validator.
- [x] HTTPS profile.
- [x] File secrets.
- [x] Security regression pack.
- [x] Reproducible dependencies.
- [x] SBOM.
- [x] Container scan.
- [x] Checksums.
- [x] Migration framework.
- [x] Restore drill.
- [x] Historical upgrade tests.
- [x] Docs synchronized.
- [x] Tag only after CI passes.

### Release verification — 2026-08-29

| Check | Result |
|---|:---:|
| Configuration validator, HTTPS profile, file secrets, and security regression pack | PASS |
| Exact dependency pins and installed-package consistency | PASS |
| SPDX SBOM, HIGH/CRITICAL container gate, and SHA-256 publication path | PASS |
| Versioned migrations, backup-first runner, restore drill, and v0.6–v0.8 upgrade matrix | PASS |
| 61 executable regression modules in the existing image | PASS |
| Base/HTTPS Compose and release-artifact consistency | PASS |
| README, CHANGELOG, release notes, history, upgrade notes, and latest-release links | PASS |
| No tracked runtime files or active Gitleaks exceptions | PASS |
| Release commit and annotated tag gated by GitHub Actions | PASS |

### Suggested commit

```text
docs: release v0.8.0
```

---

# M25 — Load Testing & Backpressure

## M25.1 — Synthetic Telemetry Load Generator

**Status:** ✅ Complete

### Modes

```text
steady
burst
mixed-source
windows-heavy
authentication-heavy
```

### Safety

- [x] Local by default.
- [x] Generate telemetry, not exploit traffic.
- [x] AI/TI disabled.

### Local verification — 2026-08-29

| Check | Result |
|---|:---:|
| `steady`, `burst`, `mixed-source`, `windows-heavy`, and `authentication-heavy` modes | PASS |
| Deterministic output for fixed mode, count, duration, seed, and start time | PASS |
| Versioned HIDS, Windows, NIDS, and honeypot event envelopes | PASS |
| TEST-NET addresses and synthetic records only; no packet or API transmission | PASS |
| AI and external threat-intelligence providers are never initialized | PASS |
| Bounded count/duration validation and exclusive local-file creation | PASS |
| CLI JSONL generation and existing-file protection | PASS |
| 62 executable regression modules | PASS |
| Python syntax validation | PASS |
| No new dependency, package installation, or image build | PASS |

### Suggested commit

```text
test: add synthetic telemetry load generator
```

---

## M25.2 — Throughput Benchmark

**Status:** ✅ Complete

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

### Local verification — 2026-08-29

| Profile | Achieved events/s | Normalize p95 ms | Detect p95 ms | SQLite p95 ms | CPU % | Peak Python memory bytes |
|---|---:|---:|---:|---:|---:|---:|
| 10 events/s | 9.998 | 0.342 | 12.449 | 2.888 | 3.106 | 166972 |
| 50 events/s | 49.994 | 0.304 | 0.306 | 4.524 | 11.262 | 146890 |
| 100 events/s | 99.988 | 0.286 | 0.323 | 3.367 | 19.159 | 286880 |
| 250 events/s | 249.981 | 0.197 | 0.275 | 2.869 | 39.042 | 373507 |
| Burst (250 events) | 346.414 | 0.155 | 0.075 | 2.933 | 50.736 | 299202 |

| Additional check | Result |
|---|:---:|
| Dashboard `/health`, 10 samples, p95 35.913 ms, HTTP 200 | PASS |
| Temporary SQLite rows equal processed events for every profile | PASS |
| Queue depth, dropped events, and rejected events remained zero | PASS |
| AI/TI disabled; benchmark database isolated and removed automatically | PASS |
| Local-only API allowlist rejects remote hosts and embedded credentials | PASS |
| Total attempted events bounded to 100,000 | PASS |
| 63 executable regression modules | PASS |
| Python syntax validation | PASS |
| No new dependency, package installation, or image build | PASS |

### Suggested commit

```text
perf: add single-node throughput benchmark
```

---

## M25.3 — Bounded Ingestion Queue

**Status:** ✅ Complete

### Tasks

- [x] Bounded queue.
- [x] Queue-depth metric.
- [x] Explicit overload policy.
- [x] Prefer backpressure where supported.
- [x] Never silently drop.
- [x] Count rejected/dropped events.
- [x] Health reports saturation.

### Overload policy

```text
HIDS/Windows durable files → bounded shared queue → single ingestion worker
queue full               → block producer (backpressure)
worker failure           → log and increment dropped_total
queue stopped            → reject explicitly and increment rejected_total
```

### Local verification — 2026-08-29

| Check | Result |
|---|:---:|
| Shared HIDS and Windows ingestion through one bounded stdlib queue | PASS |
| Forced capacity-one saturation blocks the producer and preserves FIFO order | PASS |
| Queue depth, capacity, backpressure, rejected, and dropped metrics | PASS |
| Processing failure is logged and counted; stopped queue rejects explicitly | PASS |
| Agent heartbeat, system status, and public health expose saturation | PASS |
| Queue drains before worker shutdown | PASS |
| 64 executable regression modules | PASS |
| Python syntax and Docker Compose validation | PASS |
| No new dependency or runtime external service call | PASS |

### Suggested commit

```text
feat: add bounded ingestion backpressure
```

---

## M25.4 — Graceful Degradation

**Status:** ✅ Complete

### States

```text
healthy
degraded
saturated
```

### Rules

- [x] Core detection/persistence has priority.
- [x] AI/TI can degrade first.
- [x] Notifications remain bounded.
- [x] Health exposes overload.

### Overload behavior

| State | Core persistence | AI/external TI | Notifications | Public health |
|---|---|---|---|---|
| `healthy` | Active | Active and single-flight | Serialized | HTTP 200 |
| `degraded` | Active | New work skipped and recorded | Serialized | HTTP 200, degraded |
| `saturated` | Active | New work skipped and recorded | Network call skipped and audited | HTTP 503, saturated |

### Local verification — 2026-08-29

| Check | Result |
|---|:---:|
| Queue transitions at healthy, 80% degraded, and full saturated thresholds | PASS |
| Core alert persisted before optional notification handling | PASS |
| AI and external TI skip new work with explicit overload evidence | PASS |
| TI provider async submission is single-flight with explicit busy result | PASS |
| Saturated notification makes no network call and writes `SKIPPED_OVERLOAD` audit | PASS |
| Optional ELK forwarding occurs after primary persistence | PASS |
| Agent, NIDS, and honeypot use the shared overload state | PASS |
| Public health reports degraded and returns HTTP 503 for saturated | PASS |
| 65 executable regression modules | PASS |
| Python syntax and Docker Compose validation | PASS |
| No new dependency or runtime external service call | PASS |

### Suggested commit

```text
feat: add graceful overload degradation
```

---

# M26 — Storage & Query Performance

## M26.1 — SQLite Query Plan Audit

**Status:** ✅ Complete

### Audit

- [x] alert list
- [x] time range
- [x] incident status
- [x] rule coverage
- [x] KPIs
- [x] analytics
- [x] assets
- [x] feedback/rule quality

### Tasks

- [x] Use `EXPLAIN QUERY PLAN`.
- [x] Document scans.
- [x] Add justified indexes only.
- [x] Measure before/after.

Detailed plans and rejected index candidates are recorded in
[SQLite Query Plan Audit](SQLITE_QUERY_PLAN_AUDIT.md).

### Local verification — 2026-08-29

| Check | Result |
|---|:---:|
| Alert ordering uses `idx_alerts_timestamp_id` without a temporary order tree | PASS |
| ISO time range uses a bounded index search instead of an ordered scan | PASS |
| Severity filter and ordering use `idx_alerts_severity_timestamp_id` | PASS |
| False-positive trend uses `idx_incident_events_type_timestamp` | PASS |
| Rule-quality latest feedback uses scoped indexed lookup instead of a full feedback scan | PASS |
| Incident-status and asset-enabled candidate indexes rejected after slower measurements | PASS |
| Backup-first schema migration v2 and historical upgrade matrix | PASS |
| 66 executable regression modules | PASS |
| Python syntax and Docker Compose validation | PASS |
| No temporary `check_m*.py`, new dependency, or external service call | PASS |

### Suggested commit

```text
perf: optimize SQLite query indexes
```

---

## M26.2 — Bounded Batched Writes

**Status:** ✅ Complete

Only implement if benchmarks show transaction overhead is significant.

- [x] Safe batch size.
- [x] Maximum flush delay.
- [x] Flush on shutdown.
- [x] Preserve required ordering.
- [x] Benchmark improvement.

Detailed measurements and runtime safety boundaries are recorded in
[SQLite Write Batching](SQLITE_WRITE_BATCHING.md).

### Local verification — 2026-08-29

| Check | Result |
|---|:---:|
| Batch size 10 and maximum 50 ms flush delay | PASS |
| FIFO ordering, bounded queue, read barrier, and shutdown drain | PASS |
| Async batching restricted to the durable JSON dual-write profile | PASS |
| SQLite telemetry/incident transaction time reduced by 88.9%/87.8% | PASS |
| End-to-end dual-write time reduced by 44.4%/36.7% | PASS |
| Focused storage, suppression, retention, and migration regressions | PASS |
| 67 executable regression modules | PASS |
| No temporary `check_m*.py`, new dependency, or external service call | PASS |

### Suggested commit

```text
perf: add bounded telemetry write batching
```

---

## M26.3 — Large-history Benchmark

**Status:** ✅ Complete

### Dataset sizes

```text
10k alerts
50k alerts
100k alerts
```

### Verify

- [x] alert API
- [x] search
- [x] analytics
- [x] rule coverage
- [x] incident workspace
- [x] report generation
- [x] retention

Detailed method, timings, and the measured analytics ceiling are recorded in
[Large-history Benchmark](LARGE_HISTORY_BENCHMARK.md).

### Local verification — 2026-08-31

| Check | Result |
|---|:---:|
| Incremental isolated 10k, 50k, and 100k alert corpora | PASS |
| Alert API storage/serialization, filtered search, and rule coverage | PASS |
| SOC KPI/analytics and open-incident workspace | PASS |
| Deterministic incident PDF generation | PASS |
| Retention on disposable copies archives eligible alerts and preserves open incidents | PASS |
| 100k API/search paths remain below 50 ms; analytics ceiling measured at 2.73 s | PASS |
| Input bounds and exclusive JSON report output | PASS |
| 68 executable regression modules | PASS |
| No live data, provider/network call, new dependency, or retained benchmark corpus | PASS |

### Suggested commit

```text
perf: add large-history query benchmark
```

---

# M27 — Collector Reliability & Offline Recovery

## M27.1 — Collector Identity

**Status:** ✅ Complete

Fields:

```text
collector_id
collector_version
hostname
source_type
last_seen
```

- [x] Stable collector ID.
- [x] Server tracks last seen.
- [x] Version visible.
- [x] Duplicate ID warning.

The Windows collector persists a generated ID beside its cursor and buffer state. The
existing heartbeat inventory now exposes version, hostname, source type, and last seen;
reusing an ID from a different hostname raises a persistent warning without replacing the
original host identity.

### Local verification — 2026-08-31

| Check | Result |
|---|:---:|
| Stable generated collector ID persisted atomically | PASS |
| Version, hostname, source type, and last seen returned by API and diagnostics | PASS |
| Duplicate ID from a different hostname preserves identity and raises warning | PASS |
| Legacy collector payload remains accepted | PASS |
| Backup-first migration v3 and historical upgrade matrix | PASS |
| PowerShell syntax and Python compile checks | PASS |
| 68 executable regression modules | PASS |
| No temporary `check_m*.py`, new dependency, or external service call | PASS |

### Suggested commit

```text
feat: add collector identity and version tracking
```

---

## M27.2 — Buffer Diagnostics

**Status:** ✅ Complete

### Metrics

```text
buffered_events
buffer_oldest_age
retry_attempts
delivery_failures
last_successful_delivery
```

### Tasks

- [x] Bound buffer size.
- [x] Oldest-first replay.
- [x] Delete only after acknowledgement.
- [x] Corrupt entry handled safely.
- [x] Admin diagnostics.

The collector caps each cross-channel buffer at the configured batch size (maximum 500),
orders events by observation time, and preserves corrupt buffers for inspection. Heartbeats
report current buffer age plus cumulative retry and delivery-failure counters; the server
records successful delivery time and exposes all metrics through admin health diagnostics.

### Local verification — 2026-08-31

| Check | Result |
|---|:---:|
| Buffer bounded to 500 events and ordered oldest-first across channels | PASS |
| Buffered file retained on failure and deleted only after `response.ok` | PASS |
| Corrupt buffer quarantined without deletion or network dependency | PASS |
| Retry, delivery-failure, buffer count/age, and last-success metrics | PASS |
| Strict metric bounds at the collector API trust boundary | PASS |
| Admin health API and workspace summary expose buffer diagnostics | PASS |
| Backup-first migration v4 and historical upgrade matrix | PASS |
| Windows PowerShell 5.1 behavioral mock and syntax checks | PASS |
| 68 executable regression modules | PASS |
| No temporary `check_m*.py`, new dependency, or external service call | PASS |

### Suggested commit

```text
feat: add collector buffer diagnostics
```

---

## M27.3 — Collector Protocol Version

**Status:** ✅ Complete

- [x] Collector reports protocol/schema version.
- [x] Unsupported future version rejected clearly.
- [x] Supported legacy version accepted.
- [x] Compatibility matrix documented.

The collector payload now carries `protocol_version` (`tools/windows_event_collector.ps1`
sends `1`). The server treats a missing field as legacy version `0`, accepts versions
`0` and `1`, and rejects future versions with HTTP 400 and an explicit error. The
successful response echoes the negotiated version. The compatibility matrix lives in
[Collector Ingestion Protocol](COLLECTOR_PROTOCOL.md).

### Local verification — 2026-08-31

| Check | Result |
|---|:---:|
| Missing `protocol_version` negotiated as legacy `0` and accepted | PASS |
| Version `1` accepted with negotiated version echoed in the response | PASS |
| Future version `2` rejected with HTTP 400 and explicit unsupported-version error | PASS |
| Non-integer, boolean, float, negative, and null versions rejected with HTTP 400 | PASS |
| Versioned batch ingests, deduplicates, and heartbeats unchanged for v0/v1 payloads | PASS |
| Windows collector sends `protocol_version = 1` in every batch | PASS |
| Protocol gate placed before ingestion/heartbeat side effects | PASS |
| [docs/COLLECTOR_PROTOCOL.md](COLLECTOR_PROTOCOL.md) compatibility matrix | PASS |
| 69 executable regression modules on source and built image | PASS |
| Python syntax, PowerShell parse, and Docker Compose validation | PASS |
| Dashboard/agent rollout and health smoke test (HTTP 200) | PASS |
| No schema migration, new dependency, or external service call | PASS |

### Suggested commit

```text
feat: version collector ingestion protocol
```

---

## M27.4 — Outage Recovery Scenario

**Status:** ✅ Complete

```text
collector running
→ server unavailable
→ events buffered
→ server returns
→ replay
→ no duplicates
→ cursor advances
```

### Scenario

A Windows collector sends event A while the server is healthy. The server then
goes unavailable — the collector reports `endpoint_available: false`. On recovery,
the collector replays event B from its local buffer. The server accepts it as a
new event (no duplicate). A replay of event B is correctly deduplicated. A new
event C is accepted and all three events are persisted without silent loss. The
collector heartbeat state remains consistent across the outage window.

### Definition of Done

- [x] No silent loss.
- [x] Buffer drains.
- [x] Dedup behaves correctly.
- [x] Test is offline/deterministic.

### Local verification — 2026-08-31

| Check | Result |
|---|:---:|
| Step 1 — healthy server accepts event A as new | PASS |
| Step 2 — unavailable server responds with `endpoint_unavailable` | PASS |
| Step 3 — recovery replays event B as new (no duplicate) | PASS |
| Step 4 — replay of event B correctly deduplicated | PASS |
| Step 5 — new event C accepted, cursor advances | PASS |
| Step 6 — all three events persisted, all unique event IDs | PASS |
| Step 7 — collector heartbeat shows consistent state | PASS |
| 70 executable regression modules | PASS |
| Python syntax and Docker Compose validation | PASS |
| No external service call, provider init, or live data write | PASS |

### Suggested commit

```text
test: add collector outage recovery scenario
```

---

## M27.5 — Release v0.9.0

**Status:** ✅ Complete

```text
v0.9.0 — Performance & Operational Resilience
```

### Release Gate

- [x] Load generator.
- [x] Throughput baseline.
- [x] Explicit overload behavior.
- [x] Queue health.
- [x] Query plan audit.
- [x] Large-history benchmark.
- [x] Collector identity.
- [x] Buffer diagnostics.
- [x] Protocol version.
- [x] Outage recovery regression.
- [x] Migration regression.
- [ ] Tag after CI.

### Release verification — 2026-08-31

| Check | Result |
|---|:---:|
| Synthetic load generator, 5 modes, deterministic local-only output | PASS |
| Throughput benchmark at 10/50/100/250 events/s plus burst | PASS |
| Bounded queue, explicit overload policy, and queue-health saturation | PASS |
| Graceful degradation healthy/degraded/saturated states | PASS |
| SQLite query-plan audit and bounded batched writes | PASS |
| Large-history benchmark across 10k/50k/100k alert corpora | PASS |
| Collector identity, buffer diagnostics, and protocol version | PASS |
| Offline outage recovery regression with no silent loss | PASS |
| Historical upgrade matrix extended to v0.9.0 | PASS |
| 70 executable regression modules on source and built image | PASS |
| Python/JavaScript syntax, Compose, replay corpus, and coverage checks | PASS |
| Runtime agent, dashboard, database, and public `/health` healthy | PASS |
| Release commit and annotated tag gated by GitHub Actions | PASS |

### Suggested commit

```text
docs: release v0.9.0
```

---

# M28 — API & Schema Versioning

## M28.1 — REST API v1

**Status:** ✅ Complete

Example:

```text
/api/v1/alerts
/api/v1/incidents/...
/api/v1/assets
/api/v1/system/status
```

### Tasks

- [x] Inventory current endpoints.
- [x] Classify public/internal.
- [x] Define v1 contracts.
- [x] Add versioned routes.
- [x] Temporary compatibility aliases.
- [x] Deprecation documentation.

The supported REST surface now has `/api/v1/...` routes backed by the same
handlers, authorization checks, CSRF protection, limits, and response bodies
as the existing endpoints. Unversioned routes remain temporary aliases and
advertise their successor through deprecation headers. Dashboard-internal,
collector, health, and metrics endpoints remain outside the v1 contract.
The complete inventory and compatibility policy are documented in
[REST API v1](REST_API_V1.md).

### Local verification — 2026-09-01

| Check | Result |
|---|:---:|
| Explicit supported endpoint inventory and public/internal classification | PASS |
| v1 route patterns and HTTP methods match their compatibility aliases | PASS |
| v1 and alias routes share the same handlers and authorization boundaries | PASS |
| Authenticated v1 and alias alert responses are identical | PASS |
| Anonymous v1 and alias alert requests both return HTTP 401 | PASS |
| Legacy aliases advertise v1 successors; v1 responses are not deprecated | PASS |
| Collector and dashboard-internal endpoints are excluded from v1 | PASS |
| 71 executable regression modules | PASS |
| Python syntax and Docker Compose validation | PASS |
| No schema migration, dependency, Ollama, or external provider call | PASS |

### Suggested commit

```text
refactor: introduce versioned REST API v1
```

---

## M28.2 — Alert Schema Version

**Status:** ✅ Complete

- [x] Add `alert_schema_version`.
- [x] Document field semantics.
- [x] Document nullable fields.
- [x] Document enums.
- [x] Define compatibility policy.
- [x] Normalize legacy alerts through adapter.

New and updated alerts persist `alert_schema_version: 1`. The shared adapter
normalizes pre-versioned JSONL and SQLite payloads in memory, generates stable
UUID5 identifiers when needed, maps legacy `INFO` severity to `LOW`, and
rejects invalid or unsupported future versions. Field, nullability, enum,
extension, and compatibility rules are documented in
[Alert Schema v1](ALERT_SCHEMA.md).

### Local verification — 2026-09-01

| Check | Result |
|---|:---:|
| New alerts and repository writes carry `alert_schema_version: 1` | PASS |
| Missing/zero legacy versions normalize to v1 on JSONL and SQLite reads | PASS |
| Missing legacy IDs receive deterministic UUID5 identifiers | PASS |
| Legacy `INFO` severity normalizes to `LOW` | PASS |
| Boolean, string, null, negative, and future versions rejected clearly | PASS |
| Lifecycle arrays and nullable/enum semantics documented | PASS |
| v1 and compatibility API routes expose the same normalized payload | PASS |
| JSON-to-SQLite migration remains idempotent | PASS |
| 72 executable regression modules | PASS |
| Python syntax validation | PASS |
| No database migration, dependency, Ollama, or external provider call | PASS |

### Suggested commit

```text
refactor: version persisted alert schema
```

---

## M28.3 — Machine-readable API Contract

**Status:** ✅ Complete

Use OpenAPI or JSON Schema.

- [x] Core endpoints.
- [x] Auth requirements.
- [x] Error model.
- [x] Pagination.
- [x] Request limits.
- [x] CI schema validation.

The supported REST v1 surface is now described by an OpenAPI 3.1 document.
It records every registered v1 path and method, dashboard session and CSRF
requirements, minimum roles, reusable JSON errors, alert pagination, field
bounds, and enforced request-body limits. The existing CI regression loop
loads the contract, resolves every local reference, and rejects route,
security, pagination, or limit drift without adding another dependency.

### Local verification — 2026-09-01

| Check | Result |
|---|:---:|
| OpenAPI paths and methods exactly match all registered Flask v1 routes | PASS |
| Session, CSRF, and minimum-role requirements present on every operation | PASS |
| Reusable JSON error schema and internal reference resolution | PASS |
| Alert pagination defaults, bounds, and response schema | PASS |
| Runtime request-body, field, list, and KPI range limits represented | PASS |
| Existing CI `tests/test_*.py` loop discovers the contract regression | PASS |
| M28.1–M28.3 focused regression modules | PASS |
| 73 executable regression modules | PASS |
| No dependency, database migration, Ollama, or external provider call | PASS |

### Suggested commit

```text
docs: add machine-readable API contract
```

---

## M28.4 — API Compatibility Regression

**Status:** ✅ Complete

- [x] Required response fields.
- [x] Error status behavior.
- [x] Permission boundaries.
- [x] Pagination.
- [x] Legacy alert normalization.

The compatibility suite exercises the published v1 API through Flask with a
temporary SQLite repository. It derives required alert fields from OpenAPI,
checks 400/401/403/404/413 behavior, verifies viewer/analyst/admin boundaries,
tests multi-page search metadata, and confirms pre-versioned SQLite alerts are
normalized before being returned. The shared adapter now supplies legacy
event-window defaults, and the OpenAPI `external_cases` type matches the
provider-keyed object returned by the API.

### Local verification — 2026-09-01

| Check | Result |
|---|:---:|
| Current and legacy API responses contain every OpenAPI-required alert field | PASS |
| JSON error model and HTTP 400/401/403/404/413 behavior | PASS |
| Viewer, analyst, and admin permission boundaries | PASS |
| Page size, total, page number, total pages, and non-overlapping pages | PASS |
| Legacy severity, schema version, event count, and event-window normalization | PASS |
| OpenAPI `external_cases` object agrees with runtime payloads | PASS |
| M28.2–M28.4 focused regression modules | PASS |
| 74 executable regression modules | PASS |
| Python syntax validation | PASS |
| No dependency, database migration, Ollama, or external provider call | PASS |

### Suggested commit

```text
test: add API compatibility regression suite
```

---

# M29 — Operator Experience & Accessibility

## M29.1 — Environment Doctor

**Status:** ✅ Complete

```text
python -m tools.doctor
```

### Check

- [x] required directories
- [x] writable data path
- [x] DB integrity
- [x] admin user existence
- [x] config validity
- [x] optional integrations
- [x] collector config
- [x] AI readiness without consuming an analysis request

### Local verification — 2026-09-01

| Check | Result |
|---|:---:|
| Required directories (BASE, RULES, SIGMA) checked for existence and readability | PASS |
| Writable data, backup, and archive paths | PASS |
| SQLite database read-only integrity check | PASS |
| Dashboard users file with admin role enumeration and no-admin warning | PASS |
| Configuration validation reusing `tools.validate_config` | PASS |
| Case export, TheHive/Jira, and threat intelligence providers | PASS |
| Windows collector secret and stale threshold | PASS |
| Ollama Cloud/local primary and fallback without making an analysis call | PASS |
| Aggregated PASS/FAIL output with exit code | PASS |
| Python syntax validation | PASS |
| No database migration, dependency, or external service call | PASS |

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
M29.2 — Unified Diagnostics View
```

M29.2 links health, ingestion failures, rule-load failures, provider state,
and collector state into a single diagnostics view.

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

- [x] `v0.7.0` ships with detection replay, tuning, and ingestion quality.
- [x] `v0.8.0` ships with secure deployment, supply-chain checks, and tested migration/recovery.
- [x] `v0.9.0` ships with measured performance and collector recovery.
- [x] API v1 exists.
- [x] Alert schema is explicitly versioned.
- [x] Historical upgrade tests pass.
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
M29.2 — Unified Diagnostics View
```

M29.1 ships a read-only environment doctor for operator preflight checks.
M29.2 links health, ingestion failures, rule-load failures, provider state,
and collector state into a single diagnostics view.
