# Mini-SIEM Blue Team — Continuation Roadmap

> **Repository:** `zenniskayy2k4/Mini-SIEM`
> **Continuation from:** `v0.3.0` / roadmap M0–M9
> **Created:** 2026-08-15
> **Environment:** Windows + Docker Desktop
> **Storage:** SQLite primary + JSON dual-write/fallback
> **AI:** Ollama Cloud (`gemma4:cloud`)
> **Recommended next release:** `v0.4.0`

---

## 1. Điểm xuất phát

Roadmap M0–M9 đã hoàn tất. Baseline hiện tại đã có:

- Docker deployment.
- HIDS / NIDS / Honeypot pipeline.
- Standardized alert contract.
- Correlation, deduplication và cooldown.
- Ollama Cloud AI triage.
- AI recommendation tách khỏi system severity.
- Incident lifecycle, assignment, notes và timeline.
- SQLite primary storage.
- YAML detection rules và detection coverage.
- Safe response simulation / manual approval.
- Webhook notifications.
- Windows Event Log / Sysmon ingestion và detection.
- Dashboard authentication / RBAC / CSRF.
- Immutable analyst audit log.
- Health / diagnostics.
- Retention / backup / restore.
- End-to-end demo và release `v0.3.0`.

Từ đây, hướng phát triển chuyển từ **SOC foundation** sang:

```text
Detection Engineering
+ Threat Intelligence
+ Asset-aware Risk
+ SOC Analytics
+ Resilient AI
```

---

## 2. Release strategy

### v0.4.0 — Detection Engineering & Threat Intelligence

```text
M10 — Engineering Quality & CI
M11 — Sigma Rule Support
M12 — Threat Intelligence Layer
```

### v0.5.0 — Asset Context & SOC Analytics

```text
M13 — Asset Inventory & Risk Context
M14 — Reporting & Observability
M15 — AI Resilience & Provider Abstraction
```

### v0.6.0 — Integrations & Workspace Scaling

```text
M16 — External Case Management Integration
M17 — Role-specific SOC Workspace
```

### Future / Optional

```text
M18 — Multi-tenant Architecture
```

---

## 3. Quy tắc triển khai

1. Không làm nhiều milestone lớn song song.
2. Mỗi batch có commit riêng.
3. Không đổi schema ổn định nếu không có migration path.
4. External API phải có timeout, bounded retry, rate limit, cache và failure isolation.
5. Threat intelligence và AI không tự quyết định incident outcome.
6. Detection content phải giữ provenance/source.
7. Không commit API key/token.
8. Feature mới phải có regression hoặc smoke verification.
9. Response mode mặc định tiếp tục là `simulation`.
10. Kết thúc mỗi milestone bằng documentation sync.

---

## 4. Tracking overview

| Milestone | Nội dung | Release | Status |
|---|---|---|---|
| M10 | Engineering Quality & CI | v0.4.0 | ✅ Complete |
| M11 | Sigma Rule Support | v0.4.0 | ✅ Complete |
| M12 | Threat Intelligence Layer | v0.4.0 | ✅ Complete |
| M13 | Asset Inventory & Risk Context | v0.5.0 | 🟠 In Progress |
| M14 | Reporting & Observability | v0.5.0 | ⬜ |
| M15 | AI Resilience & Provider Abstraction | v0.5.0 | ⬜ |
| M16 | External Case Management | v0.6.0 | ⬜ |
| M17 | Role-specific SOC Workspace | v0.6.0 | ⬜ |
| M18 | Multi-tenant Architecture | Future | ⬜ |

---

# M10 — Engineering Quality & CI

## M10.1 — GitHub Actions baseline CI

**Status:** ✅ Complete — local and GitHub verification passed

### Goal

Tự động hóa các regression/smoke checks hiện đang chạy thủ công.

### File dự kiến

```text
.github/workflows/ci.yml
```

### Tasks

- [x] Trigger trên `push` và `pull_request`.
- [x] Checkout repository.
- [x] Setup Python.
- [x] Install dependencies.
- [x] Python syntax checks.
- [x] JavaScript syntax check.
- [x] `docker compose --profile train config --quiet`.
- [x] Chạy executable regression modules hiện có.
- [x] Fail workflow khi regression fail.
- [x] Không yêu cầu Ollama API key thật.
- [x] Không gửi webhook thật.
- [x] Không chạy response action thật.

### Minimum flow

```text
Checkout
→ Setup
→ Syntax checks
→ Compose validation
→ Regression
→ PASS / FAIL
```

### Definition of Done

- [x] Commit hợp lệ → CI green.
- [x] Syntax lỗi → CI red.
- [x] Regression lỗi → CI red.
- [x] Không lộ secret trong log.
- [x] README có CI badge.

### Local verification — 2026-08-15

```text
node --check static/js/app.js                                      PASS
docker compose --profile train config --quiet                     PASS
python -m compileall -q config src tools tests dashboard.py main.py PASS
14 executable regression modules                                  PASS
```

GitHub Actions [run 31880377953](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/31880377953) passed for commit `308d82b`.

### Commit

```text
ci: add baseline GitHub Actions workflow
```

---

## M10.2 — Docker service smoke CI

**Status:** ✅ Complete — local and GitHub Docker smoke passed

### Tasks

- [x] Build Docker services.
- [x] Start stack với CI-safe config.
- [x] Wait `/health`.
- [x] Verify dashboard startup.
- [x] Verify SQLite initialization.
- [x] Stop stack trong cleanup.
- [x] Upload logs khi job fail.
- [x] Không gọi Ollama Cloud mặc định.

### DoD

- [x] Docker build pass trên GitHub runner.
- [x] `/health` trả expected result.
- [x] Cleanup luôn chạy.
- [x] Failure có logs để debug.

### Local verification — 2026-08-16

```text
GitHub Actions YAML/contract validation                     PASS
docker compose config --quiet                              PASS
docker compose build                                       PASS
GET /health (agent/dashboard/database/status = healthy)    PASS
GET /login (HTTP 200)                                      PASS
SQLite PRAGMA quick_check + alerts table                   PASS
Failure log artifact + always-run cleanup                  CONFIGURED
```

GitHub Actions [run 31925484215](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/31925484215) passed for commit `be8b718`.

### Commit

```text
ci: add Docker service smoke checks
```

---

## M10.3 — Security checks

**Status:** ✅ Complete — local and GitHub security checks passed

### Tasks

- [x] Secret scanning.
- [x] Python dependency vulnerability scan.
- [x] Kiểm tra `.env` không bị track.
- [x] Kiểm tra runtime data không bị track.
- [x] Có allowlist rõ cho false positive.

### Tool candidates

```text
gitleaks
pip-audit
```

### DoD

- [x] Dummy secret bị phát hiện.
- [x] Repo sạch pass.
- [x] Dependency issue được report rõ.

### Local verification — 2026-08-16

```text
GitHub Actions YAML/security contract validation            PASS
Gitleaks full Git history (40 commits)                      PASS — no leaks
Gitleaks documented dummy-secret fixture                    PASS — detected
pip-audit requirements.txt                                  PASS — no known vulnerabilities
.env, data/** and logs/** tracking guard                    PASS
.gitleaksignore reviewed-fingerprint policy                 PASS — 0 exceptions
```

GitHub Actions [run 31925849592](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/31925849592) passed for commit `e3a7c47`.

### Commit

```text
ci: add secret and dependency security checks
```

---

## M10.4 — Release gate

**Status:** ✅ Complete — local and GitHub release gate passed

### Tasks

- [x] Document release checklist.
- [x] CI phải green trước release.
- [x] Verify changelog.
- [x] Verify Compose config.
- [x] Verify clean-clone path.
- [x] Verify no tracked secrets.

### Local verification — 2026-08-16

```text
GitHub Actions YAML/release-gate contract validation         PASS
M10.1 baseline GitHub run                                   PASS
M10.2 Docker smoke GitHub run                               PASS
M10.3 security GitHub run                                   PASS
CHANGELOG semantic-version/date format                      PASS
Clean-clone Compose and tracked-runtime checks              PASS
```

GitHub Actions [run 31926399008](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/31926399008) passed for commit `1953a63`.

### Commit

```text
docs: add CI-backed release gate
```

---

# M11 — Sigma Rule Support

## M11.1 — Sigma parser và metadata

**Status:** ✅ Complete — GitHub Actions passed

### Architecture

```text
Sigma YAML
→ Sigma Loader
→ Validator
→ Mini-SIEM Adapter
→ Existing Rule Engine
```

### File dự kiến

```text
src/sigma/
├── __init__.py
├── loader.py
├── schema.py
└── adapter.py

config/sigma/
```

### Metadata giữ lại

- title
- id
- status
- description
- author
- references
- tags
- logsource
- level
- detection
- source filename

### Tasks

- [x] Load Sigma YAML.
- [x] Validate structure.
- [x] Invalid rule bị skip riêng.
- [x] Giữ Sigma UUID.
- [x] Map Sigma level → severity.
- [x] Map ATT&CK tags.
- [x] Alert lưu `rule_source: sigma`.
- [x] Alert lưu `sigma_rule_id`.
- [x] Unsupported rule không được enable silently.

### DoD

- [x] Sample Sigma rule load được.
- [x] Invalid rule không crash agent.
- [x] Native rules không bị ảnh hưởng.
- [x] Duplicate Sigma ID bị phát hiện.

### Local verification — 2026-08-16

```text
Sigma loader/schema/adapter syntax                           PASS
Sample metadata, severity and ATT&CK mapping                 PASS
Invalid rule isolation                                      PASS
Duplicate Sigma UUID detection                              PASS
Native/Sigma alert provenance contract                      PASS
15 executable regression modules                            PASS
```

GitHub Actions [run 31926912963](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/31926912963) passed for commit `b29c39e`.

### Commit

```text
feat: add Sigma rule parser and metadata adapter
```

---

## M11.2 — Sigma selection mapping

**Status:** ✅ Complete — GitHub Actions passed

### Supported subset phase 1

```text
keywords
equals
contains
startswith
endswith
contains|all
selection
selection and filter
selection1 or selection2
```

### Tasks

- [x] Define supported operators.
- [x] Define unsupported operators.
- [x] Map field aliases.
- [x] Normalize Windows fields.
- [x] Preserve raw Sigma detection.
- [x] Unsupported syntax → skip + reason.

### DoD

- [x] Process creation rule match được Sysmon normalized event.
- [x] PowerShell rule hoạt động.
- [x] Exclusion/filter hoạt động.
- [x] Unsupported syntax không tạo false match.

### Local verification — 2026-08-16

```text
Sigma loader and selection mapping regression                PASS
Windows/native rule compatibility                            PASS
16 executable regression modules                            PASS
Docker Compose validation                                    PASS
```

Unsupported fields, modifiers, wildcards and complex conditions remain disabled with an explicit `skip_reason`.

GitHub Actions [run 31928551948](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/31928551948) passed for commit `3e60298`.

### Commit

```text
feat: translate supported Sigma selections into Mini-SIEM rules
```

---

## M11.3 — Sigma lifecycle

**Status:** ✅ Complete — GitHub Actions passed

### Tasks

- [x] Enable/disable Sigma rule.
- [x] Admin UI hiển thị source Native/Sigma.
- [x] Validation status.
- [x] Last loaded time.
- [x] Hit count.
- [x] Never-hit state.
- [x] Audit enable/disable.

### Local verification — 2026-08-16

```text
Admin lifecycle API and CSRF/RBAC path                       PASS
Persistent enable/disable override and agent reload          PASS
Source, validation, loaded time, hit/never-hit metadata      PASS
Immutable enable/disable audit events                        PASS
JavaScript syntax and Python compile                         PASS
17 executable regression modules                            PASS
Docker Compose validation                                    PASS
```

Sigma YAML remains read-only; runtime overrides are stored atomically under `data/`.

GitHub Actions [run 31929684141](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/31929684141) passed for commit `31c942d`.

### Commit

```text
feat: manage Sigma rule lifecycle and coverage
```

---

## M11.4 — Sigma regression corpus

**Status:** ✅ Complete — GitHub Actions passed

### Fixtures

- [x] Windows process creation.
- [x] PowerShell.
- [x] Account creation.
- [x] Positive cases.
- [x] Negative cases.
- [x] Unsupported syntax case.

### DoD

- [x] Positive matches đúng rule.
- [x] Negative không match.
- [x] Regression chạy trong CI.
- [x] Không cần network.

### Local verification — 2026-08-18

```text
Sysmon process creation positive/negative corpus             PASS
PowerShell positive/negative corpus                          PASS
Security Event 4720 account creation corpus                  PASS
Unsupported Sigma syntax remains disabled                   PASS
Sigma UUID/provenance on positive alerts                     PASS
18 executable regression modules                            PASS
Docker Compose validation                                    PASS
```

The corpus is entirely repository-local and is discovered by the existing CI test glob.

GitHub Actions [run 32099750118](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/32099750118) passed for commit `6dc1fc3`.

### Commit

```text
test: add Sigma detection regression corpus
```

---

## M11.5 — Sigma documentation

**Status:** ✅ Complete — GitHub Actions passed

- [x] Supported subset.
- [x] Unsupported syntax.
- [x] Import path.
- [x] Provenance.
- [x] Example.
- [x] Debug procedure.
- [x] Known limitations.

### Local verification — 2026-08-18

```text
Supported operators, conditions and field aliases documented PASS
Unsupported behavior and limitations documented              PASS
Import/lifecycle/provenance paths matched implementation      PASS
Sample and repository-local links verified                   PASS
Documented Sigma loader command                              PASS
Documented offline corpus command                            PASS
Docker Compose validation                                    PASS
```

Runtime code is unchanged.

GitHub Actions [run 32100301022](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/32100301022) passed for commit `f25d087`.

### Commit

```text
docs: document Sigma rule support
```

---

# M12 — Threat Intelligence Layer

## M12.1 — ThreatIntelProvider abstraction

**Status:** ✅ Complete — local and GitHub verification passed

### Architecture

```text
Alert IOC
→ IOC Normalizer
→ Cache
→ Provider
→ Normalized Result
→ Dashboard / AI Context
```

### File triển khai

```text
src/threat_intel/
├── __init__.py
├── base.py
└── service.py
```

### IOC types

```text
ip
domain
url
sha256
md5
```

### Tasks

- [x] Provider interface.
- [x] IOC normalization.
- [x] TTL cache.
- [x] Rate limiter.
- [x] Timeout.
- [x] Bounded retry.
- [x] Structured error state.
- [x] Lookup không block alert persistence.
- [x] Không persist API secret.

### DoD

- [x] Dummy provider hoạt động.
- [x] Cache hit không lookup lại.
- [x] Provider timeout không crash pipeline.
- [x] Result có timestamp/provenance.

### Local verification — 2026-08-18

```text
IP/domain/URL/SHA-256/MD5 normalization                       PASS
Dummy provider and normalized result contract                PASS
TTL cache hit and provider rate limiter                      PASS
Bounded retry and enforced timeout/error state               PASS
Async lookup returns before alert persistence path continues PASS
No network, file persistence or API-secret handling          PASS
19 executable regression modules                            PASS
Docker Compose validation                                    PASS
```

The phase-1 abstraction uses stdlib only and one bounded provider worker. External providers and alert enrichment are deferred to later M12 batches.

GitHub Actions [run 32100953262](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/32100953262) passed for commit `97a5fe7`.

### Commit

```text
refactor: add threat intelligence provider abstraction
```

---

## M12.2 — GeoIP enrichment

**Status:** ✅ Complete — local and GitHub verification passed

### Fields

```json
{
  "country": null,
  "country_code": null,
  "city": null,
  "asn": null,
  "organization": null,
  "is_private": false
}
```

### Tasks

- [x] Detect private/loopback/link-local.
- [x] Không lookup private IP ngoài Internet.
- [x] Cache result.
- [x] Dashboard hiển thị GeoIP.
- [x] Không coi foreign country = malicious.

### Local verification — 2026-08-18

```text
Private/loopback/link-local classification without HTTP call PASS
Public IPv4 normalization and live HTTPS provider smoke      PASS
TTL cache hit avoids repeated provider lookup                PASS
Alert persisted before asynchronous GeoIP enrichment         PASS
Dashboard renders normalized GeoIP context safely            PASS
Foreign location does not change severity or disposition     PASS
20 executable regression modules                             PASS
Python/JavaScript syntax and Docker Compose validation        PASS
```

The agent shares one bounded GeoIP service across HIDS, Windows, NIDS and honeypot sensors. Public lookups use the configurable keyless HTTPS endpoint; local and special-use addresses never leave the host.

GitHub Actions [run 32102158042](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/32102158042) passed for commit `9e3b04b`.

### Commit

```text
feat: add GeoIP context enrichment
```

---

## M12.3 — AbuseIPDB provider

**Status:** ✅ Complete — local and GitHub verification passed

### Normalize

- abuse confidence
- total reports
- last reported
- ISP/domain
- usage type

### Tasks

- [x] Key qua `.env`.
- [x] Missing key → provider disabled.
- [x] Không lookup private IP.
- [x] Rate limit.
- [x] Cache.
- [x] Không gửi raw log.
- [x] AI chỉ nhận normalized summary.
- [x] API 429 handled.

### Local verification — 2026-08-18

```text
Missing API key disables provider construction               PASS
Private/loopback/link-local lookup skips HTTP                PASS
GET /api/v2/check request uses API key header only           PASS
Normalized confidence/reports/time/ISP/domain/usage fields   PASS
TTL cache and bounded shared provider worker                 PASS
HTTP 429 structured rate_limited state without retry         PASS
Raw provider payload/API key excluded from persisted result  PASS
AI receives normalized allowlisted threat-intel summary      PASS
21 executable regression modules                             PASS
Python/JavaScript syntax and Docker Compose validation        PASS
```

No live AbuseIPDB request was made because the repository intentionally contains no API key; the HTTP contract is covered with an offline fake response.

GitHub Actions [run 32102809495](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/32102809495) passed for commit `9205005`.

### Commit

```text
feat: add AbuseIPDB threat intelligence enrichment
```

---

## M12.4 — VirusTotal metadata provider

**Status:** ✅ Complete — local and GitHub verification passed

### Safety rule

```text
Query metadata/hash only.
Never auto-upload internal files.
```

### Tasks

- [x] Hash lookup trước.
- [x] Domain/IP optional — intentionally disabled in hash-first scope.
- [x] Respect API quota.
- [x] Cache hash result.
- [x] Normalize malicious/suspicious counts.
- [x] Không có auto-upload code path.

### Local verification — 2026-08-18

```text
Missing API key disables provider construction               PASS
SHA-256 preferred over MD5; other IOC types rejected         PASS
GET /api/v3/files/{hash} uses x-apikey header only           PASS
Public quota limited to 4 requests/minute with 24-hour cache PASS
Malicious/suspicious and aggregate metadata normalized       PASS
HTTP 404 not-found and 429 rate-limit behavior bounded       PASS
Raw engine response/API key excluded from persisted result   PASS
No upload, rescan or download code path                      PASS
22 executable regression modules                             PASS
Python/JavaScript syntax and Docker Compose validation        PASS
```

No live VirusTotal request was made because the repository intentionally contains no API key; the metadata-only HTTP contract is covered with an offline fake response.

GitHub Actions [run 32103490075](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/32103490075) passed for commit `2f9f6c6`.

### Commit

```text
feat: add VirusTotal IOC metadata enrichment
```

---

## M12.5 — Threat Intel dashboard panel

**Status:** ✅ Complete — local and GitHub verification passed

### UI

```text
Threat Intelligence
├── IOC
├── Type
├── GeoIP
├── Reputation
├── Provider
├── Confidence / reports
├── Lookup time
└── Cache status
```

### Tasks

- [x] Pending/loading.
- [x] Provider unavailable.
- [x] Không render raw provider JSON.
- [x] Không tự đổi system severity.
- [x] Phân biệt observed evidence và third-party intelligence.

### Local verification — 2026-08-18

```text
Pending/loading state persisted before provider lookup       PASS
Missing provider rendered as unavailable                     PASS
IOC/type and GeoIP/reputation/provider cards                 PASS
Confidence/reports, lookup time and cache state              PASS
Observed evidence separated from third-party intelligence   PASS
Raw provider JSON excluded from rendering                   PASS
System severity remains unchanged                           PASS
Legacy GeoIP alert display compatibility                    PASS
23 executable regression modules                            PASS
Python/JavaScript syntax and Docker Compose validation       PASS
```

The panel reuses the existing normalized alert payload and search API; it adds no endpoint, frontend framework or raw-provider rendering path.

GitHub Actions [run 32118998036](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/32118998036) passed for commit `daeea28`. Follow-up login CSRF hotfix [run 32119994389](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/32119994389) passed for commit `fd98961`.

### Commit

```text
feat: show threat intelligence context on dashboard
```

---

## M12.6 — STIX/TAXII

**Status:** ✅ Complete — local and GitHub verification passed

### Scope ban đầu

- STIX Indicator.
- IPv4.
- Domain.
- Hash.
- Source/feed metadata.
- `valid_from`.
- `valid_until`.
- confidence/labels.

### Tasks

- [x] Offline STIX bundle import.
- [x] TAXII collection optional.
- [x] Scheduled/manual pull.
- [x] Deduplicate indicators.
- [x] Expire indicators.
- [x] Match alert IOC.
- [x] Preserve feed source.

### DoD

- [x] Sample STIX bundle import được.
- [x] IOC match hiển thị source.
- [x] Expired indicator không active.
- [x] Feed failure không crash detection.

### Local verification — 2026-08-18

```text
Offline STIX 2.1 bundle import for IPv4/domain/hash           PASS
Normalized JSON persistence and reload                       PASS
Same-feed IOC deduplication                                   PASS
valid_until expiry excludes inactive indicators              PASS
Alert IOC match preserves source/confidence/labels            PASS
Dashboard STIX/TAXII source card uses normalized fields       PASS
Optional bounded TAXII collection pull with bearer header     PASS
Manual import and scheduled safe refresh paths                PASS
Feed failure leaves detection/store operational               PASS
24 executable regression modules                              PASS
Python/JavaScript syntax and Docker Compose validation         PASS
```

The phase-1 parser accepts exact STIX equality patterns for IPv4, domain, SHA-256 and MD5. TAXII uses the configured collection objects URL, a 5 MiB response cap and at most 10 pages; no additional package or database is required.

GitHub Actions [run 32121071532](https://github.com/zenniskayy2k4/Mini-SIEM/actions/runs/32121071532) passed for commit `26fdb7c`.

### Commit

```text
feat: add STIX and TAXII threat intelligence ingestion
```

---

## M12.7 — Release v0.4.0

**Status:** ✅ Complete — responsive stabilization CI passed and annotated tag published

### Checklist

- [x] M10 complete.
- [x] M11 complete.
- [x] M12 feature batches complete.
- [x] CI green through M12.6.
- [x] README sync.
- [x] `.env.example` sync.
- [x] CHANGELOG update.
- [x] Clean-clone verification.
- [x] No secret.
- [x] Pre-tag responsive dashboard stabilization passes 25/25 local regression modules.
- [x] Responsive stabilization CI green (`32123583216`).
- [x] Annotated tag `v0.4.0` published from verified commit `1c41462`.

### Release theme

```text
v0.4.0 — Detection Engineering & Threat Intelligence
```

### Local verification — 2026-08-18

```text
README, CHANGELOG and v0.4.0 release checklist synchronized  PASS
.env.example covers all optional Threat Intelligence config PASS
Release artifact and local Markdown link validation          PASS
24 executable regression modules in release snapshot         PASS
Clean-clone Docker Compose validation                         PASS
Clean-clone 24/24 regression using existing image             PASS
No tracked .env/data/logs runtime files                       PASS
Release diff secret-pattern review                            PASS
No active Gitleaks exception                                  PASS
```

The local clean-clone verification reused the existing image to avoid a duplicate multi-gigabyte build; GitHub Actions performs the independent clean build and Docker smoke after the release commit is pushed.

### Pre-tag stabilization — responsive dashboard

- [x] Desktop, tablet, and mobile navigation/layout breakpoints.
- [x] Horizontal overflow for dense alert, coverage, rule, and log tables.
- [x] Responsive filters, settings, graph, and login surfaces.
- [x] No API, schema, business-logic, or dependency changes.
- [x] 25/25 executable regression modules pass in the existing image without rebuilding.

GitHub Actions run `32123583216` passed baseline, Docker smoke, security, and release gate. Annotated tag `v0.4.0` points to verified commit `1c41462`.

### Commit

```text
docs: prepare v0.4.0 release
```

---

# M13 — Asset Inventory & Risk Context

## M13.1 — Asset schema

**Status:** ✅ Complete — local and GitHub Actions verification passed (`32126105310`)

### Schema

```json
{
  "asset_id": "AST-...",
  "hostname": "...",
  "ip_addresses": [],
  "os": "...",
  "owner": "...",
  "department": "...",
  "environment": "dev|test|prod",
  "criticality": "LOW|MEDIUM|HIGH|CRITICAL",
  "tags": [],
  "enabled": true
}
```

### Tasks

- [x] SQLite asset and normalized IP tables.
- [x] CRUD repository.
- [x] Stable immutable `AST-<UUID>` ID.
- [x] Case-insensitive hostname and canonical IPv4/IPv6 lookup.
- [x] Application and SQLite duplicate detection.
- [x] Immutable create/update/delete audit events.

### Local verification — 2026-08-18

```text
M13.1 focused asset inventory regression        PASS
Python syntax                                    PASS
26 executable regression modules                PASS
Docker Compose validation                        PASS
No image rebuild                                 PASS
```

### Commit

```text
feat: add asset inventory data model
```

---

## M13.2 — Asset management API/UI

**Status:** ✅ Complete — local verification and commit CI passed (`32127236447`)

- [x] Admin-only CRUD page and API.
- [x] Search plus environment, criticality, and enabled-state filters.
- [x] Criticality editing.
- [x] Owner/team editing.
- [x] Tags editing.
- [x] Bounded payload, field, IP, and tag validation.
- [x] Existing session RBAC and CSRF enforcement.
- [x] Immutable create/update/delete audit events.

### Local verification — 2026-08-18

```text
M13.2 focused API/UI regression                PASS
M13.1 asset repository regression              PASS
Authentication and responsive contracts        PASS
Python and JavaScript syntax                    PASS
27 executable regression modules               PASS
Docker Compose validation                       PASS
No image rebuild                                PASS
```

### Commit

```text
feat: add asset inventory management
```

---

## M13.3 — Alert-to-asset enrichment

**Status:** ✅ Complete — local verification passed; commit CI pending

- [x] Match by IP/hostname.
- [x] Add `asset_id`.
- [x] Unknown asset vẫn hợp lệ.
- [x] Dashboard link alert → asset.
- [x] Không duplicate full asset object nếu không cần.

### Local verification — 2026-08-18

```text
M13.3 focused enrichment/UI regression          PASS
M13.1/M13.2 asset regressions                   PASS
Python and JavaScript syntax                    PASS
28 executable regression modules               PASS
Docker Compose validation                       PASS
No image rebuild                                PASS
```

### Commit

```text
feat: enrich alerts with asset context
```

---

## M13.4 — Explainable risk scoring

**Status:** ⬜

### Inputs

- detection severity
- asset criticality
- threat confidence
- TI reputation
- correlation count
- human-review recommendation

### Output

```json
{
  "risk_score": 0,
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "risk_factors": []
}
```

### Rules

- [ ] Deterministic.
- [ ] Explainable.
- [ ] LLM không trực tiếp đặt risk score.
- [ ] Missing TI không làm score lỗi.
- [ ] Configurable weights.

### Commit

```text
feat: add explainable asset-aware risk scoring
```

---

# M14 — Reporting & Observability

## M14.1 — Prometheus metrics

**Status:** ⬜

### Metrics

- alerts by severity
- incidents by status
- detection hits
- AI success/failure
- TI success/failure
- notification success/failure
- response simulations
- heartbeat age
- queue/backlog

### Tasks

- [ ] `/metrics`.
- [ ] Không expose secrets.
- [ ] Không dùng raw IP/user làm high-cardinality labels.
- [ ] Document access/auth.

### Commit

```text
feat: expose Prometheus operational metrics
```

---

## M14.2 — SOC KPIs

**Status:** ⬜

### KPIs

```text
MTTD
MTTA
MTTR
Open incidents
Resolved incidents
False-positive rate
Alerts per rule
Human-review rate
AI enrichment success rate
```

### Tasks

- [ ] Define timestamps.
- [ ] Time range filtering.
- [ ] SQLite query hiệu quả.
- [ ] Không hiển thị KPI nếu data chưa đủ.

### Commit

```text
feat: add SOC KPI analytics
```

---

## M14.3 — Analytics dashboard

**Status:** ⬜

- [ ] Summary cards.
- [ ] Alert trend.
- [ ] Incident distribution.
- [ ] Top rules.
- [ ] Top MITRE techniques.
- [ ] False positive trend.
- [ ] Time range selector.

### Commit

```text
feat: add SOC analytics dashboard
```

---

## M14.4 — PDF incident report

**Status:** ⬜

### Sections

```text
Incident Metadata
Executive Summary
Detection Evidence
MITRE Mapping
AI Analysis
Threat Intelligence
Asset Context
Analyst Timeline
Response Actions
Resolution
Appendix
```

### Rules

- [ ] Không include secrets.
- [ ] AI text không được trình bày như observed fact.
- [ ] Tách evidence / AI / TI.
- [ ] UTC timestamps.
- [ ] Report reproducible từ stored incident.

### Commit

```text
feat: generate incident PDF reports
```

---

# M15 — AI Resilience & Provider Abstraction

## M15.1 — AI provider interface

**Status:** ⬜

### Interface

```python
class AIProvider:
    name: str

    def available(self) -> bool:
        ...

    def analyze(self, messages, schema):
        ...
```

### Tasks

- [ ] Ollama Cloud adapter.
- [ ] `AIAnalyst` chỉ phụ thuộc interface.
- [ ] Provider config validation.
- [ ] Persist provider actually used.
- [ ] Existing AI result contract không đổi.

### Commit

```text
refactor: add pluggable AI provider interface
```

---

## M15.2 — Local Ollama optional provider

**Status:** ⬜

### Tasks

- [ ] `ollama_cloud`.
- [ ] `ollama_local`.
- [ ] Local base URL configurable.
- [ ] Local model configurable.
- [ ] Không auto-download model.
- [ ] Health detection.
- [ ] Resource requirements documented.

### Commit

```text
feat: add optional local Ollama provider
```

---

## M15.3 — Bounded provider fallback

**Status:** ⬜

### Example

```text
Ollama Cloud
→ local Ollama
→ AI unavailable
```

### Rules

- [ ] Bounded failover.
- [ ] Không retry storm.
- [ ] Persist provider used.
- [ ] Diagnostics hiển thị fallback.
- [ ] Không gửi incident lặp vô hạn.

### Commit

```text
feat: add bounded AI provider fallback
```

---

## M15.4 — AI evaluation corpus

**Status:** ⬜

### Cases

- single failed login
- confirmed brute force
- benign admin action
- suspicious PowerShell
- malicious TI hit
- unknown IOC
- missing fields
- prompt-like text trong raw log

### Evaluate

- [ ] JSON valid.
- [ ] Evidence grounding.
- [ ] No unsupported compromise claim.
- [ ] MITRE consistency.
- [ ] No secret leakage.
- [ ] Severity recommendation semantics stable.

### Commit

```text
test: add AI triage evaluation corpus
```

---

## M15.5 — Release v0.5.0

**Status:** ⬜

```text
v0.5.0 — Asset-aware SOC Analytics & Resilient AI
```

- [ ] M13 complete.
- [ ] M14 complete.
- [ ] M15 complete.
- [ ] CI green.
- [ ] Docs sync.
- [x] Clean clone pass.
- [ ] Upgrade notes.
- [ ] Tag `v0.5.0`.

---

# M16 — External Case Management

## M16.1 — Connector abstraction

**Status:** ⬜

```python
class CaseConnector:
    def create_case(self, incident):
        ...

    def update_case(self, external_id, incident):
        ...
```

### Tasks

- [ ] Disabled by default.
- [ ] External ID.
- [ ] Idempotency.
- [ ] Timeout/retry.
- [ ] Manual analyst export.
- [ ] Audit export.

### Commit

```text
refactor: add external case connector interface
```

---

## M16.2 — TheHive

**Status:** ⬜

- [ ] Manual create case.
- [ ] Map severity/risk.
- [ ] Include observables.
- [ ] Store case ID.
- [ ] Prevent duplicate export.
- [ ] No secrets.

### Commit

```text
feat: add TheHive case export integration
```

---

## M16.3 — Jira

**Status:** ⬜

- [ ] Manual create issue.
- [ ] Config project/key.
- [ ] Map title/description/labels.
- [ ] Store issue key.
- [ ] Prevent duplicate export.
- [ ] Audit.

### Commit

```text
feat: add Jira incident export integration
```

---

# M17 — Role-specific SOC Workspace

## M17.1 — Viewer workspace

**Status:** ⬜

- Read-only alerts.
- SOC metrics.
- Rule coverage.
- Incident status.
- No mutation controls.

## M17.2 — Analyst workspace

**Status:** ⬜

- Human-review queue.
- Assigned incidents.
- Investigation actions.
- Notes.
- Response proposals.
- TI/AI context.

## M17.3 — Admin workspace

**Status:** ⬜

- User management.
- Runtime settings.
- Rule/Sigma management.
- Health.
- Integrations.
- Audit verification.
- Retention/backup status.

### Commit

```text
feat: add role-specific SOC workspaces
```

---

## M17.4 — Release v0.6.0

**Status:** ⬜

```text
v0.6.0 — SOC Integrations & Role-focused Workspaces
```

---

# M18 — Multi-tenant Architecture

**Status:** Optional / Do not start yet

Chỉ thực hiện khi có use case thật.

Multi-tenant ảnh hưởng:

- database schema
- authentication
- RBAC
- alerts
- incidents
- assets
- rules
- integrations
- audit
- retention
- API authorization

### Preconditions

- [ ] Có requirement nhiều organization/team.
- [ ] v0.6.0 ổn định.
- [ ] Migration strategy rõ.
- [ ] Tenant isolation model rõ.
- [ ] Security review khả thi.

---

# 5. Thứ tự thực hiện

```text
M10.1 GitHub Actions
→ M10.2 Docker smoke CI
→ M10.3 Security checks
→ M10.4 Release gate

→ M11 Sigma
→ M12 Threat Intelligence
→ v0.4.0

→ M13 Asset/Risk
→ M14 Analytics/Reporting
→ M15 AI Resilience
→ v0.5.0

→ M16 External Cases
→ M17 Role Workspaces
→ v0.6.0

→ M18 Multi-tenant only if needed
```

---

# 6. Batch cần làm ngay

```text
M13.4 — Explainable risk scoring (not started; begin only in the next requested batch)
```

M13.3 hoàn tất ở local. Không bắt đầu M13.4 trong cùng batch.

### Success condition

```text
git push
→ GitHub Actions tự chạy
→ baseline (including Sigma regression)/docker-smoke/security/release-gate
→ PASS hoặc FAIL rõ ràng
```

---

# 7. Template tracking

```markdown
## Batch Mxx.x — <Tên>

**Status:** 🟠 In Progress
**Started:** YYYY-MM-DD
**Completed:**
**Commit:**

### Goal

...

### Files changed

- `...`

### Tasks

- [ ] ...

### Verification

- [ ] Python syntax pass.
- [ ] JavaScript syntax pass nếu có.
- [ ] Regression pass.
- [ ] Docker Compose validation pass.
- [ ] Relevant service smoke pass.
- [ ] API/UI smoke pass nếu có.
- [ ] No secret committed.
- [ ] Working tree clean after commit.

### Evidence

```text
<command output / test summary>
```

### Known issues

- ...

### Follow-up

- ...
```

---

# 8. Checklist trước commit

```powershell
git status --short
git diff
git check-ignore .env
```

- [ ] `.env` không bị track.
- [ ] Không có API key/token.
- [ ] Không commit runtime `data/`.
- [ ] Không commit `logs/`.
- [ ] Không commit temp fixtures ngoài chủ đích.
- [ ] Regression liên quan pass.
- [ ] Docs update nếu contract thay đổi.
- [ ] Một commit chỉ bao gồm một batch logic.

---

# 9. Checklist trước release

- [ ] CI green.
- [ ] Working tree clean.
- [ ] Version đúng.
- [ ] CHANGELOG updated.
- [ ] README synchronized.
- [ ] `.env.example` synchronized.
- [ ] Clean-clone verification.
- [ ] Docker Compose validation.
- [ ] Health smoke.
- [ ] Regression pass.
- [ ] No tracked secrets.
- [ ] Migration/upgrade notes nếu cần.
- [ ] Known limitations documented.
- [ ] Annotated tag đúng commit.

---

# 10. Definition of Done — v0.4.0

- [x] GitHub Actions bảo vệ baseline.
- [x] Docker smoke CI hoạt động.
- [x] Secret/dependency checks hoạt động.
- [x] Sigma parser giữ provenance.
- [x] Supported Sigma subset được document.
- [x] Sigma positive/negative regression chạy trong CI.
- [x] Native rules vẫn hoạt động.
- [x] Threat Intel abstraction hoàn tất.
- [x] GeoIP hoạt động.
- [x] AbuseIPDB optional provider hoạt động.
- [x] VirusTotal metadata lookup optional hoạt động.
- [x] Không có VirusTotal auto-upload.
- [x] TI cache/rate-limit/provenance hoạt động.
- [x] TI failure không block detection.
- [x] TI dashboard panel hoạt động.
- [x] STIX offline import hoạt động.
- [x] TAXII optional path hoạt động hoặc có documented blocker.
- [x] README / `.env.example` sync.
- [x] Clean clone pass.
- [x] Tag `v0.4.0`.

---

# 11. Definition of Done — v0.5.0

- [ ] Asset inventory hoạt động.
- [ ] Alert map được asset.
- [ ] Risk score deterministic/explainable.
- [ ] Prometheus metrics hoạt động.
- [ ] SOC KPI analytics hoạt động.
- [ ] PDF incident report hoạt động.
- [ ] AI provider abstraction hoàn tất.
- [ ] Local Ollama optional.
- [ ] Bounded fallback hoạt động.
- [ ] AI evaluation corpus pass.
- [ ] Tag `v0.5.0`.

---

# 12. Không nên làm ngay

```text
Multi-tenant
Kubernetes
Elasticsearch/OpenSearch
Kafka
Full SOAR engine
Automatic production response
Custom EDR
Large distributed collector
```

Các mục này tăng complexity mạnh nhưng chưa mang lại ROI tốt cho mục tiêu Blue Team portfolio hiện tại.

---

# 13. Decision log

| Date | Decision | Reason |
|---|---|---|
| 2026-08-15 | `v0.3.0` là stable baseline | M0–M9 hoàn tất |
| 2026-08-15 | Roadmap mới bắt đầu từ M10 | Không kéo dài roadmap cũ |
| 2026-08-15 | CI trước Sigma/TI | Bảo vệ baseline |
| 2026-08-15 | Sigma hỗ trợ theo subset | Tránh implement toàn bộ spec ngay |
| 2026-08-15 | TI dùng provider abstraction | Tránh coupling provider |
| 2026-08-15 | Không auto-upload VirusTotal | Tránh rò rỉ dữ liệu |
| 2026-08-18 | GeoIP chỉ là context, chỉ lookup IP global | Không suy diễn quốc gia là malicious và không gửi địa chỉ local ra ngoài |
| 2026-08-18 | AbuseIPDB chỉ dùng check endpoint và normalized summary | Không gửi raw log hoặc provider payload sang API/AI |
| 2026-08-18 | VirusTotal chỉ lookup hash metadata | Không có upload, rescan hoặc download code path |
| 2026-08-18 | TI dashboard chỉ render normalized allowlist | Tách observed IOC khỏi third-party context và không đổi severity |
| 2026-08-18 | STIX phase 1 chỉ hỗ trợ exact equality IPv4/domain/hash | Giữ parser explainable; TAXII pull bị giới hạn size/page và feed failure không chặn detection |
| 2026-08-18 | Tag release chỉ tạo sau release-commit CI xanh | Bảo đảm annotated tag trỏ đúng commit đã qua release gate |
| 2026-08-15 | Risk tách khỏi severity | Detection semantics rõ ràng |
| 2026-08-15 | LLM không đặt risk score trực tiếp | Risk phải explainable |
| 2026-08-15 | Multi-tenant deferred | Complexity cao, chưa cần |

---

# 14. Current next action

```text
START HERE:
M13.4 — Explainable risk scoring (not started)
```

M13.3 đã hoàn tất local. Xác minh commit CI trước, sau đó bắt đầu M13.4 ở batch kế tiếp khi người dùng yêu cầu tiếp tục.
