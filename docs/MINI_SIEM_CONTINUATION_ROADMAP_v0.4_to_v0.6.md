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
| M11 | Sigma Rule Support | v0.4.0 | 🟠 In Progress |
| M12 | Threat Intelligence Layer | v0.4.0 | ⬜ |
| M13 | Asset Inventory & Risk Context | v0.5.0 | ⬜ |
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

**Status:** 🟠 In Progress — local Sigma metadata verification passed, GitHub run pending

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

Sigma detection translation vẫn disabled rõ ràng cho tới M11.2. GitHub-hosted regression chờ commit được push.

### Commit

```text
feat: add Sigma rule parser and metadata adapter
```

---

## M11.2 — Sigma selection mapping

**Status:** ⬜

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

- [ ] Define supported operators.
- [ ] Define unsupported operators.
- [ ] Map field aliases.
- [ ] Normalize Windows fields.
- [ ] Preserve raw Sigma detection.
- [ ] Unsupported syntax → skip + reason.

### DoD

- [ ] Process creation rule match được Sysmon normalized event.
- [ ] PowerShell rule hoạt động.
- [ ] Exclusion/filter hoạt động.
- [ ] Unsupported syntax không tạo false match.

### Commit

```text
feat: translate supported Sigma selections into Mini-SIEM rules
```

---

## M11.3 — Sigma lifecycle

**Status:** ⬜

### Tasks

- [ ] Enable/disable Sigma rule.
- [ ] Admin UI hiển thị source Native/Sigma.
- [ ] Validation status.
- [ ] Last loaded time.
- [ ] Hit count.
- [ ] Never-hit state.
- [ ] Audit enable/disable.

### Commit

```text
feat: manage Sigma rule lifecycle and coverage
```

---

## M11.4 — Sigma regression corpus

**Status:** ⬜

### Fixtures

- [ ] Windows process creation.
- [ ] PowerShell.
- [ ] Account creation.
- [ ] Positive cases.
- [ ] Negative cases.
- [ ] Unsupported syntax case.

### DoD

- [ ] Positive matches đúng rule.
- [ ] Negative không match.
- [ ] Regression chạy trong CI.
- [ ] Không cần network.

### Commit

```text
test: add Sigma detection regression corpus
```

---

## M11.5 — Sigma documentation

**Status:** ⬜

- [ ] Supported subset.
- [ ] Unsupported syntax.
- [ ] Import path.
- [ ] Provenance.
- [ ] Example.
- [ ] Debug procedure.
- [ ] Known limitations.

### Commit

```text
docs: document Sigma rule support
```

---

# M12 — Threat Intelligence Layer

## M12.1 — ThreatIntelProvider abstraction

**Status:** ⬜

### Architecture

```text
Alert IOC
→ IOC Normalizer
→ Cache
→ Provider
→ Normalized Result
→ Dashboard / AI Context
```

### File dự kiến

```text
src/threat_intel/
├── __init__.py
├── base.py
├── service.py
├── cache.py
└── models.py
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

- [ ] Provider interface.
- [ ] IOC normalization.
- [ ] TTL cache.
- [ ] Rate limiter.
- [ ] Timeout.
- [ ] Bounded retry.
- [ ] Structured error state.
- [ ] Lookup không block alert persistence.
- [ ] Không persist API secret.

### DoD

- [ ] Dummy provider hoạt động.
- [ ] Cache hit không lookup lại.
- [ ] Provider timeout không crash pipeline.
- [ ] Result có timestamp/provenance.

### Commit

```text
refactor: add threat intelligence provider abstraction
```

---

## M12.2 — GeoIP enrichment

**Status:** ⬜

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

- [ ] Detect private/loopback/link-local.
- [ ] Không lookup private IP ngoài Internet.
- [ ] Cache result.
- [ ] Dashboard hiển thị GeoIP.
- [ ] Không coi foreign country = malicious.

### Commit

```text
feat: add GeoIP context enrichment
```

---

## M12.3 — AbuseIPDB provider

**Status:** ⬜

### Normalize

- abuse confidence
- total reports
- last reported
- ISP/domain
- usage type

### Tasks

- [ ] Key qua `.env`.
- [ ] Missing key → provider disabled.
- [ ] Không lookup private IP.
- [ ] Rate limit.
- [ ] Cache.
- [ ] Không gửi raw log.
- [ ] AI chỉ nhận normalized summary.
- [ ] API 429 handled.

### Commit

```text
feat: add AbuseIPDB threat intelligence enrichment
```

---

## M12.4 — VirusTotal metadata provider

**Status:** ⬜

### Safety rule

```text
Query metadata/hash only.
Never auto-upload internal files.
```

### Tasks

- [ ] Hash lookup trước.
- [ ] Domain/IP optional.
- [ ] Respect API quota.
- [ ] Cache hash result.
- [ ] Normalize malicious/suspicious counts.
- [ ] Không có auto-upload code path.

### Commit

```text
feat: add VirusTotal IOC metadata enrichment
```

---

## M12.5 — Threat Intel dashboard panel

**Status:** ⬜

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

- [ ] Pending/loading.
- [ ] Provider unavailable.
- [ ] Không render raw provider JSON.
- [ ] Không tự đổi system severity.
- [ ] Phân biệt observed evidence và third-party intelligence.

### Commit

```text
feat: show threat intelligence context on dashboard
```

---

## M12.6 — STIX/TAXII

**Status:** ⬜

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

- [ ] Offline STIX bundle import.
- [ ] TAXII collection optional.
- [ ] Scheduled/manual pull.
- [ ] Deduplicate indicators.
- [ ] Expire indicators.
- [ ] Match alert IOC.
- [ ] Preserve feed source.

### DoD

- [ ] Sample STIX bundle import được.
- [ ] IOC match hiển thị source.
- [ ] Expired indicator không active.
- [ ] Feed failure không crash detection.

### Commit

```text
feat: add STIX and TAXII threat intelligence ingestion
```

---

## M12.7 — Release v0.4.0

**Status:** ⬜

### Checklist

- [ ] M10 complete.
- [ ] M11 complete.
- [ ] M12 complete.
- [ ] CI green.
- [ ] README sync.
- [ ] `.env.example` sync.
- [ ] CHANGELOG update.
- [ ] Clean-clone verification.
- [ ] No secret.
- [ ] Tag `v0.4.0`.

### Release theme

```text
v0.4.0 — Detection Engineering & Threat Intelligence
```

---

# M13 — Asset Inventory & Risk Context

## M13.1 — Asset schema

**Status:** ⬜

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

- [ ] SQLite asset table.
- [ ] CRUD repository.
- [ ] Stable asset ID.
- [ ] IP/hostname lookup.
- [ ] Duplicate detection.
- [ ] Audit changes.

### Commit

```text
feat: add asset inventory data model
```

---

## M13.2 — Asset management API/UI

**Status:** ⬜

- [ ] Admin-only CRUD.
- [ ] Search/filter.
- [ ] Criticality.
- [ ] Owner/team.
- [ ] Tags.
- [ ] Validation.
- [ ] CSRF/RBAC.
- [ ] Audit.

### Commit

```text
feat: add asset inventory management
```

---

## M13.3 — Alert-to-asset enrichment

**Status:** ⬜

- [ ] Match by IP/hostname.
- [ ] Add `asset_id`.
- [ ] Unknown asset vẫn hợp lệ.
- [ ] Dashboard link alert → asset.
- [ ] Không duplicate full asset object nếu không cần.

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
- [ ] Clean clone pass.
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
M11.1 — Commit/push and verify Sigma metadata regression
```

Không bắt đầu Sigma trước CI vì feature Sigma/TI sẽ mở rộng đáng kể số code path cần bảo vệ.

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

- [ ] GitHub Actions bảo vệ baseline.
- [ ] Docker smoke CI hoạt động.
- [ ] Secret/dependency checks hoạt động.
- [ ] Sigma parser giữ provenance.
- [ ] Supported Sigma subset được document.
- [ ] Sigma positive/negative regression chạy trong CI.
- [ ] Native rules vẫn hoạt động.
- [ ] Threat Intel abstraction hoàn tất.
- [ ] GeoIP hoạt động.
- [ ] AbuseIPDB optional provider hoạt động.
- [ ] VirusTotal metadata lookup optional hoạt động.
- [ ] Không có VirusTotal auto-upload.
- [ ] TI cache/rate-limit/provenance hoạt động.
- [ ] TI failure không block detection.
- [ ] TI dashboard panel hoạt động.
- [ ] STIX offline import hoạt động.
- [ ] TAXII optional path hoạt động hoặc có documented blocker.
- [ ] README / `.env.example` sync.
- [ ] Clean clone pass.
- [ ] Tag `v0.4.0`.

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
| 2026-08-15 | Risk tách khỏi severity | Detection semantics rõ ràng |
| 2026-08-15 | LLM không đặt risk score trực tiếp | Risk phải explainable |
| 2026-08-15 | Multi-tenant deferred | Complexity cao, chưa cần |

---

# 14. Current next action

```text
START HERE:
M11.1 — Commit/push and verify the Sigma metadata GitHub Actions run
```

Sau khi GitHub Actions chạy thành công:

1. Đổi M11.1 thành `✅` và ghi GitHub Actions run.
2. Đổi M11.2 thành batch tiếp theo.
3. Không enable Sigma detection trước khi selection mapping pass.
