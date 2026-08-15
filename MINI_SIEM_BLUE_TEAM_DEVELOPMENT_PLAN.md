# Mini-SIEM Blue Team Development Plan

> **Repository:** `zenniskayy2k4/Mini-SIEM`
> **Plan type:** Milestone / batch execution plan
> **Last updated:** 2026-08-06
> **Primary environment:** Windows + Docker Desktop
> **Primary AI provider:** Ollama Cloud (`gemma4:cloud`)
> **Storage hiện tại:** `data/siem_alerts.json`

---

## 1. Mục tiêu dự án

Phát triển Mini-SIEM thành một nền tảng Blue Team nhẹ, có thể chạy trên máy cá nhân bằng Docker, tập trung vào:

- Thu thập và chuẩn hóa security events.
- Rule-based detection kết hợp ML anomaly detection.
- Correlation theo IP, user, host và attack sequence.
- AI-assisted triage bằng Ollama Cloud.
- Incident lifecycle và analyst workflow.
- Response workflow an toàn theo chế độ simulation/manual.
- Dashboard phục vụ điều tra và theo dõi.
- Storage có khả năng truy vấn, cập nhật và mở rộng.
- Detection engineering có thể cấu hình và kiểm thử bằng attack simulator.

### Ngoài phạm vi hiện tại

Các thành phần sau **không nằm trong roadmap chính** vì giới hạn tài nguyên máy:

- Wazuh stack.
- Shuffle SOAR.
- Elasticsearch/OpenSearch.
- Kafka.
- Hệ thống EDR hoặc endpoint isolation thật.
- Auto-response production không có analyst approval.

---

## 2. Nguyên tắc phát triển

1. Phát triển trực tiếp từ repo gốc; không viết lại project từ đầu.
2. Mỗi batch chỉ giải quyết một nhóm vấn đề rõ ràng.
3. Không trộn storage migration, dashboard redesign và detection logic trong cùng một commit.
4. Giữ tương thích với Docker Compose hiện tại.
5. Mọi automated response mặc định phải là `simulation` hoặc yêu cầu xác nhận.
6. AI chỉ đưa ra phân tích và khuyến nghị; không tự thay đổi quyết định chính thức của detection engine.
7. Không commit:
   - `.env`
   - API key
   - runtime logs
   - generated alerts
   - model artifacts không chủ đích
8. Ưu tiên manual smoke verification. Automated test là optional backlog, không phải blocker.
9. Sau mỗi batch:
   - Rebuild service liên quan.
   - Chạy smoke check.
   - Kiểm tra `git diff`.
   - Commit độc lập.
   - Push.

---

## 3. Ký hiệu tracking

| Ký hiệu | Ý nghĩa |
|---|---|
| ✅ | Hoàn thành |
| 🟡 | Batch nên làm tiếp theo |
| ⬜ | Chưa bắt đầu |
| 🟠 | Đang thực hiện |
| ⛔ | Bị chặn |
| 🔁 | Cần kiểm tra lại hoặc refactor |

---

## 4. Trạng thái tổng quan

| Milestone | Nội dung | Trạng thái |
|---|---|---|
| M0 | Baseline Docker và pipeline gốc | ✅ |
| M1 | Ollama Cloud AI Analyst | ✅ |
| M2 | Detection correctness và alert contract | ✅ |
| M3 | Incident lifecycle và analyst workflow | 🟡 |
| M4 | SQLite storage migration | ⬜ |
| M5 | Detection engineering và rule management | ✅ |
| M6 | Lightweight response automation | ✅ |
| M7 | Windows telemetry và Sysmon | ⬜ |
| M8 | Dashboard security, observability và reliability | ✅ |
| M9 | Release, documentation và portfolio demo | ⬜ |

---

# Milestone M0 — Baseline Docker và pipeline gốc

## Mục tiêu

Xác nhận repo gốc chạy end-to-end trước khi phát triển.

## Batch M0.1 — Docker baseline

**Trạng thái:** ✅ Hoàn thành

### Đã xác nhận

- [x] `docker compose config` hợp lệ.
- [x] Docker Compose nhận đủ:
  - `agent`
  - `dashboard`
  - `train`
- [x] Model training hoàn thành.
- [x] Agent đọc được `/app/logs/auth.log`.
- [x] Dashboard chạy tại `http://localhost:5000`.
- [x] Alert được persist vào `data/siem_alerts.json`.
- [x] Incident responder ghi `data/incident_responses.log`.

### Model artifacts đã tạo

- `autoencoder.pth`
- `iso_forest.pkl`
- `nlp_iso_forest.pkl`
- `tfidf_vectorizer.pkl`
- `scaler.pkl`
- `feature_names.txt`
- `threshold.txt`

### Baseline smoke commands

```powershell
docker compose ps
docker compose logs --tail=100 agent
docker compose logs --tail=100 dashboard
Get-Content .\data\siem_alerts.json -Raw
```

---

# Milestone M1 — Ollama Cloud AI Analyst

## Mục tiêu

Thay Groq bằng Ollama Cloud và tích hợp AI triage vào pipeline HIGH/CRITICAL alert.

## Batch M1.1 — Ollama Cloud provider

**Trạng thái:** ✅ Hoàn thành

### Đã thực hiện

- [x] Thêm cấu hình:
  - `AI_PROVIDER=ollama_cloud`
  - `OLLAMA_API_KEY`
  - `OLLAMA_BASE_URL=https://ollama.com/api`
  - `OLLAMA_MODEL=gemma4:cloud`
- [x] Docker `agent` nhận `.env`.
- [x] Container gọi `/api/chat` thành công.
- [x] `AIAnalyst` sử dụng Ollama Cloud thay cho Groq.
- [x] `main.py` inject `AIAnalyst` vào `ThreatDetector`.
- [x] AI trả structured JSON.
- [x] Async enrichment persist vào `siem_alerts.json`.

### Kết quả AI contract hiện tại

```json
{
  "is_false_positive": false,
  "fp_confidence": 10,
  "threat_confidence": 85,
  "mitre_tactic": "Credential Access",
  "mitre_technique": "T1110.001 - Password Guessing",
  "threat_summary": "...",
  "recommended_playbook": ["..."],
  "ioc_tags": ["192.168.1.50"],
  "escalate_to_human": true,
  "provider": "ollama_cloud",
  "model": "gemma4:cloud",
  "analysed_at": "...",
  "cached": false
}
```

## Batch M1.2 — AI panel trên dashboard

**Trạng thái:** ✅ Hoàn thành
**Commit:** `d0658db feat: show AI analysis on dashboard`

### Đã thực hiện

- [x] Render panel `AI Analyst`.
- [x] Hiển thị threat confidence.
- [x] Hiển thị false-positive confidence.
- [x] Hiển thị MITRE mapping.
- [x] Hiển thị summary.
- [x] Hiển thị recommended playbook.
- [x] Hiển thị IOC tags.
- [x] Hiển thị provider/model.
- [x] Có trạng thái `AI analysis pending`.

## Batch M1.3 — Tách AI recommendation khỏi severity

**Trạng thái:** ✅ Hoàn thành
**Commit:** `4dd5387 refactor: separate AI severity recommendation`

### Đã thực hiện

- [x] AI không sửa `alert["severity"]`.
- [x] AI không sửa `alert["status"]`.
- [x] Thêm:
  - `ai_recommended_severity`
  - `ai_disposition`
- [x] Dashboard hiển thị:
  - System severity
  - AI recommendation
  - Decision
- [x] Pipeline xác nhận:
  - `severity: HIGH`
  - `ai_recommended_severity: CRITICAL`
  - `ai_disposition: REQUIRES_HUMAN_REVIEW`

---

# Milestone M2 — Detection correctness và alert contract

## Mục tiêu

Đảm bảo detection engine không tạo alert sai ngữ nghĩa và mọi alert có schema ổn định để dashboard, storage, AI và incident workflow cùng sử dụng.

---

## Batch M2.1 — SSH brute-force threshold

**Trạng thái:** ✅ Hoàn thành và xác nhận lại

### Yêu cầu chức năng

- [x] Một failed login không bị kết luận là brute force.
- [x] Theo dõi failed login theo source IP.
- [x] Áp dụng threshold.
- [x] Áp dụng time window.
- [x] Đủ điều kiện mới sinh `SSH Brute Force Attempt`.
- [x] Alert tổng hợp được gửi sang Ollama Cloud.

### Alert nên có

```json
{
  "event_count": 5,
  "window_seconds": 60,
  "first_seen": "...",
  "last_seen": "...",
  "target_users": ["admin"]
}
```

### Cần xác nhận lại trước khi đóng milestone

- [x] Lần 1–4 không tạo brute-force alert.
- [x] Lần 5 tạo đúng một alert.
- [x] Lần 6 trong cùng campaign không tạo alert trùng không kiểm soát.
- [x] IP khác có bucket riêng.
- [x] Event hết window bị loại khỏi bộ đếm.
- [x] Restart agent không gây exception do state rỗng.

---

## Batch M2.2 — Chuẩn hóa Alert Contract

**Trạng thái:** ✅ Hoàn thành

### Mục tiêu

Tạo một schema alert thống nhất để tránh mỗi detector sinh field khác nhau.

### File dự kiến sửa

- `src/detector.py`
- `src/correlator.py`
- `src/network_monitor.py`
- `src/honeypot.py`
- `src/handler.py`
- Có thể thêm: `src/alert_schema.py`

### Schema tối thiểu đề xuất

```json
{
  "alert_id": "ALT-...",
  "timestamp": "...",
  "alert_name": "...",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "status": "DETECTED",
  "source_type": "HIDS_LOG|NIDS|HONEYPOT|CORRELATION",
  "description": "...",
  "raw_log": "...",
  "ip_address": "...",
  "mitre_attck_id": "...",
  "event_count": 1,
  "first_seen": "...",
  "last_seen": "...",
  "correlation_key": "...",
  "ml_confidence": null,
  "ai_analysis": null,
  "ai_recommended_severity": null,
  "ai_disposition": null
}
```

### Tasks

- [x] Tạo hàm factory, ví dụ `build_alert(...)`.
- [x] Sinh `alert_id` ổn định bằng UUID.
- [x] Chuẩn hóa timestamp thành UTC ISO-8601 kết thúc bằng `Z`.
- [x] Chuẩn hóa severity thành enum cố định.
- [x] Không dùng nhiều tên field cho cùng một khái niệm.
- [x] Field không có dữ liệu dùng `null`, không dùng nhiều biến thể `"N/A"`, `""`, `"Unknown"`.
- [x] Các sensor cũ vẫn tạo alert thành công.
- [x] Dashboard không lỗi với alert cũ thiếu field.

### Definition of Done

- [x] HIDS alert đúng schema.
- [x] NIDS alert đúng schema.
- [x] Honeypot alert đúng schema.
- [x] Correlated alert đúng schema.
- [x] Ollama vẫn enrich được.
- [x] `/api/alerts` trả dữ liệu tương thích dashboard.
- [x] Không làm mất field hiện có.

### Manual verification

```powershell
docker compose up -d --build --force-recreate agent dashboard
docker compose run --rm agent python tools/attack_sim.py
docker compose logs --tail=200 agent
Invoke-RestMethod http://localhost:5000/api/alerts
```

### Commit gợi ý

```text
refactor: standardize security alert schema
```

---

## Batch M2.3 — Correlation deduplication và cooldown

**Trạng thái:** ✅ Hoàn thành

### Mục tiêu

Ngăn cùng một campaign tạo quá nhiều alert giống nhau.

### Tasks

- [x] Xác định correlation key:
  - alert type
  - source IP
  - target host/user nếu có
- [x] Thêm cooldown sau khi trigger.
- [x] Trong cooldown, cập nhật `event_count` và `last_seen`.
- [x] Không append alert mới cho từng event.
- [x] Khi window mới bắt đầu, cho phép tạo campaign mới.
- [x] AI cache không dùng chung cho hai IP khác nhau.
- [x] Thêm `deduplicated_events` hoặc `suppressed_count`.

### Definition of Done

- [x] 20 failed logins trong một campaign tạo một alert cập nhật.
- [x] Hai source IP tạo hai campaign.
- [x] Sau cooldown có thể tạo campaign mới.
- [x] Dashboard hiển thị count mới nhất.

### Commit gợi ý

```text
feat: deduplicate correlated attack campaigns
```

---

## Batch M2.4 — Prompt grounding cho AI

**Trạng thái:** ✅ Hoàn thành

### Mục tiêu

Không để LLM suy diễn event volume, compromise hoặc attack progression khi alert không cung cấp bằng chứng.

### Tasks

- [x] Gửi `event_count`.
- [x] Gửi `window_seconds`.
- [x] Gửi `first_seen`, `last_seen`.
- [x] Gửi `target_users`.
- [x] Thêm prompt rule:
  - Không giả định dữ liệu không có.
  - Phân biệt observed facts và inference.
  - Không nói “successful compromise” nếu không có successful login.
- [x] Thêm field:
  - `observed_facts`
  - `analyst_inferences`
  - hoặc cập nhật `threat_summary` theo nguyên tắc evidence-only.

### Definition of Done

- [x] Một authentication failure không bị mô tả là high-volume brute force.
- [x] AI nói rõ khi evidence chưa đủ.
- [x] AI playbook vẫn hữu ích.
- [x] JSON parse không lỗi.

### Xác nhận Milestone M2 — 2026-08-05

- [x] `python -m tools.check_m2` pass trong agent container vừa rebuild.
- [x] Python và JavaScript syntax check pass.
- [x] `agent` và `dashboard` Up sau rebuild/recreate.
- [x] `/api/alerts` trả alert contract mới và vẫn đọc alert cũ.
- [x] Ollama Cloud mô tả đúng một failed login, không suy diễn brute force hoặc compromise.

### Commit gợi ý

```text
refactor: ground AI triage in correlated alert evidence
```

---

# Milestone M3 — Incident lifecycle và analyst workflow

## Mục tiêu

Cho phép SOC analyst quản lý alert như một incident có trạng thái, người phụ trách, notes và timeline.

---

## Batch M3.1 — Alert identity và lifecycle fields

**Trạng thái:** ✅ Hoàn thành

### File dự kiến sửa

- `src/alert_store.py`
- `dashboard.py`
- `static/js/app.js`
- Có thể thêm: `src/incident_service.py`

### Fields đề xuất

```json
{
  "alert_id": "ALT-...",
  "incident_id": "INC-...",
  "incident_status": "NEW",
  "assigned_to": null,
  "analyst_notes": [],
  "created_at": "...",
  "updated_at": "..."
}
```

### Status hợp lệ

```text
NEW
INVESTIGATING
CONTAINED
RESOLVED
FALSE_POSITIVE
```

### Tasks

- [x] Alert mới có `alert_id`.
- [x] Incident-worthy alert có `incident_id`.
- [x] Status mặc định là `NEW`.
- [x] AI không được tự sửa incident status.
- [x] Alert cũ thiếu field vẫn đọc được.

### Definition of Done

- [x] Alert mới có ID không phụ thuộc index JSON.
- [x] Reload dashboard không đổi ID.
- [x] Không có hai alert cùng ID.

### Xác nhận Batch M3.1 — 2026-08-06

- [x] HIGH/CRITICAL tự tạo `incident_id`; LOW/MEDIUM giữ `null`.
- [x] `created_at` và `updated_at` dùng UTC ISO-8601.
- [x] Alert bị ML nâng severity vẫn nhận lifecycle trước khi persist.
- [x] `python -m tools.check_m3_1` pass.
- [x] M2 regression và Python syntax check pass.

### Commit gợi ý

```text
feat: add alert identity and incident lifecycle fields
```

---

## Batch M3.2 — API cập nhật incident status

**Trạng thái:** ✅ Hoàn thành

### API đề xuất

```http
PATCH /api/alerts/<alert_id>/status
```

Request:

```json
{
  "status": "INVESTIGATING"
}
```

### Tasks

- [x] Validate status.
- [x] Trả `404` nếu không có alert.
- [x] Trả `400` nếu status không hợp lệ.
- [x] Cập nhật `updated_at`.
- [x] Ghi event vào timeline/audit.
- [x] Không ghi đè alert mới do agent append đồng thời.

### Definition of Done

- [x] `NEW → INVESTIGATING` hoạt động.
- [x] `INVESTIGATING → CONTAINED` hoạt động.
- [x] `CONTAINED → RESOLVED` hoạt động.
- [x] `FALSE_POSITIVE` persist sau reload.
- [x] Invalid status bị từ chối.

### Xác nhận Batch M3.2 — 2026-08-06

- [x] PATCH API, `400` và `404` pass bằng Flask test client.
- [x] Timeline lưu `from_status`, `to_status` và UTC timestamp.
- [x] Hai process status-update/append đồng thời không làm mất alert.
- [x] `python -m tools.check_m3_2` pass.
- [x] M3.1, M2 regression và Python syntax check pass.

### Commit gợi ý

```text
feat: add incident status update API
```

---

## Batch M3.3 — Analyst notes và assignment

**Trạng thái:** ✅ Hoàn thành

### API đề xuất

```http
POST /api/alerts/<alert_id>/notes
PATCH /api/alerts/<alert_id>/assignee
```

### Tasks

- [x] Note không được rỗng.
- [x] Giới hạn độ dài note.
- [x] Lưu author và timestamp.
- [x] Escape output để chống XSS.
- [x] Có thể gán `assigned_to`.
- [x] Timeline ghi nhận status, note và assignment changes.

### Definition of Done

- [x] Thêm note thành công.
- [x] Reload vẫn còn note.
- [x] HTML trong note không được thực thi.
- [x] Assignment hiển thị trên dashboard.

### Xác nhận Batch M3.3 — 2026-08-06

- [x] Note rỗng và vượt 2.000 ký tự trả `400`.
- [x] Note, author và assignee được HTML-escape trước khi persist.
- [x] API trả `404` cho alert không tồn tại.
- [x] Timeline có đủ status, note và assignment events.
- [x] `python -m tools.check_m3_3` pass.
- [x] M3.2, M3.1, M2 regression và syntax checks pass.

### Commit gợi ý

```text
feat: add analyst notes and incident assignment
```

---

## Batch M3.4 — Incident dashboard UI

**Trạng thái:** ✅ Hoàn thành

### Tasks

- [x] Status badge.
- [x] Status action buttons.
- [x] Assignee field.
- [x] Analyst note form.
- [x] Timeline.
- [x] Filter theo incident status.
- [x] Filter `REQUIRES_HUMAN_REVIEW`.
- [x] Hiển thị system severity cạnh AI recommendation.

### Definition of Done

- [x] Analyst xử lý incident mà không mở JSON thủ công.
- [x] UI vẫn hoạt động với alert không có AI.
- [x] API error hiển thị rõ.
- [x] Không reload toàn page cho mỗi action nếu có thể.

### Xác nhận Batch M3.4 — 2026-08-06

- [x] Status, assignment, notes và timeline thao tác trực tiếp trên Logs UI.
- [x] Status/assignee/note action chỉ thay dòng vừa cập nhật, không reload toàn page.
- [x] Incident status và human-review filters hoạt động phía server.
- [x] API error hiển thị inline trong incident panel.
- [x] `python -m tools.check_m3_4` và toàn bộ regression M2–M3 pass.
- [x] Dashboard trả HTTP 200 sau Docker rebuild.

### Commit gợi ý

```text
feat: add incident workflow to SOC dashboard
```

---

# Milestone M4 — SQLite storage migration

## Mục tiêu

Thay JSON file làm primary storage bằng SQLite để hỗ trợ update, pagination, filtering và concurrency tốt hơn.

> Không xóa JSON ngay. Triển khai theo cơ chế dual-write rồi mới chuyển read path.

---

## Batch M4.1 — Storage abstraction

**Trạng thái:** ✅ Hoàn thành

### File dự kiến

- Thêm `src/storage.py` hoặc `src/sqlite_store.py`
- Sửa `src/alert_store.py`
- Sửa `dashboard.py`

### Interface đề xuất

```python
class AlertRepository:
    def create_alert(self, alert: dict) -> dict: ...
    def update_alert(self, alert_id: str, changes: dict) -> dict | None: ...
    def get_alert(self, alert_id: str) -> dict | None: ...
    def list_alerts(self, filters: dict, limit: int, offset: int) -> list[dict]: ...
```

### Tasks

- [x] Tách code lưu trữ khỏi detector và dashboard.
- [x] JSON implementation vẫn hoạt động.
- [x] Không để module khác tự mở `siem_alerts.json`.

### Xác nhận Batch M4.1 — 2026-08-06

- [x] `JsonAlertRepository` cung cấp create, update, get và list/filter/pagination.
- [x] Detector giữ API `upsert_alert`; dashboard đọc qua repository.
- [x] Incident status, notes và assignment vẫn update nguyên tử dưới file lock.
- [x] Temporary regression M4.1 và Python syntax check pass trong container.
- [x] File check tạm đã xóa trước commit.

### Commit gợi ý

```text
refactor: add alert repository abstraction
```

---

## Batch M4.2 — SQLite schema và dual-write

**Trạng thái:** ✅ Hoàn thành

### Database

```text
data/mini_siem.db
```

### Tables đề xuất

- `alerts`
- `incidents`
- `incident_events`
- `analyst_notes`
- `response_actions`

### Tasks

- [x] Auto-create database.
- [x] Tạo schema idempotent.
- [x] Ghi alert vào JSON và SQLite.
- [x] JSON write failure không làm SQLite mất dữ liệu.
- [x] SQLite failure được log rõ.
- [x] Persist nested AI JSON dưới dạng JSON text hoặc normalized fields phù hợp.
- [x] HIDS/NIDS/Honeypot dùng chung AI dispatch path.
- [x] Ollama giới hạn một request đang chạy; alert đến khi bận được đánh dấu `busy`.

### Definition of Done

- [x] Restart container không mất dữ liệu.
- [x] Alert count JSON và SQLite khớp trong smoke test.
- [x] Incident updates persist trong SQLite.

### Xác nhận Batch M4.2 — 2026-08-06

- [x] Tạo idempotent các bảng alerts, incidents, incident_events, analyst_notes và response_actions.
- [x] JSON/SQLite failure isolation và concurrent append/update pass trong temporary regression.
- [x] AI dispatcher dùng một worker và không tạo hàng đợi vô hạn.
- [x] Live HIDS alert được Ollama enrich và dual-write với JSON = SQLite = 1.
- [x] Live incident status/timeline persist trong SQLite.
- [x] UI phân biệt AI `busy`, `rate_limited` và error thay vì pending vô hạn.
- [x] File check tạm đã xóa trước commit.

### Commit gợi ý

```text
feat: add SQLite dual-write alert storage
```

---

## Batch M4.3 — JSON to SQLite migration

**Trạng thái:** ✅ Hoàn thành

### File đề xuất

```text
tools/migrate_json_to_sqlite.py
```

### Tasks

- [x] Backup database trước migrate.
- [x] Import alert cũ.
- [x] Không duplicate khi chạy lại.
- [x] Báo số record imported/skipped/failed.
- [x] Giữ nguyên `alert_id`.
- [x] Sinh ID cho alert legacy chưa có ID.

### Xác nhận Batch M4.3 — 2026-08-07

- [x] SQLite online backup được tạo trước mỗi lần migrate.
- [x] Legacy alert thiếu ID nhận UUID5 ổn định theo nội dung.
- [x] Chạy lại migration skip ID đã tồn tại và không duplicate.
- [x] Báo riêng imported, skipped, failed và lỗi theo số dòng.
- [x] Temporary regression hai lượt và Python syntax check pass.
- [x] Live migration baseline: import 0, skip 1, fail 0; JSON = SQLite = 1.
- [x] File check tạm đã xóa trước commit.

### Commit gợi ý

```text
feat: add JSON to SQLite migration tool
```

---

## Batch M4.4 — Dashboard read từ SQLite

**Trạng thái:** ✅ Hoàn thành

### Tasks

- [x] `/api/alerts` query SQLite.
- [x] Server-side pagination.
- [x] Filter:
  - severity
  - IP
  - MITRE
  - status
  - time range
  - AI disposition
- [x] Sort theo timestamp.
- [x] JSON fallback feature flag trong giai đoạn chuyển tiếp.

### Definition of Done

- [x] Dashboard không đọc toàn bộ history vào RAM.
- [x] Filter hoạt động.
- [x] Incident update không race với agent append.
- [x] Có thể disable JSON dual-write sau khi ổn định.

### Xác nhận Batch M4.4 — 2026-08-07

- [x] `/api/alerts`, `/api/alerts/search`, `/api/stats` và graph dùng SQLite read path mặc định.
- [x] SQLite thực hiện filter, count, sort và pagination trước khi deserialize payload trả về.
- [x] UI hỗ trợ severity, IP, MITRE, incident status, time range, free text và AI disposition.
- [x] Có feature flags cho SQLite read, JSON fallback và JSON dual-write.
- [x] Regression synthetic và live API smoke test pass; temporary check đã xóa trước commit.

### Commit gợi ý

```text
feat: serve dashboard alerts from SQLite
```

---

# Milestone M5 — Detection engineering và rule management

## Mục tiêu

Chuyển signature detection từ logic hard-coded sang rule có ID, metadata, enable/disable và MITRE mapping rõ ràng.

---

## Batch M5.1 — Rule metadata contract

**Trạng thái:** ✅ Hoàn thành

### Rule fields

```yaml
id: DET-SSH-001
title: SSH Authentication Failure
enabled: true
severity: MEDIUM
source_type: HIDS_LOG
mitre:
  tactic: Credential Access
  technique: T1110.001
match:
  contains: "Failed password"
```

### Tasks

- [x] Mỗi rule có ID.
- [x] Mỗi rule có title.
- [x] Mỗi rule có severity.
- [x] Mỗi rule có MITRE metadata.
- [x] Alert lưu `rule_id`.
- [x] Dashboard hiển thị rule ID.

### Xác nhận Batch M5.1 — 2026-08-09

- [x] Hai signature hiện tại dùng contract `id`, `title`, `enabled`, `severity`, `source_type`, `mitre`, `match`.
- [x] Validator fail-fast với metadata thiếu, severity/source type sai, regex lỗi và rule ID trùng.
- [x] Signature match ghi `rule_id` vào alert; alert không thuộc signature giữ `rule_id: null`.
- [x] Overview và Logs UI hiển thị rule ID khi có.
- [x] Temporary regression pass và file check đã xóa trước commit.

### Commit gợi ý

```text
refactor: add metadata contract for detection rules
```

---

## Batch M5.2 — YAML rule loader

**Trạng thái:** ✅ Hoàn thành

### File đề xuất

```text
config/rules/
├── authentication.yml
├── privilege_escalation.yml
├── network.yml
└── persistence.yml
```

### Tasks

- [x] Load YAML khi agent start.
- [x] Validate required fields.
- [x] Rule lỗi không làm agent crash toàn bộ.
- [x] Log rule loaded/skipped.
- [x] Enable/disable rule.
- [x] Giữ fallback cho signatures cũ trong giai đoạn đầu.

### Xác nhận Batch M5.2 — 2026-08-09

- [x] Hai signature hiện tại được nạp từ `config/rules/*.yml` qua `yaml.safe_load`.
- [x] Rule sai bị bỏ qua riêng; rule disabled không được đưa vào detector.
- [x] Không có YAML hợp lệ thì quay về `config.SIGNATURES`.
- [x] Regression trong container và live alert `DET-LNX-002` đều pass.
- [x] Agent khởi động log rõ rule loaded/skipped.

### Commit gợi ý

```text
feat: load configurable detection rules from YAML
```

---

## Batch M5.3 — Rule matching operators

**Trạng thái:** ✅ Hoàn thành

### Operators

- `contains`
- `contains_any`
- `contains_all`
- `regex`
- `equals`
- `not_contains`
- threshold/time-window reference

### Definition of Done

- [x] Rule SSH hoạt động.
- [x] Rule sudo hoạt động.
- [x] Rule account creation hoạt động.
- [x] Invalid regex được xử lý an toàn.
- [x] Rule match ghi `rule_id`.

### Xác nhận Batch M5.3 — 2026-08-09

- [x] Hỗ trợ `contains`, `contains_any`, `contains_all`, `regex`, `equals`, `not_contains` không phân biệt hoa thường.
- [x] Nhiều operator trong cùng `match` được kết hợp theo điều kiện AND.
- [x] SSH dùng regex/metadata từ `DET-SSH-001` và tham chiếu threshold/window tới cấu hình hiện tại.
- [x] Validator từ chối operator/value/reference sai và regex lỗi trước khi rule chạy.
- [x] Regression trong image và live alerts cho `DET-SSH-001`, `DET-LNX-001`, `DET-LNX-002` đều pass.

### Commit gợi ý

```text
feat: add flexible rule matching operators
```

---

## Batch M5.4 — Detection coverage tracking

**Trạng thái:** ✅ Hoàn thành

### Tasks

- [x] Mapping attack simulator mode → expected rule ID.
- [x] Hiển thị rule hit count.
- [x] Hiển thị rule chưa từng trigger.
- [x] MITRE coverage summary.
- [x] Manual detection checklist document.

### Xác nhận Batch M5.4 — 2026-08-09

- [x] `/api/detection-coverage` tổng hợp hit count bằng SQLite `GROUP BY rule_id`, có JSON streaming fallback.
- [x] Dashboard hiển thị từng rule với `HIT`/`NEVER HIT` và tổng quan MITRE techniques.
- [x] Attack simulator hiển thị expected rule ID cho từng mode; mode AI/NIDS ghi rõ không thuộc YAML rule coverage.
- [x] `DETECTION_CHECKLIST.md` mô tả pass criteria cho simulator và account creation rule.
- [x] Regression trong image, Flask smoke test và live API/UI đều pass.

### Không bắt buộc

Automated test suite có thể làm sau. Giai đoạn này có thể dùng attack simulator và script smoke check.

### Commit gợi ý

```text
feat: add detection coverage reporting
```

---

# Milestone M6 — Lightweight response automation

## Mục tiêu

Cung cấp workflow phản ứng an toàn mà không cần Shuffle, mặc định không thực thi lệnh nguy hiểm.

---

## Batch M6.1 — Response mode và action contract

**Trạng thái:** ✅ Hoàn tất (2026-08-09)

### Modes

```text
disabled
simulation
manual
automatic
```

Mặc định:

```env
RESPONSE_MODE=simulation
```

### Action schema

```json
{
  "action_id": "ACT-...",
  "incident_id": "INC-...",
  "action_type": "BLOCK_IP",
  "target": "192.168.1.50",
  "mode": "simulation",
  "status": "PROPOSED",
  "requested_by": "analyst",
  "created_at": "..."
}
```

### Tasks

- [x] Không lưu command shell trực tiếp như quyết định cuối.
- [x] Mapping action theo OS.
- [x] Audit mọi action.
- [x] Không tự chạy action do LLM tạo ra.

### Xác nhận hoàn tất (2026-08-09)

- Hỗ trợ đủ bốn mode, mặc định `simulation`; M6.1 chỉ tạo contract và không có executor.
- Action có ID riêng, mapping handler Linux/Windows và được audit vào JSONL cùng SQLite.
- Legacy shell mitigation bị loại khỏi schema/UI; action do LLM yêu cầu luôn cần phê duyệt, còn mode `disabled` luôn `SKIPPED`.
- Regression test và live test SSH → `BLOCK_IP` đều pass; Ollama hoàn tất đúng một lượt phân tích cho alert thử nghiệm.

### Commit gợi ý

```text
refactor: add safe response action contract
```

---

## Batch M6.2 — Response simulation

**Trạng thái:** ✅ Hoàn tất (2026-08-09)

### Actions mô phỏng

- Block IP.
- Unblock IP.
- Disable user.
- Kill process.
- Quarantine file.
- Notify analyst.

### Definition of Done

- [x] Dashboard có nút request action.
- [x] Simulation ghi “would execute”.
- [x] Không thay đổi firewall thật.
- [x] Action xuất hiện trong incident timeline.

### Xác nhận hoàn tất (2026-08-09)

- Dashboard cho phép request đủ sáu action mô phỏng từ incident panel.
- Mọi request ở mode `simulation` chuyển thành `SIMULATED`, ghi `would execute`, JSONL audit và SQLite.
- Timeline lưu action ID, type, target và status; không có shell executor hoặc thay đổi firewall/filesystem thật.
- Regression test và live test `QUARANTINE_FILE` đều pass; marker file xác minh không được tạo.

### Commit gợi ý

```text
feat: add simulated incident response actions
```

---

## Batch M6.3 — Manual approval

**Trạng thái:** ✅ Hoàn tất (2026-08-09)

### Workflow

```text
PROPOSED
→ APPROVED
→ EXECUTED / SIMULATED
→ FAILED / ROLLED_BACK
```

### Tasks

- [x] AI playbook chỉ tạo proposal.
- [x] Analyst phải approve.
- [x] Allowlists cho localhost, gateway, critical assets.
- [x] Target validation.
- [x] Timeout và error handling.
- [x] Không cho command injection.

### Xác nhận hoàn tất (2026-08-09)

- Proposal có approval expiry; LLM không thể vượt qua `REQUIRES_APPROVAL` nếu chưa có analyst.
- Analyst approval được audit và chuyển `APPROVED → SIMULATED`; simulation có thể chuyển `ROLLED_BACK` mà không đổi hệ thống thật.
- Protected-target list hỗ trợ localhost, gateway và critical assets; IP, user, PID và path được validate theo action type.
- Proposal hết hạn hoặc target lỗi chuyển `FAILED`; không có shell executor nên command injection không có đường thực thi.
- Regression và live workflow đều pass; Ollama hoàn tất đúng một lượt cho alert thử nghiệm.

### Commit gợi ý

```text
feat: add analyst approval workflow for response actions
```

---

## Batch M6.4 — Notifications

**Trạng thái:** ✅ Hoàn tất (2026-08-13)

### Kênh ưu tiên

1. Discord webhook hoặc generic webhook.
2. Email.
3. Slack nếu cần.

### Tasks

- [x] Chỉ gửi HIGH/CRITICAL hoặc `REQUIRES_HUMAN_REVIEW`.
- [x] Deduplicate notifications.
- [x] Không gửi raw secret/log nhạy cảm.
- [x] Retry giới hạn.
- [x] Notification result ghi audit.

### Xác nhận hoàn tất (2026-08-13)

- Generic/Discord webhook dùng chung tại alert pipeline; mặc định tắt khi chưa cấu hình URL.
- Chỉ gửi allowlist field của HIGH/CRITICAL hoặc human-review alert; không gửi raw log, description, AI playbook hay webhook secret.
- Deduplicate bền vững theo incident/alert ID từ audit `SENT`; callback AI không tạo notification thứ hai.
- Timeout ngắn, tối đa ba lần thử theo cấu hình (mặc định hai); kết quả `SENT`/`FAILED` được audit JSONL không chứa URL.
- Regression, HTTP socket test trong image và live alert/Ollama đều pass; webhook tắt không tạo audit giả.

### Commit gợi ý

```text
feat: add webhook notifications for high-risk incidents
```

---

# Milestone M7 — Windows telemetry và Sysmon

## Mục tiêu

Bổ sung nguồn dữ liệu phù hợp với Blue Team Windows mà không yêu cầu Wazuh.

> Vì agent đang chạy trong Linux container, không nên giả định container có thể đọc trực tiếp Windows Event Log. Triển khai theo hai giai đoạn: offline/import trước, host collector sau.

---

## Batch M7.1 — Sysmon JSON/EVTX import

**Trạng thái:** ✅ Hoàn tất (2026-08-13)

### Nguồn ưu tiên

- Sysmon XML/JSON export.
- Windows Event Log export.
- EVTX offline dataset.

### Tasks

- [x] Import file offline.
- [x] Normalize Event ID.
- [x] Map process, parent process, command line, user, hashes, network fields.
- [x] Không yêu cầu realtime ở batch đầu.

### Xác nhận hoàn tất

- Import offline từ JSON, JSONL/NDJSON, XML và EVTX; lưu telemetry chuẩn hoá dưới dạng JSONL riêng.
- Hỗ trợ 9 Event ID ưu tiên: Sysmon 1, 3, 7, 10, 11, 13 và Windows 4624, 4625, 4688.
- Chuẩn hoá process, parent process, command line, user, hashes, network, file, registry và logon; chống nhập trùng bằng event UID ổn định.
- Đọc EVTX đa nền tảng bằng `python-evtx`; batch này không thêm realtime collector và không đẩy event vào detection/AI.
- Test importer, nhánh EVTX, CLI, dedup và regression hiện có đều pass.

### Event IDs ưu tiên

- Sysmon 1 — Process Create.
- Sysmon 3 — Network Connection.
- Sysmon 7 — Image Load.
- Sysmon 10 — Process Access.
- Sysmon 11 — File Create.
- Sysmon 13 — Registry Value Set.
- Windows 4624 — Successful Logon.
- Windows 4625 — Failed Logon.
- Windows 4688 — Process Creation.

### Commit gợi ý

```text
feat: import and normalize Windows Sysmon events
```

---

## Batch M7.2 — Windows host collector

**Trạng thái:** ✅ Hoàn tất (2026-08-13)

### Kiến trúc đề xuất

```text
Windows collector process
→ HTTP/JSON or shared file
→ Mini-SIEM agent/dashboard
```

### Tasks

- [x] Collector chạy trực tiếp trên Windows host.
- [x] Không cần privileged Linux container.
- [x] Batch hoặc stream events.
- [x] Shared secret giữa collector và Mini-SIEM.
- [x] Retry và local buffer.
- [x] Collector không gửi toàn bộ historical log mỗi lần restart.

### Xác nhận hoàn tất

- PowerShell collector dùng `Get-WinEvent` trực tiếp trên Windows cho Sysmon và Security Event ID ưu tiên; không thêm container đặc quyền.
- Hỗ trợ chạy liên tục theo batch hoặc `-Once`, retry hữu hạn và buffer cục bộ tại `%ProgramData%\Mini-SIEM` khi endpoint không sẵn sàng.
- Endpoint `POST /api/windows-events` dùng shared secret, constant-time comparison, giới hạn 500 events/2 MiB và mặc định tắt khi chưa cấu hình secret.
- Cursor riêng theo channel được khởi tạo tại record mới nhất và lưu sau mỗi batch, nên restart không gửi lại toàn bộ historical log; dedup phía server bảo vệ khi retry.
- Test endpoint/auth/limit/dedup, cú pháp và first-run collector trên Windows, toàn bộ regression M5–M7.2 đều pass.

### Commit gợi ý

```text
feat: add lightweight Windows event collector
```

---

## Batch M7.3 — Windows detection rules

**Trạng thái:** ✅ Hoàn tất (2026-08-13)

### Use cases

- Encoded PowerShell.
- Suspicious LOLBins:
  - `certutil`
  - `rundll32`
  - `regsvr32`
  - `mshta`
- Account creation.
- Scheduled task creation.
- Defender tampering.
- Credential dumping indicators.
- Abnormal parent-child process.

### Xác nhận hoàn tất

- Thêm 7 YAML rules cho encoded PowerShell, LOLBins với tham số đáng ngờ, account/task creation, Defender tampering, LSASS access và Office child process.
- Mở rộng normalize/collector cho Security 4698, 4720 và Defender 5007; bổ sung target process, scheduled task và Defender setting fields.
- Agent tail Windows JSONL từ cuối file, không replay historical telemetry; alert dùng chung rule engine, lifecycle, correlation, notification và một AI worker hiện có.
- `WINDOWS_EVENT` được hỗ trợ trong schema, correlation/graph và detection coverage; telemetry sạch/LOLBin hợp lệ không tạo alert.
- Test đủ 7 rules, negative cases, agent tail-file, importer/collector và toàn bộ regression M5–M7.3 đều pass.

### Commit gợi ý

```text
feat: add Windows and Sysmon detection rules
```

---

# Milestone M8 — Dashboard security, observability và reliability

## Batch M8.1 — Dashboard authentication

**Trạng thái:** ✅ Hoàn tất (2026-08-13)

### Scope

- Login/logout.
- Password hash.
- Session hoặc JWT.
- Role tối thiểu:
  - viewer
  - analyst
  - admin

### Permissions

| Action | Viewer | Analyst | Admin |
|---|---:|---:|---:|
| View alerts | ✅ | ✅ | ✅ |
| Add notes | ❌ | ✅ | ✅ |
| Change status | ❌ | ✅ | ✅ |
| Approve response | ❌ | ✅ | ✅ |
| Change settings | ❌ | ❌ | ✅ |

### Xác nhận hoàn tất

- Flask session 8 giờ với persistent random signing key, cookie HttpOnly/SameSite=Strict và tuỳ chọn Secure khi triển khai HTTPS.
- Tài khoản lưu bằng Werkzeug password hash trong `data/dashboard_users.json`; CLI tạo/cập nhật hỗ trợ đủ role viewer, analyst và admin.
- Mọi page/read API yêu cầu login; collector giữ shared-secret auth riêng. Mọi session mutation yêu cầu CSRF token.
- Viewer chỉ xem, analyst/admin quản lý incident và response, chỉ admin truy cập/thay đổi settings; actor note/approve/rollback lấy từ session.
- Login throttling, session invalidation khi user bị xoá, no-store/security headers và debug mode tắt.
- Auth/role/CSRF/hash tests và toàn bộ regression M5–M8.1 đều pass trong image cuối.

### Commit gợi ý

```text
feat: add dashboard authentication and analyst roles
```

---

## Batch M8.2 — Audit log

**Trạng thái:** ✅ Hoàn tất (2026-08-14)

### Audit events

- Login/logout.
- Status change.
- Note added.
- Assignment.
- Response requested/approved/executed.
- Rule enabled/disabled.
- Runtime setting changed.

### Xác nhận hoàn tất

- Audit analyst được ghi JSONL theo kiểu append-only; mỗi event có ID, UTC timestamp, actor/role, target, outcome và metadata allowlist.
- Chuỗi SHA-256 nối `previous_hash`/`entry_hash` phát hiện bản ghi bị sửa, xoá hoặc chèn giữa chuỗi; verifier từ chối chuỗi không hợp lệ.
- Login/logout, status, note, assignment, response request/approval/execution/rollback và runtime settings đều audit sau mutation thành công; login bị từ chối/chặn cũng được ghi outcome riêng.
- Rule YAML có công cụ enable/disable dành cho admin và ghi audit cùng actor; cập nhật file theo kiểu atomic replace.
- Audit không lưu mật khẩu, nội dung analyst note hoặc response target nhạy cảm; details bị giới hạn 8 KiB.
- Test chuyên biệt, tamper test và toàn bộ regression M5–M8.2 đều pass trên image cuối; live dashboard trả 401 khi chưa xác thực và audit chain hợp lệ.

### Commit gợi ý

```text
feat: add immutable analyst audit log
```

---

## Batch M8.3 — Health and diagnostics

**Trạng thái:** ✅ Hoàn tất (2026-08-14)

### Endpoints đề xuất

```http
GET /health
GET /api/system/status
```

### Status cần hiển thị

- Agent heartbeat.
- Dashboard status.
- Alert store status.
- Ollama provider availability.
- Last successful AI enrichment.
- Queue/backlog.
- NIDS enabled/disabled.
- Honeypot enabled/disabled.
- Database health.

### Xác nhận hoàn tất

- `GET /health` công khai metadata tối thiểu cho health check; trả `503` khi database hoặc alert store unhealthy, và `200` cho healthy/degraded.
- `GET /api/system/status` chỉ dành cho admin, trả chi tiết dashboard, agent, alert store, SQLite, AI, queue và sensors.
- Agent ghi heartbeat atomic mỗi 5 giây; dashboard đánh dấu stale sau 15 giây và hiển thị tuổi heartbeat.
- SQLite dùng `PRAGMA quick_check(1)`; alert store được kiểm tra độc lập và trả tổng số alert.
- AI diagnostics hiển thị provider/model, trạng thái enabled/available, lần thành công/thất bại gần nhất, worker busy và backlog; không probe Ollama nên không chiếm call AI duy nhất.
- NIDS/honeypot hiển thị cả trạng thái cấu hình và trạng thái thực tế từ agent.
- Test healthy/degraded/unhealthy, role permissions, heartbeat stale, AI telemetry và toàn bộ regression M5–M8.3 đều pass; live `/health` trả healthy.

### Commit gợi ý

```text
feat: add service health and diagnostics endpoints
```

---

## Batch M8.4 — Retention và backup

**Trạng thái:** ✅ Hoàn tất (2026-08-14)

### Tasks

- [x] Config retention days.
- [x] Archive old alerts.
- [x] SQLite backup command.
- [x] Không xóa incident đang mở.
- [x] Log rotation.
- [x] Document restore procedure.

### Xác nhận hoàn tất

- `ALERT_RETENTION_DAYS` mặc định 90 ngày; CLI maintenance nhận override theo command line hoặc `.env`.
- Retention tạo SQLite online backup có `integrity_check`, ghi archive JSONL atomic trước khi xóa và đồng bộ JSON mirror sau khi transaction commit.
- Incident `NEW`, `INVESTIGATING`, `CONTAINED`, alert mới và timestamp lỗi đều được bảo toàn; chỉ alert thường hoặc incident terminal cũ được archive.
- SQLite checkpoint/VACUUM sau khi xóa; backup riêng chạy qua `python -m tools.maintenance backup`.
- Rotation copy-truncate tối đa 5 bản cho auth, Windows events, response và notification logs; immutable analyst audit log được loại trừ.
- `docs/RETENTION_BACKUP.md` mô tả quy trình stop service, backup, retention, rotation, full restore, WAL/SHM safety và archive restore.
- Test archive/restore/open-incident protection/rotation và toàn bộ regression M5–M8.4 đều pass; live health và backup smoke test trên image cuối đều pass.

### Commit gợi ý

```text
feat: add alert retention and database backup workflow
```

---

# Milestone M9 — Release, documentation và portfolio demo

## Batch M9.1 — README synchronization

**Trạng thái:** ✅ Hoàn tất (2026-08-15)

### Cần cập nhật

- [x] Thay tài liệu Groq cũ bằng Ollama Cloud.
- [x] Cập nhật `.env.example`.
- [x] Cập nhật architecture diagram.
- [x] Cập nhật AI output fields.
- [x] Cập nhật severity decision model.
- [x] Cập nhật screenshot.
- [x] Ghi rõ Windows/Docker NIDS limitations.
- [x] Ghi rõ response mặc định là simulation.

### Xác nhận hoàn tất

- README phản ánh đúng Ollama Cloud, kiến trúc hiện tại, AI contract và mô hình quyết định severity.
- Quick start, authentication/RBAC, SQLite/JSON, health, maintenance và safe response đã được đồng bộ với mã nguồn.
- Giới hạn Windows collector và packet capture trên Windows/Docker Desktop đã được nêu rõ.
- `.env.example` chỉ còn các biến cấu hình đang được sử dụng; các biến provider cũ đã được loại bỏ.
- Screenshot dashboard thật đã được cập nhật từ phiên viewer có xác thực.
- Kiểm tra liên kết nội bộ, cấu hình mẫu và định dạng tài liệu đều pass.

### Commit gợi ý

```text
docs: update architecture and Ollama Cloud setup
```

---

## Batch M9.2 — Demo scenario

**Trạng thái:** ⬜

### Demo end-to-end đề xuất

```text
1. Inject SSH failed-login campaign.
2. Threshold detector tạo HIGH alert.
3. Correlator tổng hợp event_count.
4. Ollama Cloud phân tích.
5. AI đề xuất CRITICAL + human review.
6. System severity vẫn giữ HIGH.
7. Analyst mở incident.
8. Analyst thêm note.
9. Analyst chuyển INVESTIGATING.
10. Analyst request BLOCK_IP simulation.
11. Action được audit.
12. Incident chuyển RESOLVED.
```

### Artifacts

- Screenshot dashboard.
- Sample alert JSON.
- Sample AI analysis.
- Incident timeline.
- Response audit.
- Kiến trúc diagram.
- Demo commands.

### Commit gợi ý

```text
docs: add end-to-end Blue Team demo scenario
```

---

## Batch M9.3 — Versioned release

**Trạng thái:** ⬜

### Tasks

- [ ] Chọn semantic version.
- [ ] Tạo `CHANGELOG.md`.
- [ ] Tag release.
- [ ] Ghi known limitations.
- [ ] Ghi setup from clean clone.
- [ ] Xác nhận không có secret trong Git history gần nhất.

### Release goal đề xuất

```text
v0.3.0 — Ollama Cloud + Incident Workflow + SQLite
```

---

# 5. Backlog tùy chọn

Các mục này không chặn roadmap chính:

- [ ] Automated unit tests.
- [ ] GitHub Actions CI.
- [ ] Sigma import.
- [ ] STIX/TAXII threat intelligence.
- [ ] AbuseIPDB/VirusTotal enrichment.
- [ ] GeoIP enrichment.
- [ ] Asset inventory.
- [ ] Multi-tenant support.
- [ ] TheHive/Jira integration.
- [ ] PDF incident report.
- [ ] Prometheus metrics.
- [ ] Local Ollama fallback.
- [ ] Multi-provider AI abstraction.
- [ ] Role-specific dashboard layouts.

---

# 6. Thứ tự thực hiện được khuyến nghị

Không làm nhiều milestone song song. Follow theo thứ tự:

```text
M3 Incident Lifecycle
→ M4 SQLite
→ M5 Rule Management
→ M6 Response Simulation
→ M7 Windows/Sysmon
→ M8 Security/Reliability
→ M9 Release
```

## Batch nên bắt đầu ngay

```text
M9.2 — Demo scenario
```

Lý do:

- Milestone M6 đã hoàn tất safe action contract, simulation, manual approval và webhook notification.
- Notifications có dedup, bounded retry, payload allowlist và audit kết quả; mặc định không gửi ra ngoài.
- M7.1 đã hoàn tất import/chuẩn hoá Windows event offline, gồm JSON, XML và EVTX.
- M7.2 đã hoàn tất collector native Windows, shared-secret ingest, retry/buffer và cursor chống gửi lại lịch sử.
- M7.3 đã hoàn tất Windows/Sysmon detection và nối telemetry vào agent dùng chung AI worker.
- Milestone M7 đã hoàn tất; M8.1 đã hoàn tất dashboard session authentication và role permissions.
- M8.2 đã hoàn tất immutable analyst audit log cho các thao tác bảo mật và vận hành quan trọng.
- M8.3 đã hoàn tất health endpoints, agent heartbeat và diagnostics cho storage, AI queue và sensors.
- M8.4 đã hoàn tất retention, archive, SQLite backup, log rotation và restore procedure; Milestone M8 đã hoàn tất.
- M9.1 đã hoàn tất đồng bộ README, cấu hình mẫu, screenshot và các giới hạn vận hành.
- M9.2 là batch kế tiếp nhưng chưa bắt đầu theo nguyên tắc dừng sau mỗi batch.

---

# 7. Template tracking cho mỗi batch

Sao chép block này khi bắt đầu một batch:

```markdown
## Batch <ID> — <Tên>

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
- [ ] ...

### Manual verification

- [ ] Syntax check pass.
- [ ] Docker build pass.
- [ ] Service Up.
- [ ] API smoke check pass.
- [ ] Dashboard smoke check pass.
- [ ] No secret committed.
- [ ] Working tree clean after commit.

### Notes / Decisions

- ...

### Known issues

- ...
```

---

# 8. Checklist trước mỗi commit

```powershell
git status --short
git diff
git check-ignore .env
```

- [ ] Không có `.env`.
- [ ] Không có API key.
- [ ] Không commit `logs/auth.log`.
- [ ] Không commit generated alert data ngoài chủ đích.
- [ ] Không commit model artifacts mới ngoài chủ đích.
- [ ] Python syntax pass.
- [ ] JavaScript syntax pass nếu sửa JS.
- [ ] Docker service liên quan build và chạy được.
- [ ] Commit message chỉ mô tả một batch.

---

# 9. Checklist smoke verification chung

## Python

```powershell
docker compose exec agent python -m py_compile /app/main.py
docker compose exec agent python -m py_compile /app/src/ai_analyst.py
```

## JavaScript

```powershell
node --check static/js/app.js
```

## Docker

```powershell
docker compose up -d --build --force-recreate agent dashboard
docker compose ps
docker compose logs --tail=100 agent
docker compose logs --tail=100 dashboard
```

## API

```powershell
Invoke-RestMethod http://localhost:5000/api/alerts
```

## Dashboard

```text
http://localhost:5000/logs
```

## Git

```powershell
git status
```

Expected:

```text
nothing to commit, working tree clean
```

---

# 10. Decision log

| Date | Decision | Reason |
|---|---|---|
| 2026-08 | Không dùng Wazuh/Shuffle | Hạn chế dung lượng và tài nguyên máy |
| 2026-08 | Giữ Docker | Repo gốc đã dùng Docker và vẫn phù hợp máy |
| 2026-08 | Dùng Ollama Cloud | Không tải local model, không phụ thuộc Groq |
| 2026-08 | Model `gemma4:cloud` | Đã xác nhận API trả HTTP 200 |
| 2026-08 | AI không sửa system severity | Detection/risk engine giữ quyền quyết định |
| 2026-08 | Manual smoke checks trước | Phù hợp workflow hiện tại; automated tests để backlog |
| 2026-08 | SQLite triển khai sau incident schema | Tránh migration khi data contract chưa ổn định |

---

# 11. Definition of Project Completion

Project được xem là đạt một phiên bản Blue Team portfolio hoàn chỉnh khi:

- [ ] HIDS/NIDS/Honeypot tạo alert theo schema chung.
- [ ] Correlation giảm alert trùng và tổng hợp campaign.
- [ ] AI triage hoạt động nhưng không tự thay đổi quyết định hệ thống.
- [x] Analyst có thể quản lý lifecycle incident.
- [x] Analyst có thể ghi notes và assignment.
- [ ] Storage dùng SQLite và có migration.
- [ ] Detection rules có ID, MITRE mapping và enable/disable.
- [ ] Response action mặc định simulation và có audit.
- [ ] Có ít nhất một Windows/Sysmon ingestion path.
- [ ] Dashboard có authentication.
- [ ] Có health/diagnostics.
- [ ] Có demo end-to-end tái tạo được từ clean clone.
- [ ] README và `.env.example` phản ánh đúng implementation.
- [ ] Không có secret trong repository.
