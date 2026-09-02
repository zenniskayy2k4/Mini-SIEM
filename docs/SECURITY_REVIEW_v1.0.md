# Mini-SIEM Security Review — v1.0.0

> **Scope:** authentication, authorization, CSRF, session lifecycle, file/path
> handling, external HTTP, webhook boundaries, PDF output, collector endpoint,
> YAML/Sigma parsing, STIX/TAXII parsing, secrets, backup/restore, audit
> integrity, and response safety.
>
> **Method:** code-grounded review against the feature-freeze baseline.
> Findings reference the v1.0.0 candidate source. No live credentials,
> real secrets, or production data were accessed during this review.
>
> **Date:** 2026-09-02 — maps to roadmap milestone **M30.4**.

---

## 1. Authentication

### Controls

- Passwords are hashed with Werkzeug scrypt (memory-hard KDF) via
  `generate_password_hash` / `check_password_hash`
  (`src/dashboard_auth.py:14,114,165`).
- Minimum password length of 12 characters and maximum of 256
  (`src/dashboard_auth.py:108-109`).
- Invalid usernames are checked against a fixed dummy hash with
  `check_password_hash` to prevent user-enumeration timing oracles
  (`src/dashboard_auth.py:163-165`).
- Usernames are restricted to `^[A-Za-z0-9_.-]{1,64}$`
  (`src/dashboard_auth.py:22,104`).
- Login throttling: 5 failures per IP per 60-second window
  (`src/dashboard_auth.py:197-210`).
- Session secret requires at least 32 characters; auto-generated and stored in
  a `chmod 0o600` file when not provided (`src/dashboard_auth.py:64-77`).
- Session cookies use `HttpOnly`, `SameSite=Strict`, and a configurable
  `Secure` flag (`src/dashboard_auth.py:74-76`).

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| AUTH-1 | Info | Login throttling state is process-local and resets on restart (`src/dashboard_auth.py:196`). | Acceptable for single-node; for multi-instance deployments use a shared rate-limit store. |
| AUTH-2 | Info | No escalating lockout beyond the per-minute window. | Add exponential backoff if persistent brute force is observed in production. |

---

## 2. Authorization / RBAC

### Controls

- Three-role hierarchy: `viewer` (1), `analyst` (2), `admin` (3)
  (`src/dashboard_auth.py:21`).
- `role_required` decorator enforces a numeric role comparison and returns HTTP
  403 on insufficient privilege (`src/dashboard_auth.py:185-193`).
- A global `before_request` hook authenticates and validates CSRF on every
  request except the explicit whitelist (login, static, collector, health,
  metrics) (`dashboard.py:466-480`).
- The user's role is re-read from the user store on each request rather than
  trusted from the session cookie (`dashboard.py:477`).
- Admins cannot demote or delete themselves
  (`dashboard.py:694-695,719-720`).

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| RBAC-1 | Info | Read-only endpoints (`api_alerts`, search, stats, KPIs, coverage) are accessible to any authenticated user. | Intentional viewer read model; documented so it is not mistaken for a gap. |

---

## 3. CSRF

### Controls

- CSRF token is 32-byte `secrets.token_urlsafe(32)` stored per session
  (`src/dashboard_auth.py:176`).
- Validation compares the `X-CSRF-Token` header or `csrf_token` form field with
  `secrets.compare_digest` (`src/dashboard_auth.py:179-182`).
- Enforced globally on all non-GET/HEAD/OPTIONS requests
  (`dashboard.py:478-479`), including the login endpoint (`dashboard.py:513`).
- `SameSite=Strict` cookie provides a second layer of CSRF defense.

### Findings

None. CSRF protection is present and enforced at the platform boundary.

---

## 4. Session Lifecycle

### Controls

- Session maximum lifetime is 8 hours (`src/dashboard_auth.py:73`).
- Session is cleared on logout (`dashboard.py:544`) and on auth-version
  mismatch (`dashboard.py:475`).
- Sessions are regenerated on login (clear + update) to prevent fixation
  (`dashboard.py:529-535`).
- Logout is POST-only.

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| SESS-1 | Info | No separate idle timeout; only the 8-hour absolute lifetime. | Consider an idle timeout for high-sensitivity deployments. |

---

## 5. File / Path Handling

### Controls

- PDF download filenames are sanitized to `[A-Za-z0-9._-]` truncated to 120
  characters (`dashboard.py:880`).
- Backup verifies the source and destination paths differ via
  `resolve()` (`src/maintenance.py:31`).
- Response quarantine targets require absolute, resolved paths checked against
  protected targets including descendants (`src/response.py:89-101`).
- The HIDS watcher compares `normcase(abspath)` of the watched file against the
  event source to prevent symlink/traversal substitution (`src/handler.py:42-45`).
- Windows collector uses `-LiteralPath` exclusively
  (`tools/windows_event_collector.ps1:63,70,148`).

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| PATH-1 | Info | Runtime settings and user files are read from config-derived paths, not user input. | No user-controlled path is passed to file I/O at a trust boundary; no action required. |

---

## 6. External HTTP

### Controls

- Ollama URLs reject embedded credentials, query strings, and fragments; the
  cloud provider enforces HTTPS (`src/ai_provider.py:37-40,83`).
- GeoIP endpoint must be HTTPS; private IPs never leave the host
  (`src/threat_intel/geoip.py:13-25,38-39`).
- AbuseIPDB and VirusTotal enforce HTTPS and send keys via headers
  (`src/threat_intel/abuseipdb.py:44-59`, `src/threat_intel/virustotal.py:38`).
- All TI providers bound response sizes (64 KiB) and TAXII is capped at 5 MiB
  with a 10-page pagination limit (`src/threat_intel/geoip.py:10`,
  `src/threat_intel/stix.py:20,241,248-261`).
- Case connectors (TheHive/Jira) validate scheme and reject embedded
  credentials (`src/thehive.py:13-22`, `src/jira.py:17-25`), with bounded
  timeout (1–30 s) and attempts (1–3) (`src/case_connector.py:32-42`).
- TLS verification uses the platform `requests`/`urllib` defaults (on).

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| HTTP-1 | Low | No server-side SSRF allowlisting; a misconfigured integration URL could target internal hosts. | Validate outbound destinations against policy in production; configuration-time concern only. |
| HTTP-2 | Info | Local Ollama fallback uses plain HTTP, expected for localhost. | Keep local fallback bound to loopback. |

---

## 7. Webhook Boundaries

### Controls

- Webhook URL scheme restricted to `http`/`https`
  (`src/notifier.py:19-20`).
- Payload format whitelist (`generic` / `discord`) and a fixed field allowlist
  (`src/notifier.py:17-18,36-47`).
- Bounded timeout (default 3 s) and attempts (default 2)
  (`config/config.py:66-67`).
- Overload protection skips network sends during saturation
  (`src/notifier.py:71-72`).

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| WH-1 | Info | No outbound signature/HMAC; the receiver cannot verify Mini-SIEM as sender. | Add a shared-secret signature if receivers need origin authenticity. |

---

## 8. PDF Output

### Controls

- PDFs are hand-assembled as raw PDF objects with a built-in Helvetica font —
  no HTML engine, no browser, eliminating injection/XSS
  (`src/incident_report.py:153-188`).
- Non-ASCII text is normalized via NFKD and stripped (`src/incident_report.py:129-132`).
- PDF string escapes `\`, `(`, `)` (`src/incident_report.py:164`).
- All data passes through `redact_text()` before inclusion
  (`src/incident_report.py:5,23-93`).
- Report fields are allowlisted via a deterministic model; no freeform input
  (`src/incident_report.py:21-126`).
- Download `Content-Type` is `application/pdf` (`dashboard.py:882`).

### Findings

None material. PDF generation is injection-safe by construction.

---

## 9. Collector Endpoint

### Controls

- Authenticated via `X-Mini-SIEM-Secret` compared with `hmac.compare_digest`;
  endpoint is disabled when no secret is configured
  (`dashboard.py:911-916`).
- Request body limit 2 MiB (`dashboard.py:917-918`).
- Batch limit 500 events (`dashboard.py:930-931`).
- Protocol version strictly bounded (0 or 1) before processing
  (`src/ingestion_failures.py:92-103`).
- Event structure, XML validity, and priority IDs validated during
  normalization (`src/windows_events.py:193-207`).
- Deduplication via SHA-256 event UID (`src/windows_events.py:282-283`).
- Collector ID format constrained client-side and server-side
  (`tools/windows_event_collector.ps1:56-58`).

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| COL-1 | Low | Single shared secret authenticates all collectors; no per-collector identity. | Add per-collector credentials when fleet isolation is required. |

---

## 10. YAML / Sigma Parsing

### Controls

- YAML parsed with `yaml.safe_load` only
  (`src/rules.py:25,198`, `src/sigma/loader.py:62`).
- Rule schema validation enforces required fields, operator whitelist, and
  regex compilation (`src/rules.py:82-137`).
- Sigma schema validation enforces UUID format, level/status whitelists
  (`src/sigma/schema.py:14-67`).
- Sigma adapter `re.escape()`s all user-provided values in generated regexes
  (`src/sigma/adapter.py:85-107`).
- Unsupported Sigma conditions are skipped with a reason, never crashed
  (`src/sigma/adapter.py:152-154`).
- Rule writes are atomic (temp file + `os.replace`)
  (`src/rules.py:40-45`, `src/sigma/loader.py:38-43`).

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| YML-1 | Low | No ReDoS guard on admin-authored rule regexes; only admins author rules. | Keep rule files admin-controlled and review new rules before enablement. |

---

## 11. STIX / TAXII Parsing

### Controls

- STIX bundles parsed as JSON, never XML — no XXE surface
  (`src/threat_intel/stix.py:100,250`, `tools/import_stix.py:25`).
- Bundle type and object-list shape validated (`src/threat_intel/stix.py:128-132`).
- Indicator patterns restricted to a strict allowlist regex for IPv4, domains,
  and file hashes; IPv6 explicitly rejected
  (`src/threat_intel/stix.py:15-18,53-55,68-69`).
- TAXII URL scheme validated and credentials rejected
  (`src/threat_intel/stix.py:236-237`).
- Indicator store writes are atomic and thread-safe
  (`src/threat_intel/stix.py:93,116-125`).

### Findings

None material.

---

## 12. Secrets

### Controls

- Every persistent secret supports a `*_FILE` docker secret with mutual
  exclusion and a 64 KiB file limit (`config/secrets.py:18-39`).
- Secret files reject empty values, newlines, and null bytes; loaded via
  `Path.is_file()` (`config/secrets.py:28,37-38`).
- Nine secrets registered centrally (`config/secrets.py:4-14`).
- Redaction strips bearer tokens and secret-like key/value patterns in
  diagnostics and ingestion failures
  (`src/redaction.py:4-13`, `src/ingestion_failures.py:25-44`).
- `.env.example` ships with empty placeholder secrets only.

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| SEC-1 | Info | Redaction is regex-based; novel secret formats may escape patterns. | Extend patterns when new providers are added. |

---

## 13. Backup / Restore

### Controls

- Backups use the SQLite online backup API (consistent hot copy), not raw file
  copy (`src/maintenance.py:35-36`).
- Integrity is verified on the backup immediately after creation
  (`src/maintenance.py:37-38`).
- Backup and source paths are verified not to collide (`src/maintenance.py:31`).
- Migration runs pre/post integrity checks, dry-run mode, and auto-backup before
  writes (`tools/migrate_db.py:21-24,31,80`).
- Migration registry is version-contiguous with checksum verification
  (`tools/migrate_db.py:17-18,47-50`).
- Archive writes are atomic and fsynced (`src/maintenance.py:52-63`).

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| BAK-1 | Low | Backup files are not encrypted at rest. | Encrypt backups if they leave the host boundary. |

---

## 14. Audit Integrity

### Controls

- Entries form a SHA-256 hash chain: each record references the previous
  entry's hash and its own canonical key hash (`src/audit.py:104-106`).
- The chain starts from a fixed genesis hash (`src/audit.py:37`).
- Events are append-only under a write lock
  (`src/audit.py:38,93,107-108`).
- Event types are whitelisted; details bounded to 8 KiB
  (`src/audit.py:11-36,82-89`).
- Full-chain verification (`verify_audit_log`) walks and recomputes the chain
  (`src/audit.py:112-128`) and is surfaced in the admin workspace.

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| AUD-1 | Medium | Audit log is a local file; an attacker with filesystem access could truncate and forge a new chain. | For SOC-grade assurance, ship the log to append-only external storage (S3 object-lock, WORM). |
| AUD-2 | Info | Verification runs on demand, not continuously. | Periodically verify the chain via automation. |

---

## 15. Response Safety

### Controls

- `RESPONSE_MODE` defaults to `simulation` (`config/config.py:53`).
- Simulation mode never executes OS commands — it records status only
  (`src/response.py:108-113`).
- LLM-requested actions always require approval
  (`src/response.py:42-43`).
- Approvals expire after the configured timeout and expired approvals are
  rejected (`src/alert_store.py:162-178`).
- Protected targets include localhost, root, `/etc`, `/usr`, `/bin`, `/sbin`
  and more (`config/config.py:56-63`, `src/response.py:70-72`).
- IPs are validated (loopback/unspecified/multicast/link-local rejected),
  PIDs must be > 1, user names regex-checked, and quarantine paths must be
  absolute and outside protected trees (`src/response.py:74-101`).
- Targets may not contain null/newline characters and are length-bounded
  (`src/response.py:68`).

### Findings

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| RSP-1 | Info | No execution backends are implemented; even `manual`/`automatic` modes record rather than act. | Deliberate lab safety ceiling. Add execution handlers only with explicit authorization. |
| RSP-2 | Info | No separation of duties: the same analyst can request and approve their own action. | Require a second approver for sensitive actions if auto-response is enabled. |

---

## 16. Review Summary

| Area | Verdict |
|---|---|
| Authentication | ✅ Sound primitives with throttling and timing-oracle defense |
| Authorization / RBAC | ✅ Enforced at platform boundary with fresh role reads |
| CSRF | ✅ Global enforcement with constant-time comparison |
| Session lifecycle | ✅ Regeneration, revocation on mismatch, 8 h lifetime |
| File / path handling | ✅ No user-controlled path at trust boundaries |
| External HTTP | ✅ Scheme/credential validation, size bounds, TLS on |
| Webhook boundaries | ✅ Scheme whitelist, field allowlist, bounded retries |
| PDF output | ✅ Injection-safe by construction |
| Collector endpoint | ✅ Shared-secret auth, strict validation, size limits |
| YAML / Sigma parsing | ✅ Safe YAML, schema validation, escaping |
| STIX / TAXII parsing | ✅ JSON-only, pattern allowlist, size/pagination caps |
| Secrets | ✅ Env + file secrets, size/content validation, redaction |
| Backup / restore | ✅ Integrity-checked consistent backups |
| Audit integrity | ⚠️ Local hash chain sound; external WORM advised |
| Response safety | ✅ Simulation-first with protected targets |

**Overall:** no critical or high-severity findings. The strongest recommended
action is shipping the audit log to append-only external storage for SOC-grade
assurance. All other findings are low/info and configuration-time.

## 17. Sign-off

- Review baseline: feature-freeze commit `2de82ae` (M29.4 completion) + M30.1–M30.3 qualification.
- No secrets, credentials, or live data were exposed or accessed during review.
- The default deployment remains simulation-mode with response actions never
  executed and all AI analysis on the shared single-worker path.