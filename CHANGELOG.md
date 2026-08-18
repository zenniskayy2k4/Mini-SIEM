# Changelog

All notable changes to Mini-SIEM are documented here. The project follows semantic versioning while remaining pre-1.0.

## [Unreleased]

### Added

- SQLite-backed asset inventory data model with stable IDs, normalized hostname/IP lookup, duplicate constraints, CRUD operations, and immutable audit events.
- Responsive admin asset management UI and CSRF-protected API with search, environment/state/criticality filters, ownership, tags, and bounded validation.
- Fail-open alert enrichment with a compact `asset_id` reference and admin dashboard links to matching inventory records.

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

See the [v0.4.0 release checklist](docs/RELEASE_v0.4.0.md) for setup, verification details, upgrade notes, and known limitations.

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

See the [v0.3.0 release checklist](docs/RELEASE_v0.3.0.md) for setup, verification details, and known limitations.
