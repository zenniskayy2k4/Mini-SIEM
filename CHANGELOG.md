# Changelog

All notable changes to Mini-SIEM are documented here. The project follows semantic versioning while remaining pre-1.0.

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
