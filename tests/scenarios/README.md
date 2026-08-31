# Detection Validation Scenario Contract

Scenario manifests are YAML files below `tests/scenarios/`. They are validated offline and do not start runtime services or call AI, threat-intelligence, notification, response, or case-management providers.

## Manifest schema v1

Required top-level fields:

| Field | Contract |
|---|---|
| `schema_version` | Integer `1` |
| `id` | Unique `SCN-<UPPERCASE-NAME>-NNN` identifier |
| `title` | Non-empty title, at most 160 characters |
| `source` | `linux_auth`, `windows_event`, `network`, or `cross_source` |
| `events` | Fixture path relative to `tests/`; absolute paths and traversal outside `tests/` are rejected |
| `expected.rule_ids` | Unique rule-ID list; may be empty for a negative-only scenario |
| `expected.alert_count` | Non-negative `min` and `max`, with `min <= max` |
| `expected.severity` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `expected.fields` | Field constraints using `min`, `max`, `equals`, or `contains` |

Optional `rule_sources` selects `native`, `sigma`, or both; it defaults to both. This lets a corpus case validate Sigma provenance even when an equivalent native rule also exists.

Optional `negative_expectations.rule_ids` lists rules that must not match and cannot overlap positive rule IDs. Unknown fields, malformed YAML, missing fixtures, unsupported fixture types, duplicate scenario IDs, and manifests larger than 256 KiB fail validation.

Fixtures use JSON, JSONL/NDJSON, XML, log, or text files. JSONL cases carry ordered `relative_seconds` values so replay preserves deterministic timing without relying on the wall clock. Supported event payload keys are `message` for Linux authentication, `record` for Windows events, `packet` for network telemetry, and `alert` for cross-source correlation inputs.

Validate the repository corpus without starting a service:

```bash
python -m src.scenario_manifest tests/scenarios
```

Replay the corpus through existing rule paths without runtime services:

```bash
python tools/replay_scenario.py tests/scenarios
python tools/replay_scenario.py tests/scenarios --json
python tools/replay_scenario.py tests/scenarios --json-output scenario-replay.json
```

The replay engine disables ML model loading and never initializes AI, threat-intelligence, notification, response, or persistence components. It uses a temporary Sigma state file and emits only normalized expected fields; raw logs and source addresses are excluded from results. Replay output fields are restricted to `computer`, `correlation_type`, `event_count`, `mitre_attck_id`, `rule_source`, `sigma_rule_id`, `source_type`, `sources`, `suppressed_count`, `trigger_event_count`, `windows_event_id`, and `window_seconds`.

Generate the repository coverage matrix without reading runtime hit counts or runtime storage:

```bash
python tools/generate_validation_coverage.py
python tools/generate_validation_coverage.py --check
```

The committed artifacts are `docs/DETECTION_VALIDATION_COVERAGE.md` and `docs/DETECTION_VALIDATION_COVERAGE.json`.

GitHub Actions runs the human summary with `--json-output`, checks the committed coverage artifacts, and uploads the human/JSON replay reports only when the scenario gate fails. Provider credentials are empty for this step.
