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
| `expected.rule_ids` | Non-empty unique rule-ID list |
| `expected.alert_count` | Non-negative `min` and `max`, with `min <= max` |
| `expected.severity` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `expected.fields` | Field constraints using `min`, `max`, `equals`, or `contains` |

Optional `negative_expectations.rule_ids` lists rules that must not match and cannot overlap positive rule IDs. Unknown fields, malformed YAML, missing fixtures, unsupported fixture types, duplicate scenario IDs, and manifests larger than 256 KiB fail validation.

Fixtures use JSON, JSONL/NDJSON, XML, log, or text files. JSONL cases carry `relative_seconds` so the later replay engine can preserve deterministic event ordering without relying on wall-clock timestamps.

Validate the repository corpus without starting a service:

```bash
python -m src.scenario_manifest tests/scenarios
```

Replay the corpus through existing rule paths without runtime services:

```bash
python tools/replay_scenario.py tests/scenarios
python tools/replay_scenario.py tests/scenarios --json
```

The replay engine disables ML model loading and never initializes AI, threat-intelligence, notification, response, or persistence components. It uses a temporary Sigma state file and emits only normalized expected fields; raw logs and source addresses are excluded from results. Replay output fields are restricted to `computer`, `correlation_type`, `event_count`, `mitre_attck_id`, `rule_source`, `sigma_rule_id`, `source_type`, `suppressed_count`, `windows_event_id`, and `window_seconds`.
