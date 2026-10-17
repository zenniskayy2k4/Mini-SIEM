# Alert Schema v1

Every alert returned by the supported REST API carries
`"alert_schema_version": 1`. The version describes the persisted alert payload,
not the event envelope or collector transport protocol.

## Core field contract

| Field | Type | Nullable | Semantics |
|---|---|:---:|---|
| `alert_schema_version` | integer | No | Current alert payload version; always `1` after normalization. |
| `alert_id` | string | No | Stable `ALT-...` identifier. |
| `timestamp` | UTC timestamp | No | Time the source evidence was observed. |
| `alert_name` | string | No | Human-readable detection title. |
| `severity` | enum | No | Authoritative detector severity. AI recommendations never overwrite it. |
| `status` | enum | No | Detection processing state. |
| `source_type` | enum | No | Source family that produced the alert. |
| `description` | string | No | Evidence-grounded detection summary. |
| `raw_log` | string | Yes | Original evidence when safe and available. |
| `ip_address` | string | Yes | Primary source/subject IP used by correlation and enrichment. |
| `mitre_attck_id` | string | Yes | MITRE ATT&CK technique identifier. |
| `event_count` | integer | No | Number of events represented by the alert. |
| `first_seen` | UTC timestamp | No | First event in the detection/correlation window. |
| `last_seen` | UTC timestamp | No | Latest event in the detection/correlation window. |
| `correlation_key` | string | Yes | Stable grouping key used for deduplication/correlation. |
| `ml_confidence` | number | Yes | Local model confidence; not an LLM confidence value. |
| `rule_id` | string | Yes | Native or Sigma detection rule identifier. |
| `rule_source` | enum | Yes | Rule implementation family. |
| `sigma_rule_id` | UUID string | Yes | Sigma identifier; present when `rule_source` is `sigma`. |
| `asset_id` | string | Yes | Matched managed asset identifier. |
| `risk_score` | integer | No | Deterministic score from 0 through 100. |
| `risk_level` | enum | No | Bucket derived from `risk_score`. |
| `risk_factors` | array | No | Deterministic factor/point explanations for the risk score. |

## AI, intelligence, and incident fields

| Field | Type | Nullable | Semantics |
|---|---|:---:|---|
| `ai_analysis` | object | Yes | Bounded analyst enrichment or an explicit unavailable/skipped result. |
| `ai_recommended_severity` | enum | Yes | Non-authoritative AI recommendation. |
| `ai_disposition` | enum | Yes | AI triage recommendation requiring analyst judgment. |
| `incident_id` | string | Yes | `INC-...` identifier when the alert is incident-worthy. |
| `incident_status` | enum | Yes | Analyst lifecycle state; null when no incident exists. |
| `assigned_to` | string | Yes | Current analyst identity. |
| `analyst_notes` | array | No | Ordered analyst notes. |
| `timeline` | array | No | Ordered incident workflow events. |
| `response_actions` | array | No | Proposed/simulated/approved response records. |
| `external_cases` | object | No | Provider-keyed external case references. |

Provider, sensor, and correlation extensions such as `threat_intel`, `geoip`,
`correlated_events`, `suppressed_count`, and Windows event metadata may be
present. Consumers must ignore extension fields they do not understand.
`detection_feedback` is a nullable read-time relation and is omitted when no
feedback exists.

## Enums

| Field | Values |
|---|---|
| `severity`, `ai_recommended_severity`, `risk_level` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `status` | `DETECTED`, `EXCEPTED` |
| `source_type` | `HIDS_LOG`, `WINDOWS_EVENT`, `NIDS`, `HONEYPOT`, `CORRELATION` |
| `incident_status` | `NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE` |
| `rule_source` | `native`, `sigma` |
| `ai_disposition` | `REQUIRES_HUMAN_REVIEW`, `FALSE_POSITIVE_SUSPECTED` |

Nullable enum fields may be JSON `null`; placeholder strings such as `N/A`,
`Unknown`, or an empty string are not part of the contract.

## Compatibility policy

| Persisted value | Read behavior |
|---|---|
| Field absent or integer `0` | Treated as legacy, normalized in memory to v1. |
| Integer `1` | Accepted as the current contract. |
| Any future/negative integer | Rejected clearly; upgrade the server first. |
| Boolean, string, float, or null | Rejected as an invalid version type. |

Legacy normalization generates a deterministic UUID5 alert ID when missing,
maps legacy `INFO` severity to `LOW`, removes obsolete mitigation-command
fields, defaults a missing event count to `1`, uses `timestamp` for missing
event-window bounds, and supplies lifecycle/list defaults. Reads do not rewrite
historical JSONL or SQLite payloads; the next normal update persists the v1
form. New alerts are always written as v1. No database schema migration is
required.
