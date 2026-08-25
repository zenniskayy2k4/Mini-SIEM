# Event Envelope v1

Normalized telemetry is stored and exchanged in a versioned envelope before detection:

```json
{
  "event_schema_version": 1,
  "event_id": "EVT-0123456789abcdef0123456789abcdef",
  "source_type": "WINDOWS_EVENT",
  "collector_id": "win-lab",
  "received_at": "2026-08-25T09:00:05Z",
  "observed_at": "2026-08-25T09:00:00Z",
  "payload": {}
}
```

## Field contract

| Field | Required | Contract |
|---|:---:|---|
| `event_schema_version` | Yes | Integer `1`. Consumers reject unsupported versions. |
| `event_id` | Yes | Stable `EVT-` ID derived from normalized source type and payload identity. |
| `source_type` | Yes | One supported Mini-SIEM source type, currently `WINDOWS_EVENT` at this normalization boundary. |
| `collector_id` | Yes | 1-128 printable characters identifying the producing collector/source. |
| `received_at` | Yes | UTC ISO-8601 time when Mini-SIEM accepted the event. |
| `observed_at` | Yes | UTC ISO-8601 time when the source observed the activity. |
| `payload` | Yes | JSON object containing source-specific normalized fields. |

There are no optional v1 envelope fields. Fields inside `payload` are source-specific: Windows `event_id`, `timestamp`, `event_uid`, `process`, `network`, and similar evidence remain optional according to the event type. The payload `schema_version` describes the Windows mapping; `event_schema_version` describes the outer transport contract.

## Identity and compatibility

- `event_id` excludes receive time and collector ID, so retries and buffered delivery retain one identity.
- Windows payloads reuse their deterministic `event_uid` when deriving the envelope ID.
- Existing flat Windows JSONL records remain readable and are treated as legacy schema version `0` in generated alerts.
- Newly imported or continuously collected Windows events are written as v1 envelopes.
- The collector API accepts the new `collector_id` field and the legacy `source` alias during migration.

Envelope validation rejects missing or unknown fields, unsupported versions, invalid timestamps/source types, non-object payloads, control characters in collector identity, and IDs that do not match the normalized payload.
