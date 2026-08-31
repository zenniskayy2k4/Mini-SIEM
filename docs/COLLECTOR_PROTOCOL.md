# Collector Ingestion Protocol

The Windows collector delivers event batches and heartbeats to
`POST /api/windows-events` using the shared `X-Mini-SIEM-Secret` header.
This document is the compatibility contract for the collector payload
protocol.

## Protocol version field

| Field | Required | Contract |
|---|:---:|---|
| `protocol_version` | No | Integer protocol version of the collector payload. When omitted the payload is treated as legacy version `0`. |

Version `1` payloads carry everything introduced since v0.7.0: stable
`collector_id` identity, `collector_version`, `hostname`, `source_type`,
idle/endpoint-availability heartbeats, and bounded `buffer_diagnostics`.

## Compatibility matrix

| Collector build | `protocol_version` sent | Server behavior |
|---|---|---|
| Pre-v0.9.0 collector (field absent) | absent → negotiated `0` | Accepted as legacy; all existing behavior preserved. |
| v0.9.0 collector | `1` | Accepted; response echoes `protocol_version: 1`. |
| Future collector speaking a newer protocol | `> 1` | Rejected with HTTP 400 and an explicit `unsupported collector protocol_version N; this server supports up to 1` error. |

Invalid values (non-integer, boolean, negative) are rejected with HTTP 400
and a clear error message.

## Rules

- Legacy version `0` remains permanently supported; the server never
  requires the field, so older collectors keep working across upgrades.
- A collector that sends an unsupported future version must fail clearly
  instead of being silently misparsed. Upgrade the server before rolling out
  a collector that uses a newer protocol version.
- The successful response echoes the negotiated `protocol_version` so
  operators can confirm compatibility without reading collector state.

## Related contracts

- Event envelope versioning: [EVENT_ENVELOPE.md](EVENT_ENVELOPE.md)
- Collector identity and duplicate-hostname warnings (M27.1)
- Buffer diagnostics and delivery metrics (M27.2)
