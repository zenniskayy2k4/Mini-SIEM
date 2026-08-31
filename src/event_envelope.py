import hashlib
import json
import re
from copy import deepcopy

from src.alert_schema import SOURCE_TYPES, utc_iso


EVENT_SCHEMA_VERSION = 1
_EVENT_ID = re.compile(r"^EVT-[0-9a-f]{32}$")
_REQUIRED_FIELDS = {
    "event_schema_version", "event_id", "source_type", "collector_id",
    "received_at", "observed_at", "payload",
}


def normalize_collector_id(value) -> str:
    if not isinstance(value, str):
        raise ValueError("collector_id must be text")
    value = value.strip()
    if not value or len(value) > 128 or any(not character.isprintable() for character in value):
        raise ValueError("collector_id must contain 1 to 128 printable characters")
    return value


def _source_type(value) -> str:
    if not isinstance(value, str) or value.strip().upper() not in SOURCE_TYPES:
        raise ValueError("event source_type is invalid")
    return value.strip().upper()


def stable_event_id(payload: dict, source_type: str) -> str:
    if not isinstance(payload, dict):
        raise ValueError("event payload must be an object")
    source_type = _source_type(source_type)
    identity_payload = {
        key: value for key, value in payload.items()
        if key not in {"source_file", "imported_at"}
    }
    try:
        identity = json.dumps(
            {"source_type": source_type, "payload": identity_payload},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("event payload must contain JSON-compatible values") from exc
    return f"EVT-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:32]}"


def build_event_envelope(
    payload: dict, *, source_type: str, collector_id: str,
    observed_at=None, received_at=None,
) -> dict:
    source_type = _source_type(source_type)
    collector_id = normalize_collector_id(collector_id)
    if not isinstance(payload, dict):
        raise ValueError("event payload must be an object")
    payload = deepcopy(payload)
    observed_at = observed_at or payload.get("timestamp")
    if not observed_at:
        raise ValueError("observed_at is required")
    try:
        observed_at = utc_iso(observed_at)
        received_at = utc_iso(received_at)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("event timestamps must be valid ISO-8601 values") from exc
    return {
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "event_id": stable_event_id(payload, source_type),
        "source_type": source_type,
        "collector_id": collector_id,
        "received_at": received_at,
        "observed_at": observed_at,
        "payload": payload,
    }


def is_event_envelope(value) -> bool:
    return isinstance(value, dict) and "event_schema_version" in value


def validate_event_envelope(value: dict, expected_source_type=None) -> dict:
    if not isinstance(value, dict):
        raise ValueError("event envelope must be an object")
    missing = _REQUIRED_FIELDS - set(value)
    unknown = set(value) - _REQUIRED_FIELDS
    if missing:
        raise ValueError(f"event envelope is missing: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"event envelope has unsupported fields: {', '.join(sorted(unknown))}")
    if value["event_schema_version"] != EVENT_SCHEMA_VERSION:
        raise ValueError("unsupported event_schema_version")
    source_type = _source_type(value["source_type"])
    if expected_source_type and source_type != _source_type(expected_source_type):
        raise ValueError("event envelope source_type does not match the ingestion source")
    collector_id = normalize_collector_id(value["collector_id"])
    if not isinstance(value["payload"], dict):
        raise ValueError("event payload must be an object")
    expected_id = stable_event_id(value["payload"], source_type)
    if not isinstance(value["event_id"], str) or not _EVENT_ID.fullmatch(value["event_id"]):
        raise ValueError("event_id must use the EVT-<32 lowercase hex> format")
    if value["event_id"] != expected_id:
        raise ValueError("event_id does not match the normalized payload")
    try:
        received_at = utc_iso(value["received_at"])
        observed_at = utc_iso(value["observed_at"])
    except (TypeError, ValueError) as exc:
        raise ValueError("event timestamps must be valid ISO-8601 values") from exc
    return {
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "event_id": expected_id,
        "source_type": source_type,
        "collector_id": collector_id,
        "received_at": received_at,
        "observed_at": observed_at,
        "payload": value["payload"],
    }


def unwrap_event_envelope(value: dict, expected_source_type: str) -> tuple[dict, dict]:
    """Return source payload plus envelope metadata; accept pre-v1 flat events."""
    if is_event_envelope(value):
        envelope = validate_event_envelope(value, expected_source_type)
        return envelope["payload"], {key: envelope[key] for key in _REQUIRED_FIELDS - {"payload"}}
    if not isinstance(value, dict):
        raise ValueError("legacy event must be an object")
    envelope = build_event_envelope(
        value,
        source_type=expected_source_type,
        collector_id=str(value.get("source_file") or "legacy"),
        observed_at=value.get("timestamp"),
        received_at=value.get("imported_at") or value.get("timestamp"),
    )
    metadata = {key: envelope[key] for key in _REQUIRED_FIELDS - {"payload"}}
    metadata["event_schema_version"] = 0
    return value, metadata
