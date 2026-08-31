from copy import deepcopy

from src.event_envelope import (
    build_event_envelope, stable_event_id, unwrap_event_envelope,
    validate_event_envelope,
)


def _reject(value, message):
    try:
        validate_event_envelope(value, "WINDOWS_EVENT")
        raise AssertionError("Invalid envelope was accepted")
    except ValueError as exc:
        assert message in str(exc)


def test_versioned_event_envelope():
    payload = {
        "schema_version": 1,
        "event_uid": "WINEVT-stable-fixture",
        "event_id": 4625,
        "timestamp": "2026-08-25T09:00:00Z",
        "computer": "win-lab",
        "network": {"source_ip": "192.0.2.10"},
    }
    first = build_event_envelope(
        payload, source_type="windows_event", collector_id="win-lab",
        received_at="2026-08-25T09:00:05Z",
    )
    second = build_event_envelope(
        payload, source_type="WINDOWS_EVENT", collector_id="backup-collector",
        received_at="2026-08-25T09:00:30Z",
    )
    assert first["event_schema_version"] == 1
    assert first["event_id"] == second["event_id"] == stable_event_id(payload, "WINDOWS_EVENT")
    assert first["event_id"].startswith("EVT-") and len(first["event_id"]) == 36
    assert first["source_type"] == "WINDOWS_EVENT"
    assert first["collector_id"] == "win-lab"
    assert first["observed_at"] == "2026-08-25T09:00:00Z"
    assert first["received_at"] == "2026-08-25T09:00:05Z"
    assert first["payload"] == payload and first["payload"] is not payload
    assert validate_event_envelope(first, "WINDOWS_EVENT") == first

    tampered = deepcopy(first)
    tampered["payload"]["event_uid"] = "WINEVT-tampered"
    _reject(tampered, "does not match")
    invalid_version = {**first, "event_schema_version": 2}
    _reject(invalid_version, "unsupported event_schema_version")
    invalid_id = {**first, "event_id": "EVT-not-valid"}
    _reject(invalid_id, "EVT-<32 lowercase hex>")
    missing = deepcopy(first)
    missing.pop("collector_id")
    _reject(missing, "missing: collector_id")
    unknown = {**first, "secret": "must-not-pass"}
    _reject(unknown, "unsupported fields: secret")
    try:
        build_event_envelope(
            payload, source_type="WINDOWS_EVENT", collector_id="bad\ncollector",
        )
        raise AssertionError("Control characters were accepted in collector_id")
    except ValueError:
        pass

    legacy = {**payload, "source_file": "legacy-host", "imported_at": "2026-08-25T09:00:10Z"}
    unwrapped, metadata = unwrap_event_envelope(legacy, "WINDOWS_EVENT")
    assert unwrapped is legacy
    assert metadata["event_schema_version"] == 0
    assert metadata["collector_id"] == "legacy-host"
    assert metadata["event_id"] == first["event_id"]
    assert metadata["observed_at"] == "2026-08-25T09:00:00Z"
    assert metadata["received_at"] == "2026-08-25T09:00:10Z"


if __name__ == "__main__":
    test_versioned_event_envelope()
    print("M21.1 versioned event envelope passed")
