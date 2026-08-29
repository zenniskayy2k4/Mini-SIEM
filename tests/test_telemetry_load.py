import json
import tempfile
from collections import Counter
from pathlib import Path

from src.event_envelope import validate_event_envelope
from tools.generate_telemetry_load import generate_events, write_jsonl


def test_synthetic_telemetry_load():
    generated = {}
    for mode in (
        "steady", "burst", "mixed-source", "windows-heavy",
        "authentication-heavy",
    ):
        first = list(generate_events(mode, 40, duration=9, seed=7))
        second = list(generate_events(mode, 40, duration=9, seed=7))
        assert first == second and len(first) == 40
        assert len({event["event_id"] for event in first}) == 40
        assert all(validate_event_envelope(event) == event for event in first)
        assert all(event["payload"]["synthetic"] is True for event in first)
        assert all("ai" not in event["payload"] for event in first)
        generated[mode] = first

    assert Counter(event["source_type"] for event in generated["steady"]) == {"HIDS_LOG": 40}
    assert Counter(event["source_type"] for event in generated["mixed-source"]) == {
        "HIDS_LOG": 10, "WINDOWS_EVENT": 10, "NIDS": 10, "HONEYPOT": 10,
    }
    assert Counter(event["source_type"] for event in generated["windows-heavy"])["WINDOWS_EVENT"] == 32
    assert Counter(event["source_type"] for event in generated["authentication-heavy"]) == {
        "HIDS_LOG": 20, "WINDOWS_EVENT": 20,
    }
    assert len({event["observed_at"] for event in generated["burst"]}) == 10
    assert len({event["observed_at"] for event in generated["steady"]}) == 40

    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "load.jsonl"
        write_jsonl(iter(generated["mixed-source"]), output)
        assert [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()] == generated["mixed-source"]
        try:
            write_jsonl([], output)
            raise AssertionError("Existing output was overwritten")
        except FileExistsError:
            pass

    for invalid in (
        ("unknown", 1, 1), ("steady", 0, 1), ("steady", 1, float("inf")),
    ):
        try:
            list(generate_events(*invalid))
            raise AssertionError("Invalid load settings were accepted")
        except ValueError:
            pass


if __name__ == "__main__":
    test_synthetic_telemetry_load()
    print("M25.1 synthetic telemetry load generator passed")
