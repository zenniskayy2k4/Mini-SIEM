import tempfile
from pathlib import Path

import yaml

from src.scenario_manifest import (
    ScenarioManifestError,
    load_scenario_manifest,
    load_scenario_manifests,
)


SCENARIOS = Path(__file__).parent / "scenarios"


def test_scenario_manifest_contract():
    manifests = load_scenario_manifests(SCENARIOS)
    assert [manifest["id"] for manifest in manifests] == [
        "SCN-SSH-BRUTE-001",
        "SCN-WIN-POWERSHELL-001",
    ]
    assert {manifest["source"] for manifest in manifests} == {"linux_auth", "windows_event"}

    with tempfile.TemporaryDirectory() as directory_name:
        root = Path(directory_name)
        scenarios = root / "scenarios"
        scenarios.mkdir()
        (root / "events.jsonl").write_text("{}\n", encoding="utf-8")
        valid = {
            "schema_version": 1,
            "id": "SCN-TEST-VALID-001",
            "title": "Fixture",
            "source": "linux_auth",
            "events": "events.jsonl",
            "expected": {
                "rule_ids": ["DET-TEST-001"],
                "alert_count": {"min": 1, "max": 1},
                "severity": "HIGH",
                "fields": {},
            },
        }
        first = scenarios / "first.yml"
        first.write_text(yaml.safe_dump(valid), encoding="utf-8")
        assert load_scenario_manifest(first, root)["id"] == "SCN-TEST-VALID-001"

        invalid = scenarios / "invalid.yml"
        invalid.write_text("schema_version: 1\nid: invalid\n", encoding="utf-8")
        try:
            load_scenario_manifest(invalid, root)
            raise AssertionError("Malformed manifest was accepted")
        except ScenarioManifestError as exc:
            assert "missing fields" in str(exc)

        malformed = dict(valid, source=[])
        invalid.write_text(yaml.safe_dump(malformed), encoding="utf-8")
        try:
            load_scenario_manifest(invalid, root)
            raise AssertionError("Invalid source type was accepted")
        except ScenarioManifestError as exc:
            assert "source must be one of" in str(exc)

        escaped = dict(valid, events="../escape.jsonl")
        invalid.write_text(yaml.safe_dump(escaped), encoding="utf-8")
        try:
            load_scenario_manifest(invalid, root)
            raise AssertionError("Escaping fixture path was accepted")
        except ScenarioManifestError as exc:
            assert "stay inside" in str(exc)
        invalid.unlink()

        second = scenarios / "second.yml"
        second.write_text(yaml.safe_dump(valid), encoding="utf-8")
        try:
            load_scenario_manifests(scenarios, root)
            raise AssertionError("Duplicate scenario ID was accepted")
        except ScenarioManifestError as exc:
            assert "Duplicate scenario ID" in str(exc)


if __name__ == "__main__":
    test_scenario_manifest_contract()
    print("M19.1 scenario manifest contract passed")
