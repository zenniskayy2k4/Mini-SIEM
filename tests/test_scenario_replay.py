import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

from tools.replay_scenario import ScenarioReplayError, replay_path


SCENARIOS = Path(__file__).parent / "scenarios"


def test_offline_scenario_replay():
    with patch(
        "requests.sessions.Session.request",
        side_effect=AssertionError("offline replay attempted a network call"),
    ):
        first = replay_path(SCENARIOS)
        second = replay_path(SCENARIOS)
    assert first == second
    assert first["passed"] is True
    assert [result["scenario_id"] for result in first["results"]] == [
        "SCN-SSH-BRUTE-001", "SCN-WIN-POWERSHELL-001",
    ]
    assert first["results"][0]["matched_rule_ids"] == ["DET-SSH-001"]
    assert first["results"][1]["matched_rule_ids"] == ["DET-WIN-001"]

    with tempfile.TemporaryDirectory() as directory_name:
        root = Path(directory_name)
        scenarios = root / "scenarios"
        scenarios.mkdir()
        fixture = root / "events.jsonl"
        fixture.write_text(
            '{"relative_seconds":0,"message":"benign login"}\n', encoding="utf-8"
        )
        manifest = {
            "schema_version": 1,
            "id": "SCN-EXPECTED-FAIL-001",
            "title": "Expected failure",
            "source": "linux_auth",
            "events": "events.jsonl",
            "expected": {
                "rule_ids": ["DET-SSH-001"],
                "alert_count": {"min": 1, "max": 1},
                "severity": "HIGH",
                "fields": {},
            },
        }
        (scenarios / "failure.yml").write_text(
            yaml.safe_dump(manifest), encoding="utf-8"
        )
        failed = replay_path(scenarios, root)
        assert failed["passed"] is False
        assert "missing rule_ids: DET-SSH-001" in failed["results"][0]["failures"]

        manifest["expected"]["fields"] = {"raw_log": {"contains": "login"}}
        (scenarios / "failure.yml").write_text(
            yaml.safe_dump(manifest), encoding="utf-8"
        )
        try:
            replay_path(scenarios, root)
            raise AssertionError("Replay exposed a non-allowlisted output field")
        except ScenarioReplayError as exc:
            assert "unsupported output fields: raw_log" in str(exc)


if __name__ == "__main__":
    test_offline_scenario_replay()
    print("M19.2 offline scenario replay passed")
