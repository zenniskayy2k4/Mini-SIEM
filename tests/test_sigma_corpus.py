import json
from pathlib import Path

from src.detector import ThreatDetector
from src.sigma import load_sigma_rules
from src.windows_events import normalize_windows_event


CORPUS = Path(__file__).parent / "fixtures" / "sigma"


def test_sigma_corpus():
    rules, errors = load_sigma_rules(str(CORPUS), str(CORPUS / "no-state.json"))
    assert not errors
    active = [rule for rule in rules if rule["enabled"]]
    skipped = [rule for rule in rules if not rule["enabled"]]
    assert len(active) == 3
    assert len(skipped) == 1
    assert skipped[0]["validation_status"] == "unsupported"
    assert "unsupported modifier" in skipped[0]["skip_reason"]

    detector = ThreatDetector(active)
    cases = json.loads((CORPUS / "events.json").read_text(encoding="utf-8"))
    assert {case["case"] for case in cases} == {
        "process_creation_positive", "process_creation_negative",
        "powershell_positive", "powershell_negative",
        "account_creation_positive", "account_creation_negative",
    }
    for case in cases:
        event = normalize_windows_event(case["record"])
        alert = detector.analyze_windows_event(event)
        expected = case["expected_rule"]
        if expected is None:
            assert alert is None, case["case"]
            continue
        assert alert is not None, case["case"]
        assert alert["rule_id"] == expected, case["case"]
        assert alert["rule_source"] == "sigma"
        assert alert["sigma_rule_id"] == expected
        assert alert["windows_event_uid"] == event["event_uid"]


if __name__ == "__main__":
    test_sigma_corpus()
    print("M11.4 Sigma regression corpus passed")
