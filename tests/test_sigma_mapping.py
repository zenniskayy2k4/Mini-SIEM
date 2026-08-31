import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

from config import config
from src.detector import ThreatDetector
from src.rules import load_detection_rules
from src.sigma import load_sigma_rules


def _event(image, command_line="", parent_image=None):
    return {
        "event_id": 1,
        "event_uid": f"WINEVT-sigma-{image}-{command_line}",
        "timestamp": "2026-08-16T04:00:00Z",
        "computer": "win-sigma-lab",
        "process": {"image": image, "command_line": command_line},
        "parent_process": {"image": parent_image},
        "target_process": {},
        "network": {},
        "task": {},
        "defender": {},
    }


def _rule(rule_id, title, detection):
    return {
        "title": title,
        "id": rule_id,
        "status": "experimental",
        "description": title,
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": detection,
        "level": "high",
    }


def test_sigma_mapping():
    sigma, errors = load_sigma_rules(config.SIGMA_RULES_DIR)
    assert not errors
    detector = ThreatDetector([rule for rule in sigma if rule["enabled"]])
    alert = detector.analyze_windows_event(_event(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe -EncodedCommand SQBFAFgA",
    ))
    assert alert["rule_source"] == "sigma"
    assert alert["sigma_rule_id"] == sigma[0]["sigma_rule_id"]
    assert alert["windows_event_uid"].startswith("WINEVT-sigma-")

    with tempfile.TemporaryDirectory() as directory:
        fixtures = [
            _rule("71b618a8-3647-49f8-9413-5f5e42ab1b68", "All operators", {
                "selection": {
                    "EventID": 1,
                    "Image|endswith": r"\powershell.exe",
                    "CommandLine|startswith": "powershell.exe",
                    "CommandLine|contains|all": [" -nop", " -w hidden"],
                },
                "condition": "selection",
            }),
            _rule("a60e9851-23a4-4eb0-ae03-76c34b0afabb", "Filter exclusion", {
                "selection": {"Image|endswith": r"\powershell.exe"},
                "filter": {"ParentImage|endswith": r"\explorer.exe"},
                "condition": "selection and not filter",
            }),
            _rule("b158a08c-9537-45fb-8e35-7252e93c3127", "Selection OR", {
                "selection1": {"Image|endswith": r"\cmd.exe"},
                "selection2": {"Image|endswith": r"\powershell.exe"},
                "condition": "selection1 or selection2",
            }),
            _rule("1bb4f941-ad5a-4a79-8615-a8acbd144d10", "Keywords", {
                "keywords": ["whoami.exe", "hostname.exe"],
                "condition": "keywords",
            }),
            _rule("331116ac-5f21-4715-bec8-54014c74692a", "Unsupported modifier", {
                "selection": {"CommandLine|re": "powershell.*-enc"},
                "condition": "selection",
            }),
            _rule("832f7186-90e6-4606-a406-57309c524006", "Unsupported condition", {
                "selection1": {"Image": "cmd.exe"},
                "selection2": {"Image": "powershell.exe"},
                "condition": "1 of selection*",
            }),
        ]
        for index, fixture in enumerate(fixtures):
            Path(directory, f"rule_{index}.yml").write_text(
                yaml.safe_dump(fixture, sort_keys=False), encoding="utf-8",
            )

        with patch("logging.warning"):
            translated, failures = load_sigma_rules(directory)
        assert not failures
        active = {rule["title"]: rule for rule in translated if rule["enabled"]}
        skipped = {rule["title"]: rule for rule in translated if not rule["enabled"]}
        assert set(active) == {"All operators", "Filter exclusion", "Selection OR", "Keywords"}
        assert "unsupported modifier" in skipped["Unsupported modifier"]["skip_reason"]
        assert "unsupported condition" in skipped["Unsupported condition"]["skip_reason"]

        all_detector = ThreatDetector([active["All operators"]])
        assert all_detector.analyze_windows_event(_event(
            r"C:\Windows\System32\powershell.exe", "powershell.exe -nop -w hidden",
        ))
        assert not all_detector.analyze_windows_event(_event(
            r"C:\Windows\System32\powershell.exe", "powershell.exe -nop",
        ))

        filter_detector = ThreatDetector([active["Filter exclusion"]])
        assert filter_detector.analyze_windows_event(_event(
            r"C:\Windows\System32\powershell.exe", parent_image=r"C:\Office\winword.exe",
        ))
        assert not filter_detector.analyze_windows_event(_event(
            r"C:\Windows\System32\powershell.exe", parent_image=r"C:\Windows\explorer.exe",
        ))

        or_detector = ThreatDetector([active["Selection OR"]])
        assert or_detector.analyze_windows_event(_event(r"C:\Windows\System32\cmd.exe"))
        assert not or_detector.analyze_windows_event(_event(r"C:\Windows\System32\notepad.exe"))

        keyword_detector = ThreatDetector([active["Keywords"]])
        assert keyword_detector.analyze_windows_event(_event(
            r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami.exe",
        ))

    combined = load_detection_rules(
        config.RULES_DIR, config.SIGNATURES, config.SIGMA_RULES_DIR,
    )
    assert any(rule.get("rule_source") == "sigma" for rule in combined)


if __name__ == "__main__":
    test_sigma_mapping()
    print("M11.2 Sigma selection mapping passed")
