import json
import tempfile
from config import config
from src.detector import ThreatDetector
from src.handler import WindowsEventHandler
from src.rules import load_rules
from pathlib import Path
from types import SimpleNamespace


def _event(event_id, **fields):
    event = {
        "event_id": event_id,
        "event_uid": f"WINEVT-test-{event_id}-{len(fields)}",
        "timestamp": "2026-08-13T11:00:00Z",
        "computer": "win-lab",
        "process": {"image": None, "command_line": None},
        "parent_process": {"image": None},
        "target_process": {"image": None, "granted_access": None},
        "network": {},
        "task": {},
        "defender": {},
    }
    for path, value in fields.items():
        section, name = path.split("__", 1)
        event[section][name] = value
    return event


def test_windows_detection():
    detector = ThreatDetector(load_rules(config.RULES_DIR, config.SIGNATURES))
    cases = [
        ("DET-WIN-001", _event(1,
            process__image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            process__command_line="powershell.exe -EncodedCommand SQBFAFgA")),
        ("DET-WIN-002", _event(1,
            process__image=r"C:\Windows\System32\certutil.exe",
            process__command_line="certutil.exe -urlcache example.test")),
        ("DET-WIN-003", _event(4720)),
        ("DET-WIN-004", _event(4698, task__name=r"\Updater")),
        ("DET-WIN-005", _event(5007,
            defender__setting=r"HKLM\Software\Microsoft\Windows Defender\DisableAntiSpyware = 0x1")),
        ("DET-WIN-006", _event(10,
            process__image=r"C:\Tools\procdump.exe",
            target_process__image=r"C:\Windows\System32\lsass.exe",
            target_process__granted_access="0x1010")),
        ("DET-WIN-007", _event(1,
            process__image=r"C:\Windows\System32\cmd.exe",
            parent_process__image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")),
    ]

    for expected_rule, event in cases:
        alert = detector.analyze_windows_event(event)
        assert alert is not None, expected_rule
        assert alert["rule_id"] == expected_rule
        assert alert["source_type"] == "WINDOWS_EVENT"
        assert alert["windows_event_uid"] == event["event_uid"]
        assert alert["computer"] == "win-lab"

    benign = _event(1,
        process__image=r"C:\Windows\System32\notepad.exe",
        parent_process__image=r"C:\Windows\explorer.exe")
    assert detector.analyze_windows_event(benign) is None
    legitimate_lolbin = _event(1,
        process__image=r"C:\Windows\System32\rundll32.exe",
        process__command_line="rundll32.exe desk.cpl,InstallScreenSaver")
    assert detector.analyze_windows_event(legitimate_lolbin) is None

    with tempfile.TemporaryDirectory() as directory:
        telemetry = Path(directory, "windows.jsonl")
        telemetry.write_text(json.dumps(benign) + "\n", encoding="utf-8")
        handler = WindowsEventHandler(str(telemetry), detector)
        handled = []
        handler._process_alert = handled.append
        with telemetry.open("a", encoding="utf-8") as output:
            output.write(json.dumps(cases[0][1]) + "\n")
        handler.on_modified(SimpleNamespace(src_path=str(telemetry)))
        handler.file_handle.close()
        assert [alert["rule_id"] for alert in handled] == ["DET-WIN-001"]


if __name__ == "__main__":
    test_windows_detection()
    print("M7.3 Windows detection passed")
