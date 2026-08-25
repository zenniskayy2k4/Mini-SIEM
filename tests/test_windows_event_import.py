import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.event_envelope import validate_event_envelope
from src.windows_events import import_windows_events


EVENT_IDS = (1, 3, 7, 10, 11, 13, 4624, 4625, 4688, 4698, 4720, 5007)


def _event(event_id, record_id):
    data = {
        "ProcessId": "0x1234",
        "ProcessGuid": "{process-guid}",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile",
        "ParentProcessId": "0x456",
        "ParentProcessGuid": "{parent-guid}",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "explorer.exe",
        "User": "LAB\\analyst",
        "Hashes": "SHA256=abc123,MD5=def456",
        "SourceIp": "192.0.2.70",
        "SourcePort": "55123",
        "DestinationIp": "198.51.100.10",
        "DestinationPort": "443",
        "Protocol": "tcp",
        "TargetFilename": "C:\\Temp\\sample.bin",
        "TargetObject": "HKLM\\Software\\Demo",
        "Details": "DWORD (0x00000001)",
        "TargetUserName": "target-user",
        "TargetDomainName": "LAB",
        "LogonType": "3",
    }
    if event_id == 4688:
        data.update({
            "NewProcessId": "0x999",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CreatorProcessId": "0x888",
            "ProcessCommandLine": "cmd.exe /c whoami",
        })
    return {
        "Event": {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": event_id,
                "TimeCreated": {"@SystemTime": "2026-08-13T08:00:00Z"},
                "EventRecordID": record_id,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Computer": "win-lab",
            },
            "EventData": {"Data": [{"@Name": key, "#text": value} for key, value in data.items()]},
        }
    }


def test_windows_event_import():
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        source = directory / "events.json"
        output = directory / "normalized.jsonl"
        source.write_text(json.dumps([_event(event_id, index) for index, event_id in enumerate(EVENT_IDS, 1)]), encoding="utf-8")

        summary = import_windows_events(source, output)
        assert summary == {"read": 12, "imported": 12, "duplicates": 0, "unsupported": 0, "errors": 0}
        envelopes = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
        assert all(validate_event_envelope(item, "WINDOWS_EVENT") for item in envelopes)
        assert all(item["event_schema_version"] == 1 for item in envelopes)
        assert all(item["event_id"].startswith("EVT-") for item in envelopes)
        assert all(item["collector_id"] == "events.json" for item in envelopes)
        assert all(item["received_at"].endswith("Z") for item in envelopes)
        assert all(item["observed_at"] == item["payload"]["timestamp"] for item in envelopes)
        events = [item["payload"] for item in envelopes]
        assert {event["event_id"] for event in events} == set(EVENT_IDS)
        process = events[0]
        assert process["process"]["image"].endswith("powershell.exe")
        assert process["parent_process"]["image"].endswith("explorer.exe")
        assert process["process"]["command_line"] == "powershell.exe -NoProfile"
        assert process["user"] == "LAB\\analyst"
        assert process["hashes"] == {"SHA256": "abc123", "MD5": "def456"}
        assert process["network"]["destination_port"] == 443
        event_4688 = next(event for event in events if event["event_id"] == 4688)
        assert event_4688["process"]["id"] == "0x999"
        assert event_4688["parent_process"]["id"] == "0x888"

        duplicate = import_windows_events(source, output)
        assert duplicate["imported"] == 0 and duplicate["duplicates"] == 12

        xml_source = directory / "security.xml"
        xml_source.write_text("""<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-08-13T08:01:00Z"/><EventRecordID>99</EventRecordID><Channel>Security</Channel><Computer>win-lab</Computer></System><EventData><Data Name="TargetUserName">blocked-user</Data><Data Name="TargetDomainName">LAB</Data><Data Name="IpAddress">203.0.113.9</Data><Data Name="LogonType">10</Data><Data Name="Status">0xC000006D</Data></EventData></Event></Events>""", encoding="utf-8")
        assert import_windows_events(xml_source, output)["imported"] == 1
        xml_event = json.loads(output.read_text(encoding="utf-8").splitlines()[-1])["payload"]
        assert xml_event["user"] == "LAB\\blocked-user"
        assert xml_event["network"]["source_ip"] == "203.0.113.9"

        evtx_source = directory / "sample.evtx"
        evtx_source.touch()

        class Record:
            def xml(self):
                return xml_source.read_text(encoding="utf-8").replace("<Events>", "", 1).rsplit("</Events>", 1)[0]

        class FakeEvtx:
            def __init__(self, _path):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def records(self):
                return [Record()]

        evtx_output = directory / "evtx.jsonl"
        with patch("Evtx.Evtx.Evtx", FakeEvtx):
            assert import_windows_events(evtx_source, evtx_output)["imported"] == 1
        evtx_event = json.loads(evtx_output.read_text(encoding="utf-8"))
        assert evtx_event["event_id"].startswith("EVT-")
        assert evtx_event["payload"]["event_id"] == 4625


if __name__ == "__main__":
    test_windows_event_import()
    print("M7.1 Windows event import passed")
