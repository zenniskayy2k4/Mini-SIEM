import json
import tempfile
from pathlib import Path

from config import config
from dashboard import app


EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2026-08-13T10:00:00Z"/><EventRecordID>702</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>win-lab</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\curl.exe</Data><Data Name="User">LAB\\analyst</Data><Data Name="DestinationIp">198.51.100.21</Data><Data Name="DestinationPort">443</Data><Data Name="Protocol">tcp</Data></EventData></Event>"""


def test_windows_collector():
    with tempfile.TemporaryDirectory() as directory:
        original = (
            config.WINDOWS_COLLECTOR_SECRET, config.WINDOWS_EVENT_FILE,
            config.SQLITE_ALERT_DB,
        )
        config.WINDOWS_EVENT_FILE = str(Path(directory, "windows_events.jsonl"))
        config.SQLITE_ALERT_DB = str(Path(directory, "mini-siem.db"))
        client = app.test_client()
        try:
            config.WINDOWS_COLLECTOR_SECRET = ""
            assert client.post("/api/windows-events", json={"events": [EVENT_XML]}).status_code == 503

            config.WINDOWS_COLLECTOR_SECRET = "collector-test-secret"
            assert client.post("/api/windows-events", json={"events": [EVENT_XML]}).status_code == 401
            assert client.post(
                "/api/windows-events",
                headers={"X-Mini-SIEM-Secret": "collector-test-secret"},
                json={"events": []},
            ).status_code == 400
            assert client.post(
                "/api/windows-events",
                headers={"X-Mini-SIEM-Secret": "collector-test-secret"},
                json={"events": [EVENT_XML] * 501},
            ).status_code == 413

            headers = {"X-Mini-SIEM-Secret": "collector-test-secret"}
            response = client.post(
                "/api/windows-events",
                headers=headers,
                json={"collector_id": "win-lab", "events": [EVENT_XML]},
            )
            assert response.status_code == 200
            assert response.get_json()["imported"] == 1

            duplicate = client.post(
                "/api/windows-events",
                headers=headers,
                # Legacy clients may continue sending source during migration.
                json={"source": "win-lab", "events": [EVENT_XML]},
            )
            assert duplicate.get_json()["duplicates"] == 1
            event = json.loads(Path(config.WINDOWS_EVENT_FILE).read_text(encoding="utf-8"))
            assert event["event_schema_version"] == 1
            assert event["event_id"].startswith("EVT-")
            assert event["collector_id"] == "win-lab"
            assert event["source_type"] == "WINDOWS_EVENT"
            assert event["payload"]["network"]["destination_port"] == 443
            assert client.post(
                "/api/windows-events", headers=headers,
                json={"collector_id": {"host": "invalid"}, "events": [EVENT_XML]},
            ).status_code == 400
            assert client.post(
                "/api/windows-events", headers=headers, json=[EVENT_XML],
            ).status_code == 400
        finally:
            (
                config.WINDOWS_COLLECTOR_SECRET, config.WINDOWS_EVENT_FILE,
                config.SQLITE_ALERT_DB,
            ) = original


if __name__ == "__main__":
    test_windows_collector()
    print("M7.2 Windows collector passed")
