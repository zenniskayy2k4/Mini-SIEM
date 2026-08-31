import json
import tempfile
from pathlib import Path

from config import config
from dashboard import app
from tools.migrate_db import migrate_database


EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2026-08-13T10:00:00Z"/><EventRecordID>702</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>win-lab</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\curl.exe</Data><Data Name="User">LAB\\analyst</Data><Data Name="DestinationIp">198.51.100.21</Data><Data Name="DestinationPort">443</Data><Data Name="Protocol">tcp</Data></EventData></Event>"""


def test_windows_collector():
    with tempfile.TemporaryDirectory() as directory:
        original = (
            config.WINDOWS_COLLECTOR_SECRET, config.WINDOWS_EVENT_FILE,
            config.SQLITE_ALERT_DB,
        )
        config.WINDOWS_EVENT_FILE = str(Path(directory, "windows_events.jsonl"))
        config.SQLITE_ALERT_DB = str(Path(directory, "mini-siem.db"))
        Path(config.SQLITE_ALERT_DB).touch()
        migrate_database(config.SQLITE_ALERT_DB)
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
            heartbeat = client.post(
                "/api/windows-events",
                headers={"X-Mini-SIEM-Secret": "collector-test-secret"},
                json={"collector_id": "win-idle", "heartbeat": True, "events": []},
            )
            assert heartbeat.status_code == 200
            assert heartbeat.get_json()["collector_status"] == "idle"
            unavailable = client.post(
                "/api/windows-events",
                headers={"X-Mini-SIEM-Secret": "collector-test-secret"},
                json={
                    "collector_id": "win-idle", "heartbeat": True,
                    "endpoint_available": False, "events": [],
                },
            )
            assert unavailable.status_code == 200
            assert unavailable.get_json()["collector_status"] == "endpoint_unavailable"
            assert client.post(
                "/api/windows-events",
                headers={"X-Mini-SIEM-Secret": "collector-test-secret"},
                json={"heartbeat": "true", "events": []},
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
                json={
                    "collector_id": "win-stable-id",
                    "collector_version": "0.9.0",
                    "hostname": "win-lab",
                    "source_type": "WINDOWS_EVENT",
                    "buffer_diagnostics": {
                        "buffered_events": 1,
                        "buffer_oldest_age": 5.0,
                        "retry_attempts": 2,
                        "delivery_failures": 1,
                    },
                    "events": [EVENT_XML],
                },
            )
            assert response.status_code == 200
            payload = response.get_json()
            assert payload["imported"] == 1
            assert payload["collector"]["collector_id"] == "win-stable-id"
            assert payload["collector"]["collector_version"] == "0.9.0"
            assert payload["collector"]["hostname"] == "win-lab"
            assert payload["collector"]["buffered_events"] == 0
            assert payload["collector"]["buffer_oldest_age"] is None
            assert payload["collector"]["retry_attempts"] == 2
            assert payload["collector"]["delivery_failures"] == 1

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
            assert event["collector_id"] == "win-stable-id"
            assert event["source_type"] == "WINDOWS_EVENT"
            assert event["payload"]["network"]["destination_port"] == 443
            assert client.post(
                "/api/windows-events", headers=headers,
                json={"collector_id": {"host": "invalid"}, "events": [EVENT_XML]},
            ).status_code == 400
            assert client.post(
                "/api/windows-events", headers=headers,
                json={"source_type": "NIDS", "events": [EVENT_XML]},
            ).status_code == 400
            assert client.post(
                "/api/windows-events", headers=headers,
                json={"hostname": False, "events": [EVENT_XML]},
            ).status_code == 400
            assert client.post(
                "/api/windows-events", headers=headers,
                json={"buffer_diagnostics": {}, "events": [EVENT_XML]},
            ).status_code == 400
            assert client.post(
                "/api/windows-events", headers=headers, json=[EVENT_XML],
            ).status_code == 400
            collector_script = Path("tools/windows_event_collector.ps1").read_text(encoding="utf-8")
            for field in ("collector_id", "collector_version", "hostname", "source_type"):
                assert f"{field} =" in collector_script
            assert 'collector-id.txt' in collector_script
            for marker in (
                "buffered_events", "buffer_oldest_age", "retry_attempts",
                "delivery_failures", "Sort-Object observed_at", "corrupt-$stamp",
                "Select-Object -First $BatchSize",
            ):
                assert marker in collector_script
        finally:
            (
                config.WINDOWS_COLLECTOR_SECRET, config.WINDOWS_EVENT_FILE,
                config.SQLITE_ALERT_DB,
            ) = original


if __name__ == "__main__":
    test_windows_collector()
    print("M7.2/M21.4/M27.2 Windows collector, heartbeat, and buffer contract passed")
