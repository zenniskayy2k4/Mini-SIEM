import tempfile
from pathlib import Path

from config import config
from dashboard import app
from src.ingestion_failures import validate_collector_protocol
from tools.migrate_db import migrate_database


EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2026-08-13T10:00:00Z"/><EventRecordID>902</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>win-lab</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\curl.exe</Data><Data Name="User">LAB\\analyst</Data><Data Name="DestinationIp">198.51.100.22</Data><Data Name="DestinationPort">443</Data><Data Name="Protocol">tcp</Data></EventData></Event>"""


def test_collector_protocol():
    assert validate_collector_protocol({}) == 0
    assert validate_collector_protocol({"protocol_version": 1}) == 1
    for body in (
        {"protocol_version": "1"},
        {"protocol_version": True},
        {"protocol_version": 1.5},
        {"protocol_version": -1},
        {"protocol_version": 2},
        {"protocol_version": None},
    ):
        try:
            validate_collector_protocol(body)
        except ValueError:
            pass
        else:
            raise AssertionError(f"protocol payload was accepted: {body}")

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
            config.WINDOWS_COLLECTOR_SECRET = "collector-test-secret"
            headers = {"X-Mini-SIEM-Secret": "collector-test-secret"}

            legacy = client.post(
                "/api/windows-events", headers=headers,
                json={"collector_id": "win-legacy", "heartbeat": True, "events": []},
            )
            assert legacy.status_code == 200
            assert legacy.get_json()["protocol_version"] == 0

            current = client.post(
                "/api/windows-events", headers=headers,
                json={
                    "collector_id": "win-current", "protocol_version": 1,
                    "heartbeat": True, "events": [],
                },
            )
            assert current.status_code == 200
            assert current.get_json()["protocol_version"] == 1

            future = client.post(
                "/api/windows-events", headers=headers,
                json={"collector_id": "win-future", "protocol_version": 2,
                      "heartbeat": True, "events": []},
            )
            assert future.status_code == 400
            assert "unsupported collector protocol_version 2" in future.get_json()["error"]

            for payload in (
                {"collector_id": "win-bad", "protocol_version": "1", "events": []},
                {"collector_id": "win-bad", "protocol_version": True, "events": []},
                {"collector_id": "win-bad", "protocol_version": 1.5, "events": []},
                {"collector_id": "win-bad", "protocol_version": -1, "events": []},
            ):
                assert client.post(
                    "/api/windows-events", headers=headers, json=payload,
                ).status_code == 400

            batch = client.post(
                "/api/windows-events", headers=headers,
                json={
                    "collector_id": "win-current", "protocol_version": 1,
                    "hostname": "win-lab", "source_type": "WINDOWS_EVENT",
                    "heartbeat": True, "endpoint_available": True,
                    "buffer_diagnostics": {
                        "buffered_events": 0, "buffer_oldest_age": None,
                        "retry_attempts": 0, "delivery_failures": 0,
                    },
                    "events": [EVENT_XML],
                },
            )
            assert batch.status_code == 200
            assert batch.get_json()["protocol_version"] == 1
            assert batch.get_json()["imported"] == 1
            assert client.post(
                "/api/windows-events", headers=headers,
                json={"collector_id": "win-current", "protocol_version": 1,
                      "events": [EVENT_XML]},
            ).get_json()["duplicates"] == 1

            collector_script = Path("tools/windows_event_collector.ps1").read_text(encoding="utf-8")
            assert "$ProtocolVersion = 1" in collector_script
            assert "protocol_version = $ProtocolVersion" in collector_script
        finally:
            (
                config.WINDOWS_COLLECTOR_SECRET, config.WINDOWS_EVENT_FILE,
                config.SQLITE_ALERT_DB,
            ) = original


if __name__ == "__main__":
    test_collector_protocol()
    print("M27.3 collector protocol version contract passed")
