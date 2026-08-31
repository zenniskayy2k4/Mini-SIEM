"""
Test for M27.4 — Outage Recovery Scenario

This test verifies that the collector can handle server outages gracefully:
- Collector buffers events when server is unavailable
- Events are replayed when server comes back online
- No silent loss of events
- Deduplication works correctly
- Cursor advances properly
"""
import json
import tempfile
from pathlib import Path

from config import config
from dashboard import app
from tools.migrate_db import migrate_database


EVENT_A = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2026-08-13T10:00:00Z"/><EventRecordID>1001</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>win-lab</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\curl.exe</Data><Data Name="User">LAB\\analyst</Data><Data Name="DestinationIp">198.51.100.22</Data><Data Name="DestinationPort">443</Data></EventData></Event>"""

EVENT_B = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2026-08-13T10:00:05Z"/><EventRecordID>1002</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>win-lab</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\curl.exe</Data><Data Name="User">LAB\\analyst</Data><Data Name="DestinationIp">198.51.100.23</Data><Data Name="DestinationPort">80</Data></EventData></Event>"""

EVENT_C = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2026-08-13T10:00:15Z"/><EventRecordID>1003</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>win-lab</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\curl.exe</Data><Data Name="User">LAB\\analyst</Data><Data Name="DestinationIp">198.51.100.24</Data><Data Name="DestinationPort">443</Data></EventData></Event>"""


def test_outage_recovery_scenario():
    """Test that collector buffers events during outage and replays them on recovery."""
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

            # Step 1: Collector sends event A while server is healthy
            response = client.post(
                "/api/windows-events",
                headers=headers,
                json={
                    "collector_id": "win-outage-test",
                    "collector_version": "0.9.0",
                    "protocol_version": 1,
                    "hostname": "win-lab",
                    "source_type": "WINDOWS_EVENT",
                    "heartbeat": True,
                    "endpoint_available": True,
                    "buffer_diagnostics": {
                        "buffered_events": 0,
                        "buffer_oldest_age": None,
                        "retry_attempts": 0,
                        "delivery_failures": 0,
                    },
                    "events": [EVENT_A],
                },
            )
            assert response.status_code == 200
            assert response.get_json()["imported"] == 1
            assert response.get_json()["duplicates"] == 0

            # Step 2: Server becomes unavailable — collector buffers event B
            # endpoint_available=False signals the server is down; event B goes to the
            # local collector buffer (simulated by sending it in a later batch).
            response = client.post(
                "/api/windows-events",
                headers=headers,
                json={
                    "collector_id": "win-outage-test",
                    "collector_version": "0.9.0",
                    "protocol_version": 1,
                    "hostname": "win-lab",
                    "source_type": "WINDOWS_EVENT",
                    "heartbeat": True,
                    "endpoint_available": False,
                    "buffer_diagnostics": {
                        "buffered_events": 1,
                        "buffer_oldest_age": 30.0,
                        "retry_attempts": 1,
                        "delivery_failures": 0,
                    },
                    "events": [],
                },
            )
            assert response.status_code == 200
            assert response.get_json()["collector_status"] == "endpoint_unavailable"

            # Step 3: Server comes back — collector replays buffered event B
            response = client.post(
                "/api/windows-events",
                headers=headers,
                json={
                    "collector_id": "win-outage-test",
                    "collector_version": "0.9.0",
                    "protocol_version": 1,
                    "hostname": "win-lab",
                    "source_type": "WINDOWS_EVENT",
                    "heartbeat": True,
                    "endpoint_available": True,
                    "buffer_diagnostics": {
                        "buffered_events": 0,
                        "buffer_oldest_age": None,
                        "retry_attempts": 1,
                        "delivery_failures": 0,
                    },
                    "events": [EVENT_B],
                },
            )
            assert response.status_code == 200
            assert response.get_json()["imported"] == 1
            assert response.get_json()["duplicates"] == 0

            # Step 4: Replay verification — same event B should be deduplicated
            response = client.post(
                "/api/windows-events",
                headers=headers,
                json={
                    "collector_id": "win-outage-test",
                    "collector_version": "0.9.0",
                    "protocol_version": 1,
                    "hostname": "win-lab",
                    "source_type": "WINDOWS_EVENT",
                    "heartbeat": True,
                    "endpoint_available": True,
                    "buffer_diagnostics": {
                        "buffered_events": 0,
                        "buffer_oldest_age": None,
                        "retry_attempts": 0,
                        "delivery_failures": 0,
                    },
                    "events": [EVENT_B],
                },
            )
            assert response.status_code == 200
            assert response.get_json()["imported"] == 0
            assert response.get_json()["duplicates"] == 1

            # Step 5: Cursor advances — new event C with higher record ID is accepted
            response = client.post(
                "/api/windows-events",
                headers=headers,
                json={
                    "collector_id": "win-outage-test",
                    "collector_version": "0.9.0",
                    "protocol_version": 1,
                    "hostname": "win-lab",
                    "source_type": "WINDOWS_EVENT",
                    "heartbeat": True,
                    "endpoint_available": True,
                    "buffer_diagnostics": {
                        "buffered_events": 0,
                        "buffer_oldest_age": None,
                        "retry_attempts": 0,
                        "delivery_failures": 0,
                    },
                    "events": [EVENT_C],
                },
            )
            assert response.status_code == 200
            assert response.get_json()["imported"] == 1
            assert response.get_json()["duplicates"] == 0

            # Step 6: Verify no silent loss — all three distinct events persisted
            lines = json.loads(
                "[" + ",".join(
                    line for line in Path(config.WINDOWS_EVENT_FILE).read_text(
                        encoding="utf-8"
                    ).splitlines() if line.strip()
                ) + "]"
            )
            assert len(lines) == 3
            event_ids = {line["event_id"] for line in lines}
            assert len(event_ids) == 3, "All events should have unique IDs"
            for line in lines:
                assert line["event_schema_version"] == 1
                assert line["event_id"].startswith("EVT-")
                assert line["collector_id"] == "win-outage-test"
                assert line["source_type"] == "WINDOWS_EVENT"
                assert line["payload"]["event_id"] == 3
                assert line["payload"]["record_id"] in ("1001", "1002", "1003")

            # Step 7: Verify collector heartbeat tracks across outage
            collector = response.get_json()["collector"]
            assert collector["collector_id"] == "win-outage-test"
            assert collector["collector_version"] == "0.9.0"
            assert collector["hostname"] == "win-lab"
            assert collector["buffered_events"] == 0
            assert collector["delivery_failures"] == 0

        finally:
            (
                config.WINDOWS_COLLECTOR_SECRET, config.WINDOWS_EVENT_FILE,
                config.SQLITE_ALERT_DB,
            ) = original


if __name__ == "__main__":
    test_outage_recovery_scenario()
    print("M27.4 outage recovery test passed")