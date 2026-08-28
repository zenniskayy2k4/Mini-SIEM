import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from config import config
from src.ingestion_failures import (
    MAX_PREVIEW_CHARS, get_collector_gap_diagnostics,
    get_ingestion_failure_diagnostics, get_ingestion_health_metrics,
    record_collector_heartbeat, record_ingestion_failure,
)
from src.windows_events import ingest_windows_events


def test_ingestion_failures():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original = config.SQLITE_ALERT_DB, config.INGESTION_FAILURE_RETENTION_DAYS
        config.SQLITE_ALERT_DB = str(directory / "mini-siem.db")
        config.INGESTION_FAILURE_RETENTION_DAYS = 30
        output = directory / "windows-events.jsonl"
        try:
            heartbeat_at = datetime(2026, 8, 25, 9, tzinfo=timezone.utc)
            assert get_collector_gap_diagnostics(
                now=heartbeat_at, stale_seconds=60,
            )["status"] == "offline"
            record_collector_heartbeat("win-lab", now=heartbeat_at)
            idle = get_collector_gap_diagnostics(
                now=heartbeat_at, stale_seconds=60,
            )
            assert idle["status"] == idle["collectors"][0]["status"] == "idle"
            record_collector_heartbeat(
                "win-lab", endpoint_available=False,
                now=heartbeat_at.replace(second=1),
            )
            assert get_collector_gap_diagnostics(
                now=heartbeat_at.replace(second=1), stale_seconds=60,
            )["status"] == "endpoint_unavailable"
            record_collector_heartbeat(
                "win-lab", events_received=1, now=heartbeat_at.replace(second=2),
            )
            healthy_gap = get_collector_gap_diagnostics(
                now=heartbeat_at.replace(second=2), stale_seconds=60,
            )
            assert healthy_gap["status"] == "healthy"
            assert healthy_gap["collectors"][0]["last_event_age_seconds"] == 0
            assert get_ingestion_health_metrics(
                now=heartbeat_at.replace(second=2),
            )["WINDOWS_EVENT"]["collector_last_seen_seconds"] == 0
            assert get_collector_gap_diagnostics(
                now=heartbeat_at.replace(minute=2), stale_seconds=60,
            )["status"] == "offline"
            with patch("src.ingestion_failures.MAX_COLLECTOR_HEARTBEATS", 1):
                try:
                    record_collector_heartbeat("unbounded-id")
                    assert False, "collector heartbeat limit was not enforced"
                except ValueError as exc:
                    assert str(exc) == "collector heartbeat limit reached"

            empty_health = get_ingestion_health_metrics()["WINDOWS_EVENT"]
            assert empty_health["events_received_total"] == 0
            assert empty_health["collector_last_seen_seconds"] is not None
            malformed_xml = '<Event><Data Name="Password">SENSITIVE_XML_123 WITHSPACE</Event>'
            missing_schema = {
                "timestamp": "2026-08-25T09:00:00Z",
                "api_" + "token": "schema-secret",
                "message": "x" * 1000,
            }
            unsupported = {
                "event_id": 9999,
                "timestamp": "2026-08-25T09:00:00Z",
                "author" + "ization": "Bearer " + "unsupported-secret",
            }
            summary = ingest_windows_events(
                [malformed_xml, missing_schema, unsupported], "win-lab", output,
            )
            assert summary == {
                "read": 3, "imported": 0, "duplicates": 0,
                "unsupported": 1, "errors": 2,
            }
            diagnostics = get_ingestion_failure_diagnostics()
            assert diagnostics["counts"] == {
                "parser": 1, "schema": 1, "unsupported": 1,
            }
            assert diagnostics["total"] == len(diagnostics["recent"]) == 3
            assert diagnostics["retention_days"] == 30
            encoded = json.dumps(diagnostics)
            for secret in (
                "SENSITIVE_XML_123", "WITHSPACE", "schema-secret", "unsupported-secret",
            ):
                assert secret not in encoded
            assert "[REDACTED]" in encoded
            assert all(
                len(record["payload_preview"]) <= MAX_PREVIEW_CHARS
                and record["collector_id"] == "win-lab"
                and record["source_type"] == "WINDOWS_EVENT"
                for record in diagnostics["recent"]
            )

            valid = {
                "event_id": 4625,
                "timestamp": "2026-08-25T09:01:00Z",
                "computer": "win-lab",
                "event_data": {"TargetUserName": "analyst"},
            }
            accepted = ingest_windows_events([valid, valid], "win-lab", output)
            assert accepted == {
                "read": 2, "imported": 1, "duplicates": 1,
                "unsupported": 0, "errors": 0,
            }
            health = get_ingestion_health_metrics()["WINDOWS_EVENT"]
            assert health["events_received_total"] == 5
            assert health["events_normalized_total"] == 2
            assert health["events_rejected_total"] == 3
            assert health["events_deduplicated_total"] == 1
            assert health["event_processing_seconds"] >= 0
            assert 0 <= health["collector_last_seen_seconds"] < 5

            record_ingestion_failure(
                "schema", "expired", {"pass" + "word": "old-secret"},
                occurred_at="2020-01-01T00:00:00Z",
            )
            retained = get_ingestion_failure_diagnostics(
                now=datetime(2026, 8, 25, tzinfo=timezone.utc),
            )
            assert retained["total"] == 3

            with (
                patch("src.windows_events.record_ingestion_failure", side_effect=OSError),
                patch("src.windows_events.record_ingestion_health", side_effect=OSError),
                patch("src.windows_events.logger.warning"),
            ):
                failed_diagnostics = ingest_windows_events(
                    [{"timestamp": "2026-08-25T09:00:00Z"}], "win-lab", output,
                )
                assert failed_diagnostics["errors"] == 1
        finally:
            config.SQLITE_ALERT_DB, config.INGESTION_FAILURE_RETENTION_DAYS = original


if __name__ == "__main__":
    test_ingestion_failures()
    print("M21.2-M21.4 ingestion diagnostics, metrics, and gap detection passed")
