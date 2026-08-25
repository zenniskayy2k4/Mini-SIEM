import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from config import config
from src.ingestion_failures import (
    MAX_PREVIEW_CHARS, get_ingestion_failure_diagnostics,
    record_ingestion_failure,
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

            record_ingestion_failure(
                "schema", "expired", {"pass" + "word": "old-secret"},
                occurred_at="2020-01-01T00:00:00Z",
            )
            retained = get_ingestion_failure_diagnostics(
                now=datetime(2026, 8, 25, tzinfo=timezone.utc),
            )
            assert retained["total"] == 3

            with patch(
                "src.windows_events.record_ingestion_failure", side_effect=OSError,
            ):
                failed_diagnostics = ingest_windows_events(
                    [{"timestamp": "2026-08-25T09:00:00Z"}], "win-lab", output,
                )
                assert failed_diagnostics["errors"] == 1
        finally:
            config.SQLITE_ALERT_DB, config.INGESTION_FAILURE_RETENTION_DAYS = original


if __name__ == "__main__":
    test_ingestion_failures()
    print("M21.2 ingestion dead-letter diagnostics passed")
