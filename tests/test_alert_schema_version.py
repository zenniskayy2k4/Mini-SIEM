import json
import tempfile
from pathlib import Path

from config import config
from src.alert_schema import ALERT_SCHEMA_VERSION, build_alert, normalize_alert
from src.sqlite_store import SQLiteAlertRepository
from src.storage import JsonAlertRepository


def _legacy(alert_id=None):
    alert = {
        "timestamp": "2026-09-01T00:00:00Z",
        "alert_name": "Legacy alert",
        "severity": "INFO",
        "status": "DETECTED",
        "source_type": "HIDS_LOG",
        "description": "Pre-versioned record",
    }
    if alert_id:
        alert["alert_id"] = alert_id
    return alert


def test_alert_schema_version():
    current = build_alert(
        alert_name="Versioned alert", severity="HIGH", source_type="HIDS_LOG",
        description="Current contract",
    )
    assert current["alert_schema_version"] == ALERT_SCHEMA_VERSION == 1
    assert current["timeline"] == []

    first, second = normalize_alert(_legacy()), normalize_alert(_legacy())
    assert first["alert_id"] == second["alert_id"]
    assert first["alert_schema_version"] == 1 and first["severity"] == "LOW"
    assert first["incident_id"] is None and first["response_actions"] == []

    for value in (True, "1", None, 2, -1):
        candidate = _legacy("ALT-invalid")
        candidate["alert_schema_version"] = value
        try:
            normalize_alert(candidate)
            raise AssertionError(f"accepted invalid alert_schema_version {value!r}")
        except ValueError as exc:
            assert "alert_schema_version" in str(exc)

    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original_output = config.OUTPUT_ALERT_FILE
        config.OUTPUT_ALERT_FILE = str(directory / "alerts.jsonl")
        try:
            Path(config.OUTPUT_ALERT_FILE).write_text(
                json.dumps(_legacy("ALT-json-legacy")) + "\n", encoding="utf-8",
            )
            json_alert = JsonAlertRepository().get_alert("ALT-json-legacy")
            assert json_alert["alert_schema_version"] == 1
            assert json_alert["severity"] == "LOW"
        finally:
            config.OUTPUT_ALERT_FILE = original_output

        sqlite = SQLiteAlertRepository(str(directory / "alerts.db"))
        sqlite.ensure_schema()
        legacy = _legacy("ALT-sqlite-legacy")
        with sqlite._connect() as connection:
            connection.execute(
                "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    legacy["alert_id"], legacy["timestamp"], legacy["alert_name"],
                    legacy["severity"], legacy["source_type"], None,
                    json.dumps(legacy), legacy["timestamp"], legacy["timestamp"],
                ),
            )
        assert sqlite.get_alert(legacy["alert_id"])["alert_schema_version"] == 1
        assert sqlite.list_alerts()[0]["severity"] == "LOW"


if __name__ == "__main__":
    test_alert_schema_version()
    print("M28.2 alert schema version passed")
