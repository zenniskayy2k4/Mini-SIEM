"""Small runnable check for Batch M3.1 lifecycle fields."""

import json
import tempfile
from pathlib import Path

from config import config
from dashboard import load_alerts
from src.ai_analyst import AIAnalyst
from src.alert_schema import build_alert
from src.alert_store import upsert_alert


def main():
    high = build_alert(
        alert_name="Check", severity="HIGH", source_type="HIDS_LOG",
        description="check",
    )
    low = build_alert(
        alert_name="Check", severity="LOW", source_type="HIDS_LOG",
        description="check",
    )
    assert high["incident_id"].startswith("INC-") and high["incident_status"] == "NEW"
    assert low["incident_id"] is None and low["incident_status"] is None
    assert high["assigned_to"] is None and high["analyst_notes"] == []
    assert high["created_at"].endswith("Z") and high["updated_at"].endswith("Z")
    AIAnalyst._apply_ai_recommendation(high, {"escalate_to_human": True})
    assert high["incident_status"] == "NEW"

    low["severity"] = "HIGH"
    original_path = config.OUTPUT_ALERT_FILE
    with tempfile.TemporaryDirectory() as directory:
        config.OUTPUT_ALERT_FILE = str(Path(directory) / "escalated.json")
        upsert_alert(low)
        assert low["incident_id"].startswith("INC-") and low["incident_status"] == "NEW"
    config.OUTPUT_ALERT_FILE = original_path

    alerts = [
        build_alert(alert_name="Check", severity="HIGH", source_type="HIDS_LOG", description="check")
        for _ in range(100)
    ]
    assert len({alert["alert_id"] for alert in alerts}) == 100
    assert len({alert["incident_id"] for alert in alerts}) == 100

    original_path = config.OUTPUT_ALERT_FILE
    with tempfile.TemporaryDirectory() as directory:
        config.OUTPUT_ALERT_FILE = str(Path(directory) / "alerts.json")
        upsert_alert(high)
        first_load = load_alerts()
        second_load = load_alerts()
        assert first_load[0]["alert_id"] == second_load[0]["alert_id"] == high["alert_id"]
        assert first_load[0]["incident_id"] == second_load[0]["incident_id"] == high["incident_id"]

        Path(config.OUTPUT_ALERT_FILE).write_text(
            json.dumps({"timestamp": high["timestamp"], "alert_name": "Legacy"}) + "\n",
            encoding="utf-8",
        )
        assert load_alerts()[0]["alert_name"] == "Legacy"
    config.OUTPUT_ALERT_FILE = original_path

    print("Batch M3.1 check passed")


if __name__ == "__main__":
    main()
