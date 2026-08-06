"""Small runnable check for Batch M3.4 incident dashboard filters and controls."""

import tempfile
from pathlib import Path

from config import config
from dashboard import app
from src.alert_schema import build_alert
from src.alert_store import upsert_alert


def main():
    original_path = config.OUTPUT_ALERT_FILE
    with tempfile.TemporaryDirectory() as directory:
        config.OUTPUT_ALERT_FILE = str(Path(directory) / "alerts.json")
        human_review = build_alert(
            alert_name="Review", severity="HIGH", source_type="HIDS_LOG",
            description="needs analyst", ai_disposition="REQUIRES_HUMAN_REVIEW",
        )
        investigating = build_alert(
            alert_name="Assigned", severity="CRITICAL", source_type="NIDS",
            description="already triaged", incident_status="INVESTIGATING",
        )
        no_incident = build_alert(
            alert_name="Routine", severity="LOW", source_type="HIDS_LOG",
            description="no AI and no incident",
        )
        for alert in (human_review, investigating, no_incident):
            upsert_alert(alert)

        client = app.test_client()
        response = client.get("/api/alerts/search?incident_status=INVESTIGATING")
        assert response.status_code == 200
        assert [item["alert_id"] for item in response.json["items"]] == [investigating["alert_id"]]

        response = client.get("/api/alerts/search?human_review=true")
        assert [item["alert_id"] for item in response.json["items"]] == [human_review["alert_id"]]

    config.OUTPUT_ALERT_FILE = original_path

    root = Path(__file__).resolve().parents[1]
    html = (root / "templates" / "logs.html").read_text(encoding="utf-8")
    js = (root / "static" / "js" / "app.js").read_text(encoding="utf-8")
    for marker in ("filter-incident-status", "filter-human-review"):
        assert marker in html
    for marker in ("renderIncidentPanel", "incident-status-btn", "incident-note-btn", "incident-error"):
        assert marker in js
    assert "System severity" in js and "AI recommendation" in js

    print("Batch M3.4 check passed")


if __name__ == "__main__":
    main()
