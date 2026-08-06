"""Small runnable check for Batch M3.3 notes and assignment APIs."""

import json
import tempfile
from pathlib import Path

from config import config
from dashboard import app
from src.alert_schema import build_alert
from src.alert_store import MAX_NOTE_LENGTH, upsert_alert


def main():
    original_path = config.OUTPUT_ALERT_FILE
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "alerts.json"
        config.OUTPUT_ALERT_FILE = str(path)
        alert = build_alert(
            alert_name="Incident", severity="HIGH", source_type="HIDS_LOG",
            description="notes check",
        )
        upsert_alert(alert)
        client = app.test_client()
        alert_url = f"/api/alerts/{alert['alert_id']}"

        assert client.patch(f"{alert_url}/status", json={"status": "INVESTIGATING"}).status_code == 200
        assert client.post(f"{alert_url}/notes", json={"note": "   "}).status_code == 400
        assert client.post(f"{alert_url}/notes", json={"note": "x" * (MAX_NOTE_LENGTH + 1)}).status_code == 400
        response = client.post(
            f"{alert_url}/notes",
            json={"note": "<script>alert(1)</script>", "author": "<b>alice</b>"},
        )
        assert response.status_code == 200
        note = response.json["analyst_notes"][0]
        assert note["text"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
        assert note["author"] == "&lt;b&gt;alice&lt;/b&gt;" and note["timestamp"].endswith("Z")

        response = client.patch(f"{alert_url}/assignee", json={"assigned_to": "<b>bob</b>"})
        assert response.status_code == 200 and response.json["assigned_to"] == "&lt;b&gt;bob&lt;/b&gt;"
        assert client.patch(f"{alert_url}/assignee", json={}).status_code == 400
        assert client.post("/api/alerts/ALT-missing/notes", json={"note": "check"}).status_code == 404
        assert client.patch("/api/alerts/ALT-missing/assignee", json={"assigned_to": "bob"}).status_code == 404

        persisted = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert persisted["analyst_notes"] == response.json["analyst_notes"]
        assert persisted["assigned_to"] == "&lt;b&gt;bob&lt;/b&gt;"
        assert client.get("/api/alerts").json[0]["assigned_to"] == persisted["assigned_to"]
        assert [event["event_type"] for event in persisted["timeline"]] == [
            "STATUS_CHANGED", "NOTE_ADDED", "ASSIGNMENT_CHANGED",
        ]
    config.OUTPUT_ALERT_FILE = original_path

    print("Batch M3.3 check passed")


if __name__ == "__main__":
    main()
