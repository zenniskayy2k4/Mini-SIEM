"""Small runnable check for Batch M3.2 status API and concurrent writes."""

import json
import tempfile
from multiprocessing import Process
from pathlib import Path

from config import config
from dashboard import app
from src.alert_schema import build_alert
from src.alert_store import update_incident_status, upsert_alert


def append_worker(path, count):
    config.OUTPUT_ALERT_FILE = path
    for index in range(count):
        upsert_alert(build_alert(
            alert_name=f"Concurrent {index}", severity="LOW", source_type="HIDS_LOG",
            description="concurrency check",
        ))


def update_worker(path, alert_id):
    config.OUTPUT_ALERT_FILE = path
    assert update_incident_status(alert_id, "INVESTIGATING")


def main():
    original_path = config.OUTPUT_ALERT_FILE
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory) / "alerts.json")
        config.OUTPUT_ALERT_FILE = path
        alert = build_alert(
            alert_name="Incident", severity="HIGH", source_type="HIDS_LOG",
            description="status check",
        )
        upsert_alert(alert)

        client = app.test_client()
        for status in ("INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"):
            response = client.patch(f"/api/alerts/{alert['alert_id']}/status", json={"status": status})
            assert response.status_code == 200 and response.json["incident_status"] == status
        assert len(response.json["timeline"]) == 4
        assert client.patch(f"/api/alerts/{alert['alert_id']}/status", json={"status": "BAD"}).status_code == 400
        assert client.patch("/api/alerts/ALT-missing/status", json={"status": "NEW"}).status_code == 404

        persisted = json.loads(Path(path).read_text(encoding="utf-8").splitlines()[0])
        assert persisted["incident_status"] == "FALSE_POSITIVE"
        assert persisted["updated_at"] == persisted["timeline"][-1]["timestamp"]

        Path(path).write_text("", encoding="utf-8")
        upsert_alert(alert)
        append = Process(target=append_worker, args=(path, 20))
        update = Process(target=update_worker, args=(path, alert["alert_id"]))
        append.start()
        update.start()
        append.join()
        update.join()
        assert append.exitcode == update.exitcode == 0
        rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]
        assert len(rows) == 21
        assert next(row for row in rows if row["alert_id"] == alert["alert_id"])["incident_status"] == "INVESTIGATING"
    config.OUTPUT_ALERT_FILE = original_path

    print("Batch M3.2 check passed")


if __name__ == "__main__":
    main()
