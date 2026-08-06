import json
import os
import threading
from contextlib import contextmanager
from config import config
from src.alert_schema import INCIDENT_STATUSES, ensure_lifecycle, utc_iso

try:
    import fcntl
except ImportError:  # Windows host fallback; production runs in Linux containers.
    fcntl = None

_lock = threading.Lock()


@contextmanager
def _store_lock():
    os.makedirs(os.path.dirname(config.OUTPUT_ALERT_FILE), exist_ok=True)
    with _lock, open(config.OUTPUT_ALERT_FILE + ".lock", "a", encoding="utf-8") as lock_file:
        # ponytail: flock covers Docker/Linux; SQLite replaces this lock in M4.
        if fcntl:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl:
                fcntl.flock(lock_file, fcntl.LOCK_UN)


def _same_alert(left: dict, right: dict) -> bool:
    if left.get("alert_id") and right.get("alert_id"):
        return left["alert_id"] == right["alert_id"]
    return (
        left.get("timestamp") == right.get("timestamp")
        and left.get("alert_name") == right.get("alert_name")
        and left.get("raw_log") == right.get("raw_log")
    )


def upsert_alert(alert: dict) -> None:
    """
    Replace the existing JSONL row for this alert, or append if missing.
    """
    ensure_lifecycle(alert)
    alert["updated_at"] = utc_iso()

    with _store_lock():
        lines = []
        replaced = False
        if os.path.exists(config.OUTPUT_ALERT_FILE):
            with open(config.OUTPUT_ALERT_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

        with open(config.OUTPUT_ALERT_FILE, "w", encoding="utf-8") as f:
            for line in lines:
                try:
                    existing = json.loads(line)
                except json.JSONDecodeError:
                    f.write(line)
                    continue
                if not replaced and _same_alert(existing, alert):
                    f.write(json.dumps(alert, ensure_ascii=False) + "\n")
                    replaced = True
                else:
                    f.write(line)
            if not replaced:
                f.write(json.dumps(alert, ensure_ascii=False) + "\n")


def update_incident_status(alert_id: str, status: str) -> dict | None:
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"Invalid incident status: {status}")

    with _store_lock():
        if not os.path.exists(config.OUTPUT_ALERT_FILE):
            return None
        with open(config.OUTPUT_ALERT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        updated = None
        updated_index = None
        for index, line in enumerate(lines):
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            if alert.get("alert_id") == alert_id:
                ensure_lifecycle(alert)
                if not alert.get("incident_id"):
                    raise ValueError("Alert is not incident-worthy")
                changed_at = utc_iso()
                previous = alert["incident_status"]
                alert["incident_status"] = status
                alert["updated_at"] = changed_at
                alert["timeline"] = list(alert.get("timeline") or [])
                alert["timeline"].append({
                    "event_type": "STATUS_CHANGED",
                    "from_status": previous,
                    "to_status": status,
                    "timestamp": changed_at,
                })
                updated = alert
                updated_index = index
                break
        if updated is None:
            return None

        lines[updated_index] = json.dumps(updated, ensure_ascii=False) + "\n"
        with open(config.OUTPUT_ALERT_FILE, "w", encoding="utf-8") as f:
            f.writelines(lines)
        return updated
