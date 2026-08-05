import json
import os
import threading
from config import config

_lock = threading.Lock()


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
    os.makedirs(os.path.dirname(config.OUTPUT_ALERT_FILE), exist_ok=True)

    with _lock:
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
