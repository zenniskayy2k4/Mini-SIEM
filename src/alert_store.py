import json
import os
import threading
from config import config

_lock = threading.Lock()

def append_alert(alert: dict) -> None:
    """
    Thread-safe append-1-line JSON alert into OUTPUT_ALERT_FILE.
    """
    os.makedirs(os.path.dirname(config.OUTPUT_ALERT_FILE), exist_ok=True)
    line = json.dumps(alert, ensure_ascii=False)

    with _lock:
        with open(config.OUTPUT_ALERT_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")