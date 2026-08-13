import json
import os
import threading
from urllib.parse import urlparse
from uuid import uuid4

import requests

from config import config
from src.alert_schema import utc_iso


class WebhookNotifier:
    def __init__(self, url=None, webhook_format=None):
        self.url = (config.NOTIFICATION_WEBHOOK_URL if url is None else url).strip()
        self.webhook_format = (webhook_format or config.NOTIFICATION_WEBHOOK_FORMAT).lower()
        if self.webhook_format not in {"generic", "discord"}:
            raise ValueError("Notification webhook format must be generic or discord")
        if self.url and urlparse(self.url).scheme not in {"http", "https"}:
            raise ValueError("Notification webhook URL must use http or https")
        self._lock = threading.Lock()
        self._sent = self._load_sent_keys()

    @staticmethod
    def _eligible(alert):
        return (
            str(alert.get("severity") or "").upper() in {"HIGH", "CRITICAL"}
            or alert.get("ai_disposition") == "REQUIRES_HUMAN_REVIEW"
        )

    @staticmethod
    def _key(alert):
        return alert.get("incident_id") or alert.get("alert_id")

    @staticmethod
    def _safe_payload(alert):
        return {
            "alert_id": alert.get("alert_id"),
            "incident_id": alert.get("incident_id"),
            "alert_name": alert.get("alert_name"),
            "severity": alert.get("severity"),
            "source_type": alert.get("source_type"),
            "ip_address": alert.get("ip_address"),
            "mitre_attck_id": alert.get("mitre_attck_id"),
            "ai_disposition": alert.get("ai_disposition"),
            "timestamp": alert.get("timestamp"),
        }

    def _load_sent_keys(self):
        sent = set()
        try:
            with open(config.NOTIFICATION_LOG_FILE, encoding="utf-8") as file:
                for line in file:
                    event = json.loads(line)
                    if event.get("status") == "SENT" and event.get("dedup_key"):
                        sent.add(event["dedup_key"])
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return sent

    def notify(self, alert):
        if not self.url or not self._eligible(alert):
            return None
        key = self._key(alert)
        if not key:
            return None

        with self._lock:
            if key in self._sent:
                return {"dedup_key": key, "status": "DEDUPLICATED", "attempts": 0}

            # ponytail: serialize delivery per process; add a queue only if webhook throughput matters.
            safe_alert = self._safe_payload(alert)
            payload = (
                {"content": f"[{safe_alert['severity']}] {safe_alert['alert_name']} ({safe_alert['incident_id'] or safe_alert['alert_id']})"}
                if self.webhook_format == "discord"
                else {"event": "siem_alert", "alert": safe_alert}
            )
            error = None
            for attempt in range(1, config.NOTIFICATION_MAX_ATTEMPTS + 1):
                try:
                    response = requests.post(
                        self.url,
                        json=payload,
                        timeout=config.NOTIFICATION_TIMEOUT_SECONDS,
                    )
                    response.raise_for_status()
                    self._sent.add(key)
                    return self._audit(key, alert, "SENT", attempt)
                except requests.RequestException as exc:
                    response = getattr(exc, "response", None)
                    error = f"HTTP {response.status_code}" if response is not None else type(exc).__name__
            return self._audit(key, alert, "FAILED", config.NOTIFICATION_MAX_ATTEMPTS, error)

    @staticmethod
    def _audit(key, alert, status, attempts, error=None):
        event = {
            "notification_id": f"NTF-{uuid4()}",
            "dedup_key": key,
            "alert_id": alert.get("alert_id"),
            "incident_id": alert.get("incident_id"),
            "status": status,
            "attempts": attempts,
            "timestamp": utc_iso(),
        }
        if error:
            event["error"] = error
        os.makedirs(os.path.dirname(config.NOTIFICATION_LOG_FILE), exist_ok=True)
        with open(config.NOTIFICATION_LOG_FILE, "a", encoding="utf-8") as file:
            file.write(json.dumps(event, ensure_ascii=False) + "\n")
        return event


notification_service = WebhookNotifier()
