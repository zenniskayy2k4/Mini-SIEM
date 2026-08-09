import json
import os
import threading
from uuid import uuid4

from config import config
from src.alert_schema import ensure_lifecycle, utc_iso


RESPONSE_MODES = {"disabled", "simulation", "manual", "automatic"}
ACTION_HANDLERS = {
    "BLOCK_IP": {"linux": "linux_firewall", "windows": "windows_firewall"},
    "NOTIFY_ANALYST": {"linux": "local_notification", "windows": "event_log"},
}
_audit_lock = threading.Lock()


def build_response_action(
    *, incident_id: str, action_type: str, target: str, mode: str,
    target_os: str, requested_by: str = "detector",
) -> dict:
    mode = str(mode).lower()
    target_os = str(target_os).lower()
    action_type = str(action_type).upper()
    requested_by = str(requested_by).lower()
    if mode not in RESPONSE_MODES:
        raise ValueError(f"Invalid response mode: {mode}")
    if action_type not in ACTION_HANDLERS or target_os not in ACTION_HANDLERS[action_type]:
        raise ValueError(f"Unsupported {action_type} handler for {target_os}")
    if not incident_id or not str(target).strip():
        raise ValueError("Response action requires incident_id and target")

    status = "SKIPPED" if mode == "disabled" else "PROPOSED"
    if requested_by == "llm" and mode != "disabled":
        status = "REQUIRES_APPROVAL"
    return {
        "action_id": f"ACT-{uuid4()}",
        "incident_id": incident_id,
        "action_type": action_type,
        "target": str(target),
        "mode": mode,
        "status": status,
        "requested_by": requested_by,
        "created_at": utc_iso(),
        "target_os": target_os,
        "handler": ACTION_HANDLERS[action_type][target_os],
    }


class IncidentResponder:
    def __init__(self, mode=None, target_os=None):
        self.mode = str(mode or config.RESPONSE_MODE).lower()
        self.target_os = str(target_os or config.RESPONSE_TARGET_OS).lower()
        if self.mode not in RESPONSE_MODES:
            raise ValueError(f"Invalid response mode: {self.mode}")
        if self.target_os not in {"linux", "windows"}:
            raise ValueError(f"Invalid response target OS: {self.target_os}")

    def handle_incident(self, alert):
        ensure_lifecycle(alert)
        if alert["severity"] not in {"HIGH", "CRITICAL"}:
            return alert

        alert["analysis"] = "Incident analyzed: response action proposed from detector evidence."
        if alert["response_actions"]:
            return alert

        action_type, target = self._action_for_alert(alert)
        action = build_response_action(
            incident_id=alert["incident_id"],
            action_type=action_type,
            target=target,
            mode=self.mode,
            target_os=self.target_os,
        )
        alert["response_actions"].append(action)

        if not alert.get("suppressed_count") and not alert.get("deduplicated_events"):
            self._notify(alert, action)
        self._audit(action)
        return alert

    @staticmethod
    def _action_for_alert(alert):
        name = alert.get("alert_name", "")
        ip = alert.get("ip_address")
        if ip and any(term in name for term in ("Brute Force", "Honeypot", "Port Scanning")):
            return "BLOCK_IP", ip
        return "NOTIFY_ANALYST", alert["incident_id"]

    @staticmethod
    def _notify(alert, action):
        print(
            f"\n[INCIDENT RESPONSE] {alert['alert_name']} -> "
            f"{action['action_type']} {action['target']} [{action['status']}]"
        )

    @staticmethod
    def _audit(action):
        os.makedirs(os.path.dirname(config.RESPONSE_LOG_FILE), exist_ok=True)
        with _audit_lock, open(config.RESPONSE_LOG_FILE, "a", encoding="utf-8") as file:
            file.write(json.dumps(action, ensure_ascii=False) + "\n")
