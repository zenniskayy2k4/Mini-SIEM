import json
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4

from config import config
from src.alert_schema import ensure_lifecycle, utc_iso


RESPONSE_MODES = {"disabled", "simulation", "manual", "automatic"}
ACTION_HANDLERS = {
    "BLOCK_IP": {"linux": "linux_firewall", "windows": "windows_firewall"},
    "UNBLOCK_IP": {"linux": "linux_firewall", "windows": "windows_firewall"},
    "DISABLE_USER": {"linux": "linux_account", "windows": "windows_account"},
    "KILL_PROCESS": {"linux": "linux_process", "windows": "windows_process"},
    "QUARANTINE_FILE": {"linux": "linux_filesystem", "windows": "windows_filesystem"},
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
    created_at = utc_iso()
    action = {
        "action_id": f"ACT-{uuid4()}",
        "incident_id": incident_id,
        "action_type": action_type,
        "target": str(target),
        "mode": mode,
        "status": status,
        "requested_by": requested_by,
        "created_at": created_at,
        "target_os": target_os,
        "handler": ACTION_HANDLERS[action_type][target_os],
    }
    if status in {"PROPOSED", "REQUIRES_APPROVAL"}:
        action["approval_expires_at"] = utc_iso(
            datetime.now(timezone.utc) + timedelta(seconds=config.RESPONSE_APPROVAL_TIMEOUT_SECONDS)
        )
    return action


def validate_response_target(action_type: str, target: str) -> str:
    action_type, target = str(action_type).upper(), str(target).strip()
    if action_type not in ACTION_HANDLERS:
        raise ValueError("Invalid response action type")
    if not target or len(target) > 500 or any(character in target for character in "\x00\r\n"):
        raise ValueError("Invalid response action target")
    protected = config.RESPONSE_PROTECTED_TARGETS
    if target.lower() in protected:
        raise ValueError("Protected target cannot receive response actions")

    if action_type in {"BLOCK_IP", "UNBLOCK_IP"}:
        try:
            address = ip_address(target)
        except ValueError as exc:
            raise ValueError("IP response action requires a valid IP address") from exc
        if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ValueError("Protected IP cannot receive response actions")
        return str(address)
    if action_type == "DISABLE_USER":
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", target):
            raise ValueError("Invalid user target")
    elif action_type == "KILL_PROCESS":
        if not target.isdigit() or int(target) <= 1:
            raise ValueError("Process target must be a PID greater than 1")
    elif action_type == "QUARANTINE_FILE":
        path = Path(target)
        if not path.is_absolute():
            raise ValueError("Quarantine target must be an absolute path")
        resolved = path.resolve(strict=False)
        for protected_target in protected:
            protected_path = Path(protected_target)
            protects_descendants = protected_path != Path(protected_path.anchor)
            if protected_path.is_absolute() and (
                resolved == protected_path
                or protects_descendants and protected_path in resolved.parents
            ):
                raise ValueError("Protected path cannot receive response actions")
        return str(resolved)
    elif action_type == "NOTIFY_ANALYST":
        if len(target) > 500:
            raise ValueError("Notification target is too long")
    return target


def simulate_response_action(action: dict) -> dict:
    if action.get("mode") != "simulation" and action.get("status") != "APPROVED":
        raise ValueError("Action must be simulation-mode or approved")
    action["status"] = "SIMULATED"
    action["result"] = f"would execute {action['action_type']} on {action['target']}"
    return action


def audit_response_action(action: dict) -> None:
    os.makedirs(os.path.dirname(config.RESPONSE_LOG_FILE), exist_ok=True)
    with _audit_lock, open(config.RESPONSE_LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(action, ensure_ascii=False) + "\n")


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
        audit_response_action(action)
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
