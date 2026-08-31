import hashlib
import json
import os
import threading
from uuid import uuid4

from config import config
from src.alert_schema import utc_iso


AUDIT_EVENTS = {
    "LOGIN",
    "LOGOUT",
    "STATUS_CHANGED",
    "NOTE_ADDED",
    "ASSIGNMENT_CHANGED",
    "RESPONSE_REQUESTED",
    "RESPONSE_APPROVED",
    "RESPONSE_EXECUTED",
    "RESPONSE_ROLLED_BACK",
    "RULE_ENABLED",
    "RULE_DISABLED",
    "RUNTIME_SETTING_CHANGED",
    "ASSET_CREATED",
    "ASSET_UPDATED",
    "ASSET_DELETED",
    "CASE_EXPORT",
    "DETECTION_FEEDBACK_CREATED",
    "DETECTION_EXCEPTION_CREATED",
    "DETECTION_EXCEPTION_DELETED",
    "ALERT_SUPPRESSION_POLICY_CREATED",
    "ALERT_SUPPRESSION_POLICY_DELETED",
    "USER_CREATED",
    "USER_UPDATED",
    "USER_DELETED",
}
GENESIS_HASH = "0" * 64
_audit_lock = threading.Lock()


def _canonical(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _last_hash(path: str) -> str:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return GENESIS_HASH
    with open(path, "rb") as file:
        file.seek(0, os.SEEK_END)
        position = file.tell() - 1
        while position >= 0:
            file.seek(position)
            if file.read(1) not in {b"\n", b"\r"}:
                break
            position -= 1
        end = position + 1
        while position >= 0:
            file.seek(position)
            if file.read(1) == b"\n":
                break
            position -= 1
        file.seek(position + 1)
        line = file.read(end - position - 1).decode("utf-8")
    record = json.loads(line)
    entry_hash = record.get("entry_hash")
    if not isinstance(entry_hash, str) or len(entry_hash) != 64:
        raise ValueError("Audit log has an invalid final record")
    return entry_hash


def append_audit_event(
    event_type: str,
    actor: str,
    *,
    role: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    outcome: str = "SUCCESS",
    details: dict | None = None,
) -> dict:
    event_type = str(event_type).upper()
    if event_type not in AUDIT_EVENTS:
        raise ValueError(f"Unsupported audit event: {event_type}")
    actor = str(actor or "unknown").strip()[:100]
    safe_details = details or {}
    if not isinstance(safe_details, dict):
        raise ValueError("Audit details must be an object")
    if len(_canonical(safe_details).encode("utf-8")) > 8192:
        raise ValueError("Audit details exceed 8192 bytes")

    path = config.ANALYST_AUDIT_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _audit_lock:
        record = {
            "event_id": f"AUD-{uuid4()}",
            "timestamp": utc_iso(),
            "event_type": event_type,
            "actor": actor,
            "role": role,
            "target_type": target_type,
            "target_id": target_id,
            "outcome": str(outcome).upper(),
            "details": safe_details,
            "previous_hash": _last_hash(path),
        }
        record["entry_hash"] = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()
        with open(path, "a", encoding="utf-8") as file:
            file.write(_canonical(record) + "\n")
    return record


def verify_audit_log(path: str | None = None) -> tuple[bool, str]:
    path = path or config.ANALYST_AUDIT_FILE
    if not os.path.exists(path):
        return True, "Audit log is empty"
    previous_hash = GENESIS_HASH
    try:
        with open(path, encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                record = json.loads(line)
                entry_hash = record.pop("entry_hash")
                expected = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()
                if record.get("previous_hash") != previous_hash or entry_hash != expected:
                    return False, f"Audit chain mismatch at line {line_number}"
                previous_hash = entry_hash
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        return False, f"Invalid audit log: {exc}"
    return True, "Audit chain is valid"
