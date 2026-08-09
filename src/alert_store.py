from html import escape

from config import config
from src.alert_schema import INCIDENT_STATUSES, ensure_lifecycle, utc_iso
from src.response import (
    ACTION_HANDLERS,
    audit_response_action,
    build_response_action,
    simulate_response_action,
)
from src.storage import alert_repository

MAX_NOTE_LENGTH = 2000
MAX_IDENTITY_LENGTH = 100
MAX_ACTION_TARGET_LENGTH = 500


def upsert_alert(alert: dict) -> None:
    """
    Replace the existing JSONL row for this alert, or append if missing.
    """
    ensure_lifecycle(alert)
    alert["updated_at"] = utc_iso()

    alert_repository.create_alert(alert)


def _update_incident(alert_id: str, mutate) -> dict | None:
    def checked_mutation(alert):
        ensure_lifecycle(alert)
        if not alert.get("incident_id"):
            raise ValueError("Alert is not incident-worthy")
        mutate(alert)

    return alert_repository.update_alert(alert_id, checked_mutation)


def _record_event(alert: dict, event_type: str, **details) -> str:
    changed_at = utc_iso()
    alert["updated_at"] = changed_at
    alert["timeline"] = list(alert.get("timeline") or [])
    alert["timeline"].append({"event_type": event_type, "timestamp": changed_at, **details})
    return changed_at


def update_incident_status(alert_id: str, status: str) -> dict | None:
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"Invalid incident status: {status}")

    def mutate(alert):
        previous = alert["incident_status"]
        alert["incident_status"] = status
        _record_event(alert, "STATUS_CHANGED", from_status=previous, to_status=status)

    return _update_incident(alert_id, mutate)


def add_analyst_note(alert_id: str, text: str, author="analyst") -> dict | None:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Note must not be empty")
    text = text.strip()
    if len(text) > MAX_NOTE_LENGTH:
        raise ValueError(f"Note exceeds {MAX_NOTE_LENGTH} characters")
    if not isinstance(author, str) or not author.strip() or len(author.strip()) > MAX_IDENTITY_LENGTH:
        raise ValueError("Invalid note author")
    text, author = escape(text), escape(author.strip())

    def mutate(alert):
        changed_at = _record_event(alert, "NOTE_ADDED", author=author)
        alert["analyst_notes"] = list(alert.get("analyst_notes") or [])
        alert["analyst_notes"].append({"text": text, "author": author, "timestamp": changed_at})

    return _update_incident(alert_id, mutate)


def update_assignee(alert_id: str, assigned_to) -> dict | None:
    if assigned_to is not None and not isinstance(assigned_to, str):
        raise ValueError("Invalid assignee")
    assigned_to = assigned_to.strip() if assigned_to else None
    if assigned_to and len(assigned_to) > MAX_IDENTITY_LENGTH:
        raise ValueError(f"Assignee exceeds {MAX_IDENTITY_LENGTH} characters")
    assigned_to = escape(assigned_to) if assigned_to else None

    def mutate(alert):
        previous = alert.get("assigned_to")
        alert["assigned_to"] = assigned_to
        _record_event(
            alert, "ASSIGNMENT_CHANGED", from_assignee=previous, to_assignee=assigned_to,
        )

    return _update_incident(alert_id, mutate)


def request_response_action(alert_id: str, action_type: str, target: str) -> dict | None:
    if not isinstance(action_type, str) or action_type.upper() not in ACTION_HANDLERS:
        raise ValueError("Invalid response action type")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Response action target is required")
    action_type, target = action_type.upper(), target.strip()
    if len(target) > MAX_ACTION_TARGET_LENGTH:
        raise ValueError(f"Target exceeds {MAX_ACTION_TARGET_LENGTH} characters")

    def mutate(alert):
        action = build_response_action(
            incident_id=alert["incident_id"],
            action_type=action_type,
            target=target,
            mode=config.RESPONSE_MODE,
            target_os=config.RESPONSE_TARGET_OS,
            requested_by="analyst",
        )
        if action["mode"] == "simulation":
            simulate_response_action(action)
        alert["response_actions"].append(action)
        _record_event(
            alert,
            f"RESPONSE_ACTION_{action['status']}",
            action_id=action["action_id"],
            action_type=action_type,
            target=target,
            status=action["status"],
        )
        audit_response_action(action)

    return _update_incident(alert_id, mutate)
