from html import escape
from datetime import datetime, timedelta, timezone

from config import config
from src.alert_schema import INCIDENT_STATUSES, ensure_lifecycle, utc_iso
from src.response import (
    ACTION_HANDLERS,
    audit_response_action,
    build_response_action,
    simulate_response_action,
    validate_response_target,
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
    target = validate_response_target(action_type, target)

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


def _response_action(alert: dict, action_id: str) -> dict:
    action = next(
        (item for item in alert["response_actions"] if item.get("action_id") == action_id),
        None,
    )
    if action is None:
        raise ValueError("Response action not found")
    return action


def _action_event(alert: dict, action: dict) -> None:
    _record_event(
        alert,
        f"RESPONSE_ACTION_{action['status']}",
        action_id=action["action_id"],
        action_type=action["action_type"],
        target=action["target"],
        status=action["status"],
    )
    audit_response_action(dict(action))


def approve_response_action(alert_id: str, action_id: str, analyst="analyst") -> dict | None:
    if not isinstance(analyst, str) or not analyst.strip() or len(analyst.strip()) > MAX_IDENTITY_LENGTH:
        raise ValueError("Invalid analyst identity")
    analyst = escape(analyst.strip())

    def mutate(alert):
        action = _response_action(alert, action_id)
        if action.get("status") not in {"PROPOSED", "REQUIRES_APPROVAL"}:
            raise ValueError("Response action is not awaiting approval")
        try:
            expires_value = action.get("approval_expires_at")
            if expires_value:
                expires_at = datetime.fromisoformat(expires_value.replace("Z", "+00:00"))
            else:
                created_at = datetime.fromisoformat(action["created_at"].replace("Z", "+00:00"))
                expires_at = created_at + timedelta(seconds=config.RESPONSE_APPROVAL_TIMEOUT_SECONDS)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= datetime.now(timezone.utc):
                raise TimeoutError("Approval window expired")
            action["target"] = validate_response_target(action["action_type"], action["target"])
        except (KeyError, TypeError, ValueError, TimeoutError) as exc:
            action["status"] = "FAILED"
            action["error"] = str(exc)
            _action_event(alert, action)
            return

        action["status"] = "APPROVED"
        action["approved_by"] = analyst
        action["approved_at"] = utc_iso()
        _action_event(alert, action)
        simulate_response_action(action)
        _action_event(alert, action)

    return _update_incident(alert_id, mutate)


def rollback_response_action(alert_id: str, action_id: str, analyst="analyst") -> dict | None:
    if not isinstance(analyst, str) or not analyst.strip() or len(analyst.strip()) > MAX_IDENTITY_LENGTH:
        raise ValueError("Invalid analyst identity")
    analyst = escape(analyst.strip())

    def mutate(alert):
        action = _response_action(alert, action_id)
        if action.get("status") != "SIMULATED":
            raise ValueError("Only simulated actions can be rolled back")
        action["status"] = "ROLLED_BACK"
        action["rolled_back_by"] = analyst
        action["rolled_back_at"] = utc_iso()
        action["result"] = "simulation rolled back; no system change was made"
        _action_event(alert, action)

    return _update_incident(alert_id, mutate)
