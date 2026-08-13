from datetime import datetime, timezone
from uuid import uuid4


SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
SOURCE_TYPES = {"HIDS_LOG", "WINDOWS_EVENT", "NIDS", "HONEYPOT", "CORRELATION"}
INCIDENT_STATUSES = {"NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"}


def utc_iso(value=None) -> str:
    if value is None:
        value = datetime.now(timezone.utc)
    elif isinstance(value, str):
        value = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_lifecycle(alert: dict) -> dict:
    alert.pop("mitigation", None)
    alert.pop("mitigation_command", None)
    if not alert.get("alert_id"):
        alert["alert_id"] = f"ALT-{uuid4()}"
    alert["created_at"] = utc_iso(alert.get("created_at") or alert.get("timestamp"))
    alert["updated_at"] = utc_iso(alert.get("updated_at") or alert["created_at"])

    if alert.get("severity") in {"HIGH", "CRITICAL"} and not alert.get("incident_id"):
        alert["incident_id"] = f"INC-{uuid4()}"
    alert.setdefault("incident_id", None)

    incident_status = alert.get("incident_status") or ("NEW" if alert["incident_id"] else None)
    if incident_status and incident_status not in INCIDENT_STATUSES:
        raise ValueError(f"Invalid incident status: {incident_status}")
    alert["incident_status"] = incident_status
    alert.setdefault("rule_id", None)
    alert.setdefault("assigned_to", None)
    alert["analyst_notes"] = list(alert.get("analyst_notes") or [])
    alert["response_actions"] = list(alert.get("response_actions") or [])
    return alert


def build_alert(
    *, alert_name: str, severity: str, source_type: str, description: str,
    raw_log=None, ip_address=None, mitre_attck_id=None, timestamp=None,
    status="DETECTED", alert_id=None, event_count=1, first_seen=None,
    last_seen=None, correlation_key=None, ml_confidence=None,
    ai_analysis=None, ai_recommended_severity=None, ai_disposition=None,
    rule_id=None,
    incident_id=None, incident_status=None, assigned_to=None,
    analyst_notes=None, created_at=None, updated_at=None,
    **extra,
) -> dict:
    severity = severity.upper()
    source_type = source_type.upper()
    status = status.upper()
    if severity not in SEVERITIES:
        raise ValueError(f"Invalid alert severity: {severity}")
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"Invalid alert source type: {source_type}")
    if status != "DETECTED":
        raise ValueError(f"Invalid alert status: {status}")

    timestamp = utc_iso(timestamp)
    alert = {
        "alert_id": alert_id or f"ALT-{uuid4()}",
        "timestamp": timestamp,
        "alert_name": alert_name,
        "severity": severity,
        "status": status,
        "source_type": source_type,
        "description": description,
        "raw_log": raw_log,
        "ip_address": ip_address,
        "mitre_attck_id": mitre_attck_id,
        "event_count": event_count,
        "first_seen": utc_iso(first_seen) if first_seen else timestamp,
        "last_seen": utc_iso(last_seen) if last_seen else timestamp,
        "correlation_key": correlation_key,
        "ml_confidence": ml_confidence,
        "ai_analysis": ai_analysis,
        "ai_recommended_severity": ai_recommended_severity,
        "ai_disposition": ai_disposition,
        "rule_id": rule_id,
        "incident_id": incident_id,
        "incident_status": incident_status,
        "assigned_to": assigned_to,
        "analyst_notes": list(analyst_notes or []),
        "created_at": created_at or timestamp,
        "updated_at": updated_at or created_at or timestamp,
    }
    alert.update(extra)
    return ensure_lifecycle(alert)
