from datetime import datetime, timezone
from uuid import uuid4


SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
SOURCE_TYPES = {"HIDS_LOG", "NIDS", "HONEYPOT", "CORRELATION"}


def utc_iso(value=None) -> str:
    if value is None:
        value = datetime.now(timezone.utc)
    elif isinstance(value, str):
        value = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_alert(
    *, alert_name: str, severity: str, source_type: str, description: str,
    raw_log=None, ip_address=None, mitre_attck_id=None, timestamp=None,
    status="DETECTED", alert_id=None, event_count=1, first_seen=None,
    last_seen=None, correlation_key=None, ml_confidence=None,
    ai_analysis=None, ai_recommended_severity=None, ai_disposition=None,
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
    }
    alert.update(extra)
    return alert
