import json
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid4, uuid5


ALERT_SCHEMA_VERSION = 1
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


def legacy_alert_id(alert: dict) -> str:
    identity = {key: value for key, value in alert.items() if key != "alert_schema_version"}
    canonical = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"ALT-{uuid5(NAMESPACE_URL, canonical)}"


def normalize_alert(alert: dict) -> dict:
    if not isinstance(alert, dict):
        raise ValueError("alert must be a JSON object")
    version = alert.get("alert_schema_version", 0)
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError("alert_schema_version must be an integer")
    if version not in {0, ALERT_SCHEMA_VERSION}:
        raise ValueError(
            f"unsupported alert_schema_version {version}; "
            f"supported versions: legacy 0, {ALERT_SCHEMA_VERSION}"
        )
    if version == ALERT_SCHEMA_VERSION and not alert.get("alert_id"):
        raise ValueError("v1 alert requires alert_id")
    if not alert.get("alert_id"):
        alert["alert_id"] = legacy_alert_id(alert)
    if version == 0 and str(alert.get("severity") or "").upper() == "INFO":
        alert["severity"] = "LOW"
    alert["alert_schema_version"] = ALERT_SCHEMA_VERSION
    return ensure_lifecycle(alert)


def ensure_lifecycle(alert: dict) -> dict:
    alert.pop("mitigation", None)
    alert.pop("mitigation_command", None)
    if not alert.get("alert_id"):
        alert["alert_id"] = f"ALT-{uuid4()}"
    alert["created_at"] = utc_iso(alert.get("created_at") or alert.get("timestamp"))
    alert["updated_at"] = utc_iso(alert.get("updated_at") or alert["created_at"])

    if (
        alert.get("status") != "EXCEPTED"
        and alert.get("severity") in {"HIGH", "CRITICAL"}
        and not alert.get("incident_id")
    ):
        alert["incident_id"] = f"INC-{uuid4()}"
    alert.setdefault("incident_id", None)

    incident_status = alert.get("incident_status") or ("NEW" if alert["incident_id"] else None)
    if incident_status and incident_status not in INCIDENT_STATUSES:
        raise ValueError(f"Invalid incident status: {incident_status}")
    alert["incident_status"] = incident_status
    alert.setdefault("rule_id", None)
    rule_source = alert.get("rule_source") or ("native" if alert["rule_id"] else None)
    if rule_source not in {None, "native", "sigma"}:
        raise ValueError(f"Invalid rule source: {rule_source}")
    if rule_source == "sigma" and not alert.get("sigma_rule_id"):
        raise ValueError("Sigma alerts require sigma_rule_id")
    alert["rule_source"] = rule_source
    alert.setdefault("sigma_rule_id", None)
    alert.setdefault("assigned_to", None)
    alert.setdefault("asset_id", None)
    alert.setdefault("risk_score", 0)
    alert.setdefault("risk_level", "LOW")
    alert["risk_factors"] = list(alert.get("risk_factors") or [])
    external_cases = alert.get("external_cases") or {}
    if not isinstance(external_cases, dict):
        raise ValueError("external_cases must be an object")
    alert["external_cases"] = dict(external_cases)
    alert["analyst_notes"] = list(alert.get("analyst_notes") or [])
    alert["response_actions"] = list(alert.get("response_actions") or [])
    alert["timeline"] = list(alert.get("timeline") or [])
    return alert


def build_alert(
    *, alert_name: str, severity: str, source_type: str, description: str,
    raw_log=None, ip_address=None, mitre_attck_id=None, timestamp=None,
    status="DETECTED", alert_id=None, event_count=1, first_seen=None,
    last_seen=None, correlation_key=None, ml_confidence=None,
    ai_analysis=None, ai_recommended_severity=None, ai_disposition=None,
    rule_id=None, rule_source=None, sigma_rule_id=None,
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
        "alert_schema_version": ALERT_SCHEMA_VERSION,
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
        "rule_source": rule_source,
        "sigma_rule_id": sigma_rule_id,
        "incident_id": incident_id,
        "incident_status": incident_status,
        "assigned_to": assigned_to,
        "analyst_notes": list(analyst_notes or []),
        "created_at": created_at or timestamp,
        "updated_at": updated_at or created_at or timestamp,
    }
    alert.update(extra)
    return normalize_alert(alert)
