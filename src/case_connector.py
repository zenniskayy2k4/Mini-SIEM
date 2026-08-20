from abc import ABC, abstractmethod
import re
import threading

from src.alert_schema import utc_iso
from src.audit import append_audit_event


class CaseConnector(ABC):
    name: str

    @abstractmethod
    def create_case(self, incident, *, timeout_seconds):
        """Create or find a case using incident_id as the idempotency key."""

    @abstractmethod
    def update_case(self, external_id, incident, *, timeout_seconds):
        """Update an existing external case."""


class CaseExportService:
    def __init__(
        self, connector=None, *, enabled=False, timeout_seconds=5, max_attempts=2,
    ):
        if connector is not None and not isinstance(connector, CaseConnector):
            raise TypeError("connector must implement CaseConnector")
        if connector is not None and not re.fullmatch(
            r"[a-z0-9_.-]{1,50}", connector.name,
        ):
            raise ValueError("Connector name must be a lowercase identifier")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("Case export timeout must be positive")
        if (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or not 1 <= max_attempts <= 3
        ):
            raise ValueError("Case export attempts must be between 1 and 3")
        self.connector = connector
        self.enabled = bool(enabled)
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts
        # ponytail: one dashboard process serializes manual exports; use a shared lock if scaled out.
        self._lock = threading.Lock()

    @property
    def provider(self):
        return self.connector.name if self.connector else None

    @staticmethod
    def _payload(incident):
        return {
            "incident_id": incident.get("incident_id"),
            "alert_id": incident.get("alert_id"),
            "title": incident.get("alert_name"),
            "severity": incident.get("severity"),
            "incident_status": incident.get("incident_status"),
            "risk_score": incident.get("risk_score"),
            "risk_level": incident.get("risk_level"),
            "source_type": incident.get("source_type"),
            "mitre_attck_id": incident.get("mitre_attck_id"),
            "ip_address": incident.get("ip_address"),
            "timestamp": incident.get("timestamp"),
            "asset_id": incident.get("asset_id"),
        }

    @staticmethod
    def _external_id(value):
        if not isinstance(value, str):
            raise ValueError("Connector must return an external ID string")
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9~][A-Za-z0-9._:~-]{0,199}", value):
            raise ValueError("Connector returned an invalid external ID")
        return value

    def _audit(self, incident, actor, role, result):
        details = {
            "provider": result.get("provider"),
            "status": result["status"],
            "attempts": result["attempts"],
        }
        if result.get("external_id"):
            details["external_id"] = result["external_id"]
        append_audit_event(
            "CASE_EXPORT", actor, role=role, target_type="incident",
            target_id=incident.get("incident_id") or incident.get("alert_id"),
            outcome=result["status"], details=details,
        )
        return result

    def export(self, repository, alert_id, *, actor, role=None):
        if not self.enabled or self.connector is None:
            incident = {"alert_id": alert_id}
            status = "DISABLED" if not self.enabled else "MISCONFIGURED"
            return self._audit(incident, actor, role, {
                "provider": self.provider, "status": status, "attempts": 0,
            })

        with self._lock:
            incident = repository.get_alert(alert_id)
            if incident is None:
                return None
            if not incident.get("incident_id"):
                raise ValueError("Alert is not incident-worthy")
            external_cases = incident.get("external_cases") or {}
            if not isinstance(external_cases, dict):
                raise ValueError("Incident external_cases must be an object")
            existing = external_cases.get(self.provider)
            if isinstance(existing, dict) and existing.get("external_id"):
                existing = {**existing, "external_id": self._external_id(existing["external_id"])}
                return self._audit(incident, actor, role, {
                    **existing, "provider": self.provider,
                    "status": "DEDUPLICATED", "attempts": 0,
                })

            external_id = None
            error = None
            attempts = 0
            for attempts in range(1, self.max_attempts + 1):
                try:
                    external_id = self._external_id(self.connector.create_case(
                        self._payload(incident), timeout_seconds=self.timeout_seconds,
                    ))
                    break
                except Exception as exc:
                    error = type(exc).__name__
            if external_id is None:
                return self._audit(incident, actor, role, {
                    "provider": self.provider, "status": "FAILED",
                    "attempts": attempts, "error": error,
                })

            exported_at = utc_iso()
            record = {
                "provider": self.provider,
                "external_id": external_id,
                "status": "EXPORTED",
                "exported_at": exported_at,
                "exported_by": actor,
                "attempts": attempts,
            }

            def persist(current):
                cases = dict(current.get("external_cases") or {})
                cases[self.provider] = dict(record)
                current["external_cases"] = cases
                current["updated_at"] = exported_at
                current["timeline"] = list(current.get("timeline") or [])
                current["timeline"].append({
                    "event_type": "CASE_EXPORTED", "timestamp": exported_at,
                    "provider": self.provider, "external_id": external_id,
                })

            if repository.update_alert(alert_id, persist) is None:
                raise RuntimeError("Incident disappeared after case export")
            return self._audit(incident, actor, role, record)
