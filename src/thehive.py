import ipaddress
from urllib.parse import quote, urlsplit

import requests

from src.case_connector import CaseConnector


class TheHiveConnector(CaseConnector):
    name = "thehive"

    def __init__(self, base_url, api_key, requester=requests.request):
        parsed = urlsplit(str(base_url).strip())
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("TheHive URL must be an HTTP(S) origin without credentials")
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("TheHive API key is required")
        self.base_url = str(base_url).strip().rstrip("/")
        self._api_key = api_key.strip()
        self._requester = requester

    @staticmethod
    def _text(value, limit=512):
        return " ".join(str(value or "unknown").split())[:limit]

    @staticmethod
    def _severity(incident):
        detection = {
            "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 1,
        }.get(str(incident.get("severity") or "").upper(), 1)
        try:
            risk = float(incident.get("risk_score") or 0)
        except (TypeError, ValueError):
            risk = 0
        risk_level = 4 if risk >= 90 else 3 if risk >= 70 else 2 if risk >= 40 else 1
        return max(detection, risk_level)

    def _headers(self):
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def _send(self, method, path, payload, timeout_seconds):
        response = self._requester(
            method,
            f"{self.base_url}/api/v1/{path.lstrip('/')}",
            headers=self._headers(),
            json=payload,
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        return None if response.status_code == 204 else response.json()

    def _title(self, incident):
        incident_id = self._text(incident.get("incident_id"), 200)
        prefix = f"[Mini-SIEM {incident_id}] "
        return prefix + self._text(incident.get("title"), 512 - len(prefix))

    def _case_payload(self, incident):
        incident_id = self._text(incident.get("incident_id"), 100)
        details = (
            ("Incident", incident_id),
            ("Alert", incident.get("alert_id")),
            ("Status", incident.get("incident_status")),
            ("Risk", f"{incident.get('risk_score', 0)}/100 {incident.get('risk_level', 'LOW')}"),
            ("Source", incident.get("source_type")),
            ("MITRE ATT&CK", incident.get("mitre_attck_id")),
            ("Asset", incident.get("asset_id")),
            ("Timestamp", incident.get("timestamp")),
        )
        return {
            "title": self._title(incident),
            "description": "\n".join(
                f"**{label}:** {self._text(value, 300)}" for label, value in details
            ),
            "severity": self._severity(incident),
            "tags": ["mini-siem", f"mini-siem:{incident_id}"],
            "tlp": 2,
            "pap": 2,
        }

    def _find_case(self, incident, timeout_seconds):
        result = self._send("POST", "query", {
            "query": [
                {"_name": "listCase"},
                {"_name": "filter", "_eq": {
                    "_field": "title", "_value": self._title(incident),
                }},
                {"_name": "page", "from": 0, "to": 1},
            ],
            "excludeFields": ["description", "summary"],
        }, timeout_seconds)
        if not isinstance(result, list) or not result:
            return None
        return self._case_id(result[0])

    def _ensure_observable(self, case_id, incident, timeout_seconds):
        value = str(incident.get("ip_address") or "").strip()
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return
        existing = self._send("POST", "query", {
            "query": [
                {"_name": "getCase", "idOrName": case_id},
                {"_name": "observables"},
                {"_name": "filter", "_eq": {"_field": "data", "_value": value}},
                {"_name": "page", "from": 0, "to": 1},
            ],
            "excludeFields": ["message"],
        }, timeout_seconds)
        if isinstance(existing, list) and existing:
            return
        self._send(
            "POST",
            f"case/{quote(case_id, safe='')}/observable",
            {
                "dataType": "ip", "data": value,
                "message": "Source IP exported by Mini-SIEM", "tlp": 2, "pap": 2,
            },
            timeout_seconds,
        )

    @staticmethod
    def _case_id(response):
        if not isinstance(response, dict):
            raise ValueError("TheHive returned an invalid case response")
        case_id = response.get("_id") or response.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("TheHive response has no case ID")
        return case_id.strip()

    def create_case(self, incident, *, timeout_seconds):
        case_id = self._find_case(incident, timeout_seconds)
        if not case_id:
            case_id = self._case_id(self._send(
                "POST", "case", self._case_payload(incident), timeout_seconds,
            ))
        self._ensure_observable(case_id, incident, timeout_seconds)
        return case_id

    def update_case(self, external_id, incident, *, timeout_seconds):
        self._send(
            "PATCH", f"case/{quote(external_id, safe='')}",
            self._case_payload(incident), timeout_seconds,
        )
        self._ensure_observable(external_id, incident, timeout_seconds)
        return external_id
