import base64
import re
from urllib.parse import quote, urlsplit

import requests

from src.case_connector import CaseConnector


class JiraConnector(CaseConnector):
    name = "jira"

    def __init__(
        self, base_url, email, api_token, project_key,
        issue_type="Task", requester=requests.request,
    ):
        parsed = urlsplit(str(base_url).strip())
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Jira URL must be an HTTP(S) origin without credentials")
        if not isinstance(email, str) or not re.fullmatch(r"[^\s:@]+@[^\s:@]+", email.strip()):
            raise ValueError("Jira account email is invalid")
        if not isinstance(api_token, str) or not api_token.strip() or "\n" in api_token or "\r" in api_token:
            raise ValueError("Jira API token is required")
        project_key = str(project_key).strip().upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,49}", project_key):
            raise ValueError("Jira project key is invalid")
        issue_type = " ".join(str(issue_type).split())
        if not issue_type or len(issue_type) > 100:
            raise ValueError("Jira issue type is invalid")
        self.base_url = str(base_url).strip().rstrip("/")
        self.email = email.strip()
        self._api_token = api_token.strip()
        self.project_key = project_key
        self.issue_type = issue_type
        self._requester = requester

    @staticmethod
    def _text(value, limit=500):
        return " ".join(str(value or "unknown").split())[:limit]

    def _headers(self):
        credential = base64.b64encode(
            f"{self.email}:{self._api_token}".encode("utf-8")
        ).decode("ascii")
        return {
            "Accept": "application/json",
            "Authorization": f"Basic {credential}",
            "Content-Type": "application/json",
        }

    def _send(self, method, path, payload, timeout_seconds):
        response = self._requester(
            method,
            f"{self.base_url}/rest/api/3/{path.lstrip('/')}",
            headers=self._headers(),
            json=payload,
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        return None if response.status_code == 204 else response.json()

    def _incident_label(self, incident):
        value = re.sub(
            r"[^a-z0-9_-]+", "-",
            str(incident.get("incident_id") or "").strip().lower(),
        ).strip("-_")
        if not value:
            raise ValueError("Jira export requires an incident ID")
        return f"mini-siem-{value}"[:255]

    def _summary(self, incident):
        prefix = f"[Mini-SIEM {self._text(incident.get('incident_id'), 100)}] "
        return prefix + self._text(incident.get("title"), 255 - len(prefix))

    def _description(self, incident):
        details = (
            ("Incident", incident.get("incident_id")),
            ("Alert", incident.get("alert_id")),
            ("Status", incident.get("incident_status")),
            ("Severity", incident.get("severity")),
            ("Risk", f"{incident.get('risk_score', 0)}/100 {incident.get('risk_level', 'LOW')}"),
            ("Source", incident.get("source_type")),
            ("MITRE ATT&CK", incident.get("mitre_attck_id")),
            ("Source IP", incident.get("ip_address")),
            ("Asset", incident.get("asset_id")),
            ("Timestamp", incident.get("timestamp")),
        )
        return {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": f"{label}: {self._text(value)}"}],
                }
                for label, value in details
            ],
        }

    def _labels(self, incident):
        labels = [
            "mini-siem",
            self._incident_label(incident),
            f"severity-{self._text(incident.get('severity'), 30).lower()}",
            f"risk-{self._text(incident.get('risk_level'), 30).lower()}",
        ]
        return [re.sub(r"[^a-z0-9_-]+", "-", label).strip("-") for label in labels]

    def _fields(self, incident, *, create):
        fields = {
            "summary": self._summary(incident),
            "description": self._description(incident),
            "labels": self._labels(incident),
        }
        if create:
            fields.update({
                "project": {"key": self.project_key},
                "issuetype": {"name": self.issue_type},
            })
        return fields

    @staticmethod
    def _issue_key(response):
        if not isinstance(response, dict):
            raise ValueError("Jira returned an invalid issue response")
        issue_key = response.get("key")
        if not isinstance(issue_key, str) or not issue_key.strip():
            raise ValueError("Jira response has no issue key")
        return issue_key.strip()

    def _find_issue(self, incident, timeout_seconds):
        label = self._incident_label(incident)
        response = self._send("POST", "search/jql", {
            "jql": f'project = "{self.project_key}" AND labels = "{label}"',
            "fields": ["key"],
            "maxResults": 1,
        }, timeout_seconds)
        issues = response.get("issues") if isinstance(response, dict) else None
        if not isinstance(issues, list) or not issues:
            return None
        return self._issue_key(issues[0])

    def create_case(self, incident, *, timeout_seconds):
        issue_key = self._find_issue(incident, timeout_seconds)
        if issue_key:
            return issue_key
        return self._issue_key(self._send(
            "POST", "issue", {"fields": self._fields(incident, create=True)},
            timeout_seconds,
        ))

    def update_case(self, external_id, incident, *, timeout_seconds):
        self._send(
            "PUT", f"issue/{quote(external_id, safe='')}",
            {"fields": self._fields(incident, create=False)}, timeout_seconds,
        )
        return external_id
