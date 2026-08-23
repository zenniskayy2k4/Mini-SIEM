import base64
import json
import tempfile
from pathlib import Path

import requests

from config import config
from src.alert_schema import build_alert
from src.case_connector import CaseExportService
from src.jira import JiraConnector
from src.sqlite_store import SQLiteAlertRepository


class FixtureResponse:
    def __init__(self, payload=None, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


class FixtureHTTP:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError("unexpected Jira request")
        return self.responses.pop(0)


def _incident():
    return {
        "incident_id": "INC-jira-1",
        "alert_id": "ALT-jira-1",
        "title": "Suspicious login",
        "severity": "HIGH",
        "incident_status": "INVESTIGATING",
        "risk_score": 85,
        "risk_level": "HIGH",
        "source_type": "HIDS_LOG",
        "mitre_attck_id": "T1110",
        "ip_address": "203.0.113.21",
        "timestamp": "2026-08-21T10:00:00Z",
        "asset_id": "AST-1",
        "raw_log": "Bearer raw-secret",
        "analyst_notes": [{"text": "note-secret"}],
    }


def _connector(http):
    return JiraConnector(
        "https://soc.atlassian.net", "analyst@example.com", "fixture-api-token",
        "SOC", requester=http,
    )


def test_jira_connector():
    http = FixtureHTTP(
        FixtureResponse({"issues": [], "isLast": True}),
        FixtureResponse({"id": "10042", "key": "SOC-42"}, 201),
    )
    connector = _connector(http)
    incident = _incident()
    assert connector.create_case(incident, timeout_seconds=4) == "SOC-42"
    assert [call["method"] for call in http.calls] == ["POST", "POST"]
    assert [call["url"].rsplit("/rest/api/3/", 1)[1] for call in http.calls] == [
        "search/jql", "issue",
    ]
    assert all(call["timeout"] == 4 for call in http.calls)
    credential = http.calls[0]["headers"]["Authorization"].removeprefix("Basic ")
    assert base64.b64decode(credential).decode() == "analyst@example.com:fixture-api-token"

    search = http.calls[0]["json"]
    assert search == {
        "jql": 'project = "SOC" AND labels = "mini-siem-inc-jira-1"',
        "fields": ["key"], "maxResults": 1,
    }
    fields = http.calls[1]["json"]["fields"]
    assert fields["project"] == {"key": "SOC"}
    assert fields["issuetype"] == {"name": "Task"}
    assert fields["summary"].startswith("[Mini-SIEM INC-jira-1]")
    assert fields["description"]["type"] == "doc" and fields["description"]["version"] == 1
    assert {"mini-siem", "mini-siem-inc-jira-1", "severity-high", "risk-high"} <= set(fields["labels"])
    outbound = json.dumps([call["json"] for call in http.calls])
    assert "raw-secret" not in outbound and "note-secret" not in outbound
    assert "fixture-api-token" not in outbound

    existing_http = FixtureHTTP(FixtureResponse({
        "issues": [{"id": "10042", "key": "SOC-42"}], "isLast": True,
    }))
    assert _connector(existing_http).create_case(incident, timeout_seconds=3) == "SOC-42"
    assert len(existing_http.calls) == 1

    update_http = FixtureHTTP(FixtureResponse(status_code=204))
    assert _connector(update_http).update_case(
        "SOC-42", incident, timeout_seconds=2,
    ) == "SOC-42"
    assert update_http.calls[0]["method"] == "PUT"
    assert update_http.calls[0]["url"].endswith("/rest/api/3/issue/SOC-42")
    assert "project" not in update_http.calls[0]["json"]["fields"]

    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        previous_audit = config.ANALYST_AUDIT_FILE
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        try:
            repository = SQLiteAlertRepository(str(directory / "alerts.db"))
            alert = build_alert(
                alert_name="Jira service export", severity="HIGH",
                source_type="HIDS_LOG", description="description-secret",
                raw_log="Bearer raw-secret", ip_address="203.0.113.21",
                risk_score=80, risk_level="HIGH",
            )
            repository.create_alert(alert)
            service_http = FixtureHTTP(
                FixtureResponse({"issues": [], "isLast": True}),
                FixtureResponse({"id": "10077", "key": "SOC-77"}, 201),
            )
            service = CaseExportService(_connector(service_http), enabled=True)
            result = service.export(
                repository, alert["alert_id"], actor="tier-1", role="analyst",
            )
            assert result["status"] == "EXPORTED" and result["external_id"] == "SOC-77"
            stored = repository.get_alert(alert["alert_id"])
            assert stored["external_cases"]["jira"]["external_id"] == "SOC-77"
            assert service.export(
                repository, alert["alert_id"], actor="tier-1", role="analyst",
            )["status"] == "DEDUPLICATED"
            assert len(service_http.calls) == 2
            audit_text = Path(config.ANALYST_AUDIT_FILE).read_text(encoding="utf-8")
            events = [json.loads(line) for line in audit_text.splitlines()]
            assert all(event["details"]["provider"] == "jira" for event in events)
            assert "fixture-api-token" not in audit_text and "raw-secret" not in audit_text
        finally:
            config.ANALYST_AUDIT_FILE = previous_audit

    invalid = (
        ("ftp://jira.example", "analyst@example.com", "token", "SOC"),
        ("https://user:pass@jira.example", "analyst@example.com", "token", "SOC"),
        ("https://jira.example?token=secret", "analyst@example.com", "token", "SOC"),
        ("https://jira.example", "invalid", "token", "SOC"),
        ("https://jira.example", "analyst@example.com", "", "SOC"),
        ("https://jira.example", "analyst@example.com", "token", "1bad"),
    )
    for values in invalid:
        try:
            JiraConnector(*values)
            raise AssertionError("unsafe Jira configuration was accepted")
        except ValueError:
            pass


if __name__ == "__main__":
    test_jira_connector()
    print("M16.3 Jira connector passed")
