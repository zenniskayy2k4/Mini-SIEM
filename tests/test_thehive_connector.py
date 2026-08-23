import json
import tempfile
from pathlib import Path

import requests

from config import config
from src.alert_schema import build_alert
from src.case_connector import CaseExportService
from src.sqlite_store import SQLiteAlertRepository
from src.thehive import TheHiveConnector


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
            raise AssertionError("unexpected TheHive request")
        return self.responses.pop(0)


def _safe_incident():
    return {
        "incident_id": "INC-thehive-1",
        "alert_id": "ALT-thehive-1",
        "title": "Suspicious login",
        "severity": "HIGH",
        "incident_status": "INVESTIGATING",
        "risk_score": 95,
        "risk_level": "CRITICAL",
        "source_type": "HIDS_LOG",
        "mitre_attck_id": "T1110",
        "ip_address": "203.0.113.17",
        "timestamp": "2026-08-20T10:00:00Z",
        "asset_id": "AST-1",
        "raw_log": "Bearer raw-secret",
        "analyst_notes": [{"text": "note-secret"}],
    }


def _connector(http):
    return TheHiveConnector("https://thehive.example", "api-key-secret", requester=http)


def test_thehive_connector():
    http = FixtureHTTP(
        FixtureResponse([]),
        FixtureResponse({"_id": "~42"}, 201),
        FixtureResponse([]),
        FixtureResponse({"_id": "~99"}, 201),
    )
    connector = _connector(http)
    incident = _safe_incident()
    assert connector.create_case(incident, timeout_seconds=4) == "~42"
    assert [call["method"] for call in http.calls] == ["POST"] * 4
    assert [call["url"].rsplit("/api/v1/", 1)[1] for call in http.calls] == [
        "query", "case", "query", "case/~42/observable",
    ]
    assert all(call["timeout"] == 4 for call in http.calls)
    assert all(call["headers"]["Authorization"] == "Bearer api-key-secret" for call in http.calls)

    case_payload = http.calls[1]["json"]
    assert case_payload["severity"] == 4
    assert case_payload["title"].startswith("[Mini-SIEM INC-thehive-1]")
    assert "mini-siem:INC-thehive-1" in case_payload["tags"]
    observable = http.calls[3]["json"]
    assert observable["dataType"] == "ip" and observable["data"] == "203.0.113.17"
    outbound_data = json.dumps([call["json"] for call in http.calls])
    assert "raw-secret" not in outbound_data and "note-secret" not in outbound_data
    assert connector._severity({"severity": "CRITICAL", "risk_score": 0}) == 4
    assert connector._severity({"severity": "LOW", "risk_score": 75}) == 3
    assert connector._severity({"severity": "MEDIUM", "risk_score": "bad"}) == 2

    existing_http = FixtureHTTP(
        FixtureResponse([{"_id": "~42"}]),
        FixtureResponse([{"_id": "~99", "data": "203.0.113.17"}]),
    )
    assert _connector(existing_http).create_case(incident, timeout_seconds=3) == "~42"
    assert all(call["url"].endswith("/query") for call in existing_http.calls)

    update_http = FixtureHTTP(
        FixtureResponse(status_code=204),
        FixtureResponse([{"_id": "~99"}]),
    )
    assert _connector(update_http).update_case(
        "~42", incident, timeout_seconds=2,
    ) == "~42"
    assert update_http.calls[0]["method"] == "PATCH"
    assert update_http.calls[0]["url"].endswith("/api/v1/case/~42")

    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        previous_audit = config.ANALYST_AUDIT_FILE
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        try:
            repository = SQLiteAlertRepository(str(directory / "alerts.db"))
            alert = build_alert(
                alert_name="TheHive service export", severity="HIGH",
                source_type="HIDS_LOG", description="description-secret",
                raw_log="Bearer raw-secret", ip_address="203.0.113.17",
                risk_score=80, risk_level="HIGH",
            )
            repository.create_alert(alert)
            service_http = FixtureHTTP(
                FixtureResponse([]), FixtureResponse({"_id": "~77"}, 201),
                FixtureResponse([]), FixtureResponse({"_id": "~100"}, 201),
            )
            service = CaseExportService(_connector(service_http), enabled=True)
            result = service.export(
                repository, alert["alert_id"], actor="tier-1", role="analyst",
            )
            assert result["status"] == "EXPORTED" and result["external_id"] == "~77"
            assert repository.get_alert(alert["alert_id"])["external_cases"]["thehive"]["external_id"] == "~77"
            assert service.export(
                repository, alert["alert_id"], actor="tier-1", role="analyst",
            )["status"] == "DEDUPLICATED"
            assert len(service_http.calls) == 4
            assert "api-key-secret" not in Path(config.ANALYST_AUDIT_FILE).read_text(encoding="utf-8")
        finally:
            config.ANALYST_AUDIT_FILE = previous_audit

    for url, key in (
        ("ftp://thehive.example", "key"),
        ("https://user:pass@thehive.example", "key"),
        ("https://thehive.example?token=secret", "key"),
        ("https://thehive.example", ""),
    ):
        try:
            TheHiveConnector(url, key)
            raise AssertionError("unsafe TheHive configuration was accepted")
        except ValueError:
            pass


if __name__ == "__main__":
    test_thehive_connector()
    print("M16.2 TheHive connector passed")
