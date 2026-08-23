import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert
from src.audit import verify_audit_log
from src.case_connector import CaseConnector, CaseExportService
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


class FixtureConnector(CaseConnector):
    name = "fixture"

    def __init__(self, *, failures=0, external_id=None):
        self.failures = failures
        self.external_id = external_id
        self.create_calls = []
        self.update_calls = []

    def create_case(self, incident, *, timeout_seconds):
        self.create_calls.append((incident, timeout_seconds))
        if self.failures:
            self.failures -= 1
            raise RuntimeError("provider-secret")
        return self.external_id or f"CASE-{incident['incident_id']}"

    def update_case(self, external_id, incident, *, timeout_seconds):
        self.update_calls.append((external_id, incident, timeout_seconds))
        return external_id


def _incident(name="Connector fixture"):
    return build_alert(
        alert_name=name, severity="HIGH", source_type="HIDS_LOG",
        description="secret=description-secret", raw_log="Bearer raw-secret",
        ip_address="192.0.2.90", mitre_attck_id="T1110",
        analyst_notes=[{"text": "note-secret", "author": "analyst"}],
    )


def test_case_connector():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original = config.ANALYST_AUDIT_FILE, config.DASHBOARD_USERS_FILE
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        repository = SQLiteAlertRepository(str(directory / "alerts.db"))
        incident = _incident()
        repository.create_alert(incident)
        try:
            connector = FixtureConnector(failures=1)
            service = CaseExportService(
                connector, enabled=True, timeout_seconds=4, max_attempts=2,
            )
            exported = service.export(
                repository, incident["alert_id"], actor="tier-1", role="analyst",
            )
            assert exported["status"] == "EXPORTED" and exported["attempts"] == 2
            assert exported["external_id"] == f"CASE-{incident['incident_id']}"
            assert len(connector.create_calls) == 2
            payload, timeout = connector.create_calls[0]
            assert timeout == 4 and payload["incident_id"] == incident["incident_id"]
            serialized = json.dumps(payload)
            assert all(field not in payload for field in (
                "raw_log", "description", "analyst_notes", "ai_analysis",
            ))
            assert "secret" not in serialized

            stored = repository.get_alert(incident["alert_id"])
            assert stored["external_cases"]["fixture"]["external_id"] == exported["external_id"]
            assert stored["timeline"][-1]["event_type"] == "CASE_EXPORTED"
            duplicate = service.export(
                repository, incident["alert_id"], actor="tier-1", role="analyst",
            )
            assert duplicate["status"] == "DEDUPLICATED" and duplicate["attempts"] == 0
            assert len(connector.create_calls) == 2

            failed_connector = FixtureConnector(failures=3)
            failed = CaseExportService(
                failed_connector, enabled=True, max_attempts=2,
            ).export(repository, _store(repository, _incident("Failed export")), actor="tier-1")
            assert failed == {
                "provider": "fixture", "status": "FAILED",
                "attempts": 2, "error": "RuntimeError",
            }
            assert "provider-secret" not in json.dumps(failed)
            disabled = CaseExportService().export(
                repository, incident["alert_id"], actor="tier-1", role="analyst",
            )
            assert disabled == {
                "provider": None, "status": "DISABLED", "attempts": 0,
            }

            audit_text = Path(config.ANALYST_AUDIT_FILE).read_text(encoding="utf-8")
            events = [json.loads(line) for line in audit_text.splitlines()]
            assert [event["outcome"] for event in events] == [
                "EXPORTED", "DEDUPLICATED", "FAILED", "DISABLED",
            ]
            assert all(event["event_type"] == "CASE_EXPORT" for event in events)
            assert "secret" not in audit_text and verify_audit_log()[0] is True

            api_incident = _incident("Manual API export")
            repository.create_alert(api_incident)
            api_service = CaseExportService(FixtureConnector(), enabled=True)
            viewer = dashboard.app.test_client()
            login_as(viewer, directory, role="viewer", username="case-viewer")
            analyst = dashboard.app.test_client()
            login_as(analyst, directory, role="analyst", username="case-analyst")
            with patch.object(dashboard, "alert_repository", repository), patch.object(
                dashboard, "case_export_service", api_service,
            ):
                endpoint = f"/api/alerts/{api_incident['alert_id']}/external-case"
                assert viewer.post(endpoint).status_code == 403
                assert analyst.post(endpoint).status_code == 201
                assert analyst.post(endpoint).status_code == 200
            with patch.object(dashboard, "case_export_service", CaseExportService()):
                response = analyst.post(endpoint)
                assert response.status_code == 503 and response.get_json()["status"] == "DISABLED"

            for values in (
                {"timeout_seconds": 0}, {"max_attempts": 0}, {"max_attempts": 4},
            ):
                try:
                    CaseExportService(FixtureConnector(), enabled=True, **values)
                    raise AssertionError("invalid case export bounds were accepted")
                except ValueError:
                    pass
        finally:
            config.ANALYST_AUDIT_FILE, config.DASHBOARD_USERS_FILE = original


def _store(repository, incident):
    repository.create_alert(incident)
    return incident["alert_id"]


if __name__ == "__main__":
    test_case_connector()
    print("M16.1 external case connector contract passed")
