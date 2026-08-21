import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository
from src.storage import JsonAlertRepository
from tests.auth_helpers import login_as


def _alert(name, *, assigned_to=None, status="NEW", disposition=None, severity="HIGH", **extra):
    return build_alert(
        alert_name=name,
        severity=severity,
        source_type="HIDS_LOG",
        description=f"{name} fixture",
        ip_address="203.0.113.9",
        mitre_attck_id="T1110",
        incident_status=status if severity in {"HIGH", "CRITICAL"} else None,
        assigned_to=assigned_to,
        ai_disposition=disposition,
        **extra,
    )


def test_analyst_workspace():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original = (
            config.DASHBOARD_USERS_FILE,
            config.ANALYST_AUDIT_FILE,
            config.RESPONSE_LOG_FILE,
            config.RESPONSE_MODE,
        )
        config.DASHBOARD_USERS_FILE = str(directory / "users.json")
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        config.RESPONSE_LOG_FILE = str(directory / "responses.jsonl")
        config.RESPONSE_MODE = "simulation"
        repository = SQLiteAlertRepository(str(directory / "alerts.db"))
        alerts = [
            _alert(
                "Human review assigned",
                assigned_to="soc-analyst",
                status="INVESTIGATING",
                disposition="REQUIRES_HUMAN_REVIEW",
                ai_analysis={"summary": "Review authentication failures", "confidence": 0.8},
                threat_intel={"abuseipdb": {"provider": "abuseipdb", "status": "ok"}},
            ),
            _alert("Open unassigned", status="NEW"),
            _alert("Resolved assigned", assigned_to="soc-analyst", status="RESOLVED"),
            _alert("Another analyst", assigned_to="tier-2", status="CONTAINED"),
            _alert("Non-incident", severity="LOW"),
        ]
        for alert in alerts:
            repository.create_alert(alert)

        try:
            client = dashboard.app.test_client()
            login_as(client, directory, role="analyst", username="soc-analyst")
            with (
                patch.object(dashboard, "alert_repository", repository),
                patch("src.alert_store.alert_repository", repository),
            ):
                page = client.get("/logs")
                assert page.status_code == 200
                html = page.get_data(as_text=True)
                assert "Analyst workspace" in html
                for label in ("Human review", "Assigned to me", "Unassigned", "Open incidents"):
                    assert label in html
                assert 'href="/settings"' not in html and 'href="/assets"' not in html

                searches = {
                    "human_review=true": {"Human review assigned"},
                    "assigned_to=me&open_incidents=true": {"Human review assigned"},
                    "unassigned=true&open_incidents=true": {"Open unassigned"},
                    "open_incidents=true": {
                        "Human review assigned", "Open unassigned", "Another analyst",
                    },
                }
                for query, expected in searches.items():
                    response = client.get(f"/api/alerts/search?{query}")
                    assert response.status_code == 200
                    assert {item["alert_name"] for item in response.get_json()["items"]} == expected

                target = alerts[0]
                note = client.post(
                    f"/api/alerts/{target['alert_id']}/notes", json={"note": "Validated source activity"},
                )
                assert note.status_code == 200
                assert note.get_json()["analyst_notes"][-1]["author"] == "soc-analyst"

                status = client.patch(
                    f"/api/alerts/{target['alert_id']}/status", json={"status": "CONTAINED"},
                )
                assert status.status_code == 200 and status.get_json()["incident_status"] == "CONTAINED"

                assignment = client.patch(
                    f"/api/alerts/{alerts[1]['alert_id']}/assignee",
                    json={"assigned_to": "soc-analyst"},
                )
                assert assignment.status_code == 200 and assignment.get_json()["assigned_to"] == "soc-analyst"

                proposal = client.post(
                    f"/api/alerts/{target['alert_id']}/response-actions",
                    json={"action_type": "BLOCK_IP", "target": "203.0.113.9"},
                )
                assert proposal.status_code == 201
                assert proposal.get_json()["response_actions"][-1]["status"] == "SIMULATED"

                script = client.get("/static/js/app.js").get_data(as_text=True)
                assert "renderThreatIntelligence(alert)" in script
                assert "renderAIAnalysis(alert)" in script
                assert "incident-note-btn" in script and "incident-response-btn" in script

            assert JsonAlertRepository._matches(alerts[0], {"assigned_to": "SOC-ANALYST"})
            assert JsonAlertRepository._matches(alerts[1], {"unassigned": True, "open_incidents": True})
            assert not JsonAlertRepository._matches(alerts[2], {"open_incidents": True})
            assert not JsonAlertRepository._matches(alerts[4], {"open_incidents": True})
        finally:
            (
                config.DASHBOARD_USERS_FILE,
                config.ANALYST_AUDIT_FILE,
                config.RESPONSE_LOG_FILE,
                config.RESPONSE_MODE,
            ) = original


if __name__ == "__main__":
    test_analyst_workspace()
    print("M17.2 analyst workspace passed")
