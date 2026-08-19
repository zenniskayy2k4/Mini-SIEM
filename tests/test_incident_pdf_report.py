import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert
from src.incident_report import generate_incident_pdf, incident_report_sections
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def test_incident_pdf_report():
    with tempfile.TemporaryDirectory() as directory:
        repository = SQLiteAlertRepository(str(Path(directory, "reports.db")))
        alert = build_alert(
            alert_name="Credential attack",
            severity="HIGH",
            source_type="HIDS_LOG",
            description="Repeated login failure password=hunter2",
            raw_log="Authorization: Bearer raw-secret",
            ip_address="192.0.2.44",
            mitre_attck_id="T1110",
            rule_id="DET-AUTH-001",
            timestamp="2026-08-19T00:00:00Z",
            created_at="2026-08-19T00:00:10Z",
            updated_at="2026-08-19T01:05:00Z",
            incident_status="RESOLVED",
            assigned_to="tier-2",
            asset_id="AST-stored-reference",
            ai_disposition="REQUIRES_HUMAN_REVIEW",
            ai_recommended_severity="CRITICAL",
            ai_analysis={
                "provider": "ollama_cloud", "model": "test-model",
                "analysed_at": "2026-08-19T00:01:00Z", "threat_confidence": 91,
                "fp_confidence": 4, "escalate_to_human": True,
                "threat_summary": "Likely attack Bearer ai-secret",
                "recommended_playbook": ["Review api_key=abc123"],
            },
            threat_intel={"abuseipdb": {
                "status": "ok", "ioc_type": "ip", "ioc": "192.0.2.44",
                "abuse_confidence": 80, "raw_provider_response": "provider-secret",
            }},
            analyst_notes=[{
                "author": "analyst", "timestamp": "2026-08-19T00:30:00Z",
                "text": "Confirmed; token=note-secret",
            }],
            timeline=[{
                "event_type": "STATUS_CHANGED", "timestamp": "2026-08-19T08:00:00+07:00",
                "from_status": "INVESTIGATING", "to_status": "RESOLVED",
            }],
            response_actions=[{
                "action_id": "ACT-report", "action_type": "BLOCK_IP", "target": "192.0.2.44",
                "status": "SIMULATED", "mode": "simulation", "created_at": "2026-08-19T00:40:00Z",
                "result": "command secret=action-secret",
            }],
        )
        repository.create_alert(alert)

        sections = incident_report_sections(alert)
        assert [title for title, _ in sections] == [
            "Incident Metadata", "Executive Summary", "Detection Evidence", "MITRE Mapping",
            "AI Analysis", "Threat Intelligence", "Asset Context", "Analyst Timeline",
            "Response Actions", "Resolution", "Appendix",
        ]
        report = generate_incident_pdf(alert)
        assert report == generate_incident_pdf(alert)
        assert report.startswith(b"%PDF-1.4") and report.rstrip().endswith(b"%%EOF")
        for expected in (
            b"Incident Metadata", b"Detection Evidence", b"AI-generated assessment; not observed fact.",
            b"Third-party context; not detector evidence.", b"2026-08-19T01:00:00Z",
            b"Stored asset reference: AST-stored-reference", b"Resolution", b"Appendix",
        ):
            assert expected in report
        for excluded in (b"hunter2", b"raw-secret", b"ai-secret", b"abc123", b"note-secret", b"provider-secret", b"action-secret"):
            assert excluded not in report
        assert b"[REDACTED]" in report and b"raw log payloads" in report
        sparse = build_alert(
            alert_name="Sparse incident", severity="HIGH", source_type="HIDS_LOG",
            description="No enrichment", timestamp="2026-08-19T03:00:00Z",
        )
        assert generate_incident_pdf(sparse) == generate_incident_pdf(sparse)

        original_users_file = config.DASHBOARD_USERS_FILE
        try:
            anonymous = dashboard.app.test_client()
            assert anonymous.get(f"/api/alerts/{alert['alert_id']}/report.pdf").status_code == 401
            client = dashboard.app.test_client()
            login_as(client, directory, role="viewer", username="report-viewer")
            with patch.object(dashboard, "alert_repository", repository):
                response = client.get(f"/api/alerts/{alert['alert_id']}/report.pdf")
                assert response.status_code == 200
                assert response.mimetype == "application/pdf"
                assert "attachment" in response.headers["Content-Disposition"]
                assert alert["incident_id"] in response.headers["Content-Disposition"]
                assert response.data == report
                assert client.get("/api/alerts/missing/report.pdf").status_code == 404

                non_incident = build_alert(
                    alert_name="Low event", severity="LOW", source_type="HIDS_LOG",
                    description="No incident", timestamp="2026-08-19T02:00:00Z",
                )
                repository.create_alert(non_incident)
                assert client.get(
                    f"/api/alerts/{non_incident['alert_id']}/report.pdf"
                ).status_code == 400
        finally:
            config.DASHBOARD_USERS_FILE = original_users_file

    script = Path("static/js/app.js").read_text(encoding="utf-8")
    assert 'report.pdf" download' in script and "PDF report" in script


if __name__ == "__main__":
    test_incident_pdf_report()
    print("M14.4 incident PDF report passed")
