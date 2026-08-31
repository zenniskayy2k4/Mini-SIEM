import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def _alert(timestamp, *, rule_id, mitre, severity="LOW", status=None, timeline=None):
    return build_alert(
        alert_name="Analytics fixture",
        severity=severity,
        source_type="HIDS_LOG",
        description="Deterministic chart fixture",
        timestamp=timestamp,
        created_at=timestamp,
        updated_at=timestamp,
        rule_id=rule_id,
        mitre_attck_id=mitre,
        incident_status=status,
        timeline=timeline or [],
    )


def test_soc_analytics_dashboard():
    with tempfile.TemporaryDirectory() as directory:
        repository = SQLiteAlertRepository(str(Path(directory, "analytics.db")))
        alerts = [
            _alert("2026-08-19T00:10:00Z", rule_id="DET-A", mitre="T1110", severity="HIGH", status="NEW"),
            _alert("2026-08-19T00:20:00Z", rule_id="DET-A", mitre="T1110"),
            _alert(
                "2026-08-19T01:10:00Z", rule_id="DET-B", mitre="T1059.001",
                severity="HIGH", status="FALSE_POSITIVE", timeline=[{
                    "event_type": "STATUS_CHANGED", "timestamp": "2026-08-19T01:30:00Z",
                    "from_status": "INVESTIGATING", "to_status": "FALSE_POSITIVE",
                }],
            ),
            _alert("2026-08-20T00:00:00Z", rule_id="OUTSIDE", mitre="T0000"),
        ]
        for alert in alerts:
            repository.create_alert(alert)

        start, end = "2026-08-19T00:00:00Z", "2026-08-20T00:00:00Z"
        result = repository.soc_analytics(start, end)
        assert result["granularity"] == "hour"
        assert result["alert_trend"] == [
            {"timestamp": "2026-08-19T00:00:00Z", "count": 2},
            {"timestamp": "2026-08-19T01:00:00Z", "count": 1},
        ]
        assert result["incident_distribution"] == [
            {"status": "FALSE_POSITIVE", "count": 1}, {"status": "NEW", "count": 1},
        ]
        assert result["top_rules"][0] == {"rule_id": "DET-A", "count": 2}
        assert result["top_mitre_techniques"][0] == {"technique_id": "T1110", "count": 2}
        assert result["false_positive_trend"] == [
            {"timestamp": "2026-08-19T01:00:00Z", "count": 1},
        ]
        with repository._connect() as connection:
            indexes = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'",
            )}
        assert "idx_incident_events_timestamp" in indexes

        original_users_file = config.DASHBOARD_USERS_FILE
        try:
            client = dashboard.app.test_client()
            assert client.get("/analytics").status_code == 302
            login_as(client, directory, role="viewer", username="analytics-viewer")
            page = client.get("/analytics")
            assert page.status_code == 200
            html = page.get_data(as_text=True)
            assert "SOC Analytics" in html and "Last 30 days" in html
            with (
                patch.object(dashboard, "alert_repository", repository),
                patch.object(
                    dashboard, "VALIDATION_COVERAGE_FILE", Path(directory, "missing-validation.json"),
                ),
            ):
                response = client.get(f"/api/analytics/kpis?from={start}&to={end}")
                assert response.status_code == 200
                analytics = response.get_json()["analytics"]
                assert analytics.pop("rule_quality") == [
                    {
                        "rule_id": "DET-A", "alerts_generated": 2,
                        "true_positives": 0, "false_positives": 0,
                        "benign_expected": 0, "unclassified": 2,
                        "classified_sample_size": 0,
                        "false_positive_rate_percent": None,
                        "validation_scenario_count": 0,
                        "last_validation_result": "UNAVAILABLE",
                    },
                    {
                        "rule_id": "DET-B", "alerts_generated": 1,
                        "true_positives": 0, "false_positives": 0,
                        "benign_expected": 0, "unclassified": 1,
                        "classified_sample_size": 0,
                        "false_positive_rate_percent": None,
                        "validation_scenario_count": 0,
                        "last_validation_result": "UNAVAILABLE",
                    },
                ]
                assert analytics == result
        finally:
            config.DASHBOARD_USERS_FILE = original_users_file

    root = Path(__file__).resolve().parents[1]
    js = (root / "static/js/app.js").read_text(encoding="utf-8")
    css = (root / "static/css/style.css").read_text(encoding="utf-8")
    assert "Insufficient data" in js
    assert "@media (max-width: 700px)" in css and ".analytics-grid" in css


if __name__ == "__main__":
    test_soc_analytics_dashboard()
    print("M14.3 SOC analytics dashboard passed")
