import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def _alert(observed, detected, *, severity="LOW", rule_id=None, **extra):
    return build_alert(
        alert_name="KPI fixture",
        severity=severity,
        source_type="HIDS_LOG",
        description="Deterministic KPI timing",
        timestamp=observed,
        created_at=detected,
        updated_at=detected,
        rule_id=rule_id,
        **extra,
    )


def test_soc_kpis():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repository = SQLiteAlertRepository(str(root / "kpis.db"))
        resolved = _alert(
            "2026-08-19T00:00:00Z", "2026-08-19T00:00:10Z",
            severity="HIGH", rule_id="DET-A", incident_status="RESOLVED",
            ai_analysis={"analysed_at": "2026-08-19T00:00:20Z"},
            ai_disposition="REQUIRES_HUMAN_REVIEW",
            timeline=[
                {"event_type": "ASSIGNMENT_CHANGED", "timestamp": "2026-08-19T00:00:30Z"},
                {
                    "event_type": "STATUS_CHANGED", "timestamp": "2026-08-19T00:02:00Z",
                    "from_status": "INVESTIGATING", "to_status": "RESOLVED",
                },
            ],
        )
        ai_failure = _alert(
            "2026-08-19T01:00:00Z", "2026-08-19T01:00:20Z",
            rule_id="DET-A", ai_analysis={"error": "offline"},
        )
        false_positive = _alert(
            "2026-08-19T02:00:00Z", "2026-08-19T02:00:30Z",
            severity="HIGH", rule_id="DET-B", incident_status="FALSE_POSITIVE",
            timeline=[
                {"event_type": "NOTE_ADDED", "timestamp": "2026-08-19T02:01:00Z"},
                {
                    "event_type": "STATUS_CHANGED", "timestamp": "2026-08-19T02:01:30Z",
                    "from_status": "INVESTIGATING", "to_status": "FALSE_POSITIVE",
                },
            ],
        )
        outside = _alert(
            "2026-08-20T00:00:00Z", "2026-08-20T00:00:00Z", rule_id="DET-OUTSIDE",
        )
        for alert in (resolved, ai_failure, false_positive, outside):
            repository.create_alert(alert)

        start, end = "2026-08-19T00:00:00Z", "2026-08-20T00:00:00Z"
        kpis = repository.soc_kpis(start, end)
        assert kpis["mttd_seconds"] == {"available": True, "sample_size": 3, "value": 20.0}
        assert kpis["mtta_seconds"] == {"available": True, "sample_size": 2, "value": 25.0}
        assert kpis["mttr_seconds"] == {"available": True, "sample_size": 1, "value": 110.0}
        assert kpis["open_incidents"] == {"available": True, "sample_size": 2, "value": 0}
        assert kpis["resolved_incidents"] == {"available": True, "sample_size": 2, "value": 1}
        assert kpis["false_positive_rate_percent"]["value"] == 50.0
        assert kpis["human_review_rate_percent"]["value"] == 33.33
        assert kpis["ai_enrichment_success_rate_percent"] == {
            "available": True, "sample_size": 2, "value": 50.0,
        }
        assert kpis["alerts_per_rule"]["value"] == [
            {"rule_id": "DET-A", "alerts": 2},
            {"rule_id": "DET-B", "alerts": 1},
        ]

        empty = repository.soc_kpis("2026-08-18T00:00:00Z", "2026-08-19T00:00:00Z")
        assert all(metric["available"] is False and metric["value"] is None for metric in empty.values())

        with repository._connect() as connection:
            indexes = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'",
            )}
        assert {"idx_alerts_created_at", "idx_incident_events_incident"} <= indexes

        original_users_file = config.DASHBOARD_USERS_FILE
        try:
            client = dashboard.app.test_client()
            assert client.get("/api/analytics/kpis").status_code == 401
            login_as(client, directory, role="viewer", username="kpi-viewer")
            with patch.object(dashboard, "alert_repository", repository):
                response = client.get(f"/api/analytics/kpis?from={start}&to={end}")
                assert response.status_code == 200
                payload = response.get_json()
                assert payload["period"] == {
                    "from": start, "to": end,
                    "boundary": "[from,to)", "timestamp": "alert.created_at",
                }
                assert payload["kpis"] == kpis
                assert "mttd_seconds" in payload["definitions"]
                assert client.get(
                    "/api/analytics/kpis?from=bad&to=2026-08-20T00:00:00Z",
                ).status_code == 400
                assert client.get(
                    "/api/analytics/kpis?from=2026-08-20T00:00:00Z&to=2026-08-19T00:00:00Z",
                ).status_code == 400
                assert client.get(
                    "/api/analytics/kpis?from=2025-01-01T00:00:00Z&to=2026-08-19T00:00:00Z",
                ).status_code == 400
        finally:
            config.DASHBOARD_USERS_FILE = original_users_file


if __name__ == "__main__":
    test_soc_kpis()
    print("M14.2 SOC KPI analytics passed")
