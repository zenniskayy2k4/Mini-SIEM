import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def _alert(created_at, rule_id):
    return build_alert(
        alert_name="Rule quality fixture", severity="LOW", source_type="HIDS_LOG",
        description="Deterministic rule quality", timestamp=created_at,
        created_at=created_at, updated_at=created_at, rule_id=rule_id,
    )


def test_rule_quality_metrics():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original_users = config.DASHBOARD_USERS_FILE
        original_audit = config.ANALYST_AUDIT_FILE
        config.DASHBOARD_USERS_FILE = str(directory / "users.json")
        config.ANALYST_AUDIT_FILE = str(directory / "audit.jsonl")
        repository = SQLiteAlertRepository(str(directory / "alerts.db"))
        alerts = [
            _alert("2026-08-24T00:10:00Z", "DET-A"),
            _alert("2026-08-24T00:20:00Z", "DET-A"),
            _alert("2026-08-24T00:30:00Z", "DET-A"),
            _alert("2026-08-24T00:40:00Z", "DET-A"),
            _alert("2026-08-24T01:00:00Z", "DET-B"),
            _alert("2026-08-25T00:00:00Z", "DET-A"),
        ]
        for alert in alerts:
            repository.create_alert(alert)
        repository.create_detection_feedback(
            alerts[0]["alert_id"], "TRUE_POSITIVE", "", "tier-1", "analyst",
        )
        repository.create_detection_feedback(
            alerts[0]["alert_id"], "FALSE_POSITIVE", "Latest verdict", "tier-2", "analyst",
        )
        repository.create_detection_feedback(
            alerts[1]["alert_id"], "TRUE_POSITIVE", "", "tier-1", "analyst",
        )
        repository.create_detection_feedback(
            alerts[3]["alert_id"], "BENIGN_EXPECTED", "", "tier-1", "analyst",
        )
        repository.create_detection_feedback(
            alerts[5]["alert_id"], "FALSE_POSITIVE", "Outside range", "tier-1", "analyst",
        )

        start, end = "2026-08-24T00:00:00Z", "2026-08-25T00:00:00Z"
        quality = repository.rule_quality(start, end)
        assert quality == [
            {
                "rule_id": "DET-A", "alerts_generated": 4,
                "true_positives": 1, "false_positives": 1,
                "benign_expected": 1, "unclassified": 1,
                "classified_sample_size": 3, "false_positive_rate_percent": 33.33,
            },
            {
                "rule_id": "DET-B", "alerts_generated": 1,
                "true_positives": 0, "false_positives": 0,
                "benign_expected": 0, "unclassified": 1,
                "classified_sample_size": 0, "false_positive_rate_percent": None,
            },
        ]

        validation_file = directory / "validation.json"
        validation_file.write_text(json.dumps({"rules": [
            {"rule_id": "DET-A", "scenario_count": 2, "last_validation_result": "PASS"},
            {"rule_id": "DET-C", "scenario_count": 1, "last_validation_result": "FAIL"},
        ]}), encoding="utf-8")

        try:
            client = dashboard.app.test_client()
            login_as(client, directory, role="viewer", username="quality-viewer")
            with (
                patch.object(dashboard, "alert_repository", repository),
                patch.object(dashboard, "VALIDATION_COVERAGE_FILE", validation_file),
            ):
                response = client.get(f"/api/analytics/kpis?from={start}&to={end}")
                assert response.status_code == 200
                payload = response.get_json()
                rows = payload["analytics"]["rule_quality"]
                assert [row["rule_id"] for row in rows] == ["DET-A", "DET-B", "DET-C"]
                assert rows[0]["validation_scenario_count"] == 2
                assert rows[0]["last_validation_result"] == "PASS"
                assert rows[1]["last_validation_result"] == "UNAVAILABLE"
                assert rows[2]["alerts_generated"] == 0
                assert rows[2]["validation_scenario_count"] == 1
                assert "Latest verdict" not in json.dumps(payload)
                assert "tier-1" not in json.dumps(payload)
                assert not {"precision", "recall"} & set(payload["definitions"])

                page = client.get("/analytics").get_data(as_text=True)
                assert "Rule quality" in page and "Unclassified" in page
                assert "not precision or recall" in page
                script = client.get("/static/js/app.js").get_data(as_text=True)
                assert "rule-quality-body" in script and "classified_sample_size" in script

                validation_file.write_text(json.dumps({"rules": [{
                    "rule_id": "DET-BAD", "scenario_count": "many",
                    "last_validation_result": "<script>",
                }]}), encoding="utf-8")
                assert dashboard._rule_quality_with_validation([]) == [{
                    "rule_id": "DET-BAD", "alerts_generated": 0,
                    "true_positives": 0, "false_positives": 0,
                    "benign_expected": 0, "unclassified": 0,
                    "classified_sample_size": 0, "false_positive_rate_percent": None,
                    "validation_scenario_count": 0,
                    "last_validation_result": "UNAVAILABLE",
                }]
        finally:
            config.DASHBOARD_USERS_FILE = original_users
            config.ANALYST_AUDIT_FILE = original_audit


if __name__ == "__main__":
    test_rule_quality_metrics()
    print("M20.2 rule quality metrics passed")
