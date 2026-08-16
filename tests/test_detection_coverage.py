import tempfile
from pathlib import Path

from src.alert_schema import build_alert
from src.rules import build_detection_coverage
from src.sqlite_store import SQLiteAlertRepository


def test_detection_coverage():
    rules = [
        {
            "id": "DET-TEST-001",
            "title": "Hit rule",
            "severity": "LOW",
            "mitre": {"tactic": "Test", "technique": "T0001"},
        },
        {
            "id": "DET-TEST-002",
            "title": "Never-hit rule",
            "severity": "MEDIUM",
            "mitre": {"tactic": "Test", "technique": "T0002"},
        },
    ]
    with tempfile.TemporaryDirectory() as directory:
        repository = SQLiteAlertRepository(str(Path(directory, "alerts.db")))
        for _ in range(2):
            repository.create_alert(build_alert(
                rule_id="DET-TEST-001",
                alert_name="Hit rule",
                severity="LOW",
                source_type="HIDS_LOG",
                description="coverage test",
                mitre_attck_id="T0001",
            ))
        coverage = build_detection_coverage(
            rules,
            repository.rule_hit_counts([rule["id"] for rule in rules]),
        )

    assert coverage["summary"] == {
        "rules_total": 2,
        "rules_hit": 1,
        "rules_never_hit": 1,
        "mitre_techniques_total": 2,
        "mitre_techniques_hit": 1,
    }
    assert [rule["hit_count"] for rule in coverage["rules"]] == [2, 0]


if __name__ == "__main__":
    test_detection_coverage()
    print("M5.4 detection coverage passed")
