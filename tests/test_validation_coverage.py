import json
from copy import deepcopy
from unittest.mock import patch

from tools.generate_validation_coverage import (
    JSON_ARTIFACT,
    MARKDOWN_ARTIFACT,
    build_validation_coverage,
    json_artifact,
    markdown_artifact,
)


def test_validation_coverage():
    with patch(
        "requests.sessions.Session.request",
        side_effect=AssertionError("coverage generation attempted a network call"),
    ), patch(
        "sqlite3.connect",
        side_effect=AssertionError("coverage generation attempted a runtime DB call"),
    ):
        report = build_validation_coverage()
        assert report == build_validation_coverage()

    assert report["summary"] == {
        "rules_total": 14,
        "rules_validated": 14,
        "rules_failed": 0,
        "rules_unvalidated": 0,
        "scenarios_total": 18,
        "scenarios_passed": 18,
        "scenarios_failed": 0,
        "runtime_hits_evaluated": False,
    }
    assert all(rule["last_validation_result"] == "PASS" for rule in report["rules"])
    assert all(rule["runtime_hit_count"] is None for rule in report["rules"])
    assert json.loads(JSON_ARTIFACT.read_text(encoding="utf-8")) == report
    assert JSON_ARTIFACT.read_text(encoding="utf-8") == json_artifact(report)
    assert MARKDOWN_ARTIFACT.read_text(encoding="utf-8") == markdown_artifact(report)

    unvalidated = deepcopy(report)
    unvalidated["rules"][0]["last_validation_result"] = "UNVALIDATED"
    assert f"- `{unvalidated['rules'][0]['rule_id']}`" in markdown_artifact(unvalidated)


if __name__ == "__main__":
    test_validation_coverage()
    print("M19.4 validation coverage matrix passed")
