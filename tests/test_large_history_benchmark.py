import json
import tempfile
from pathlib import Path

from tools.benchmark_large_history import main, run_benchmark


def test_large_history_benchmark():
    report = run_benchmark(sizes=(100, 250), repeats=1)
    assert report["schema_version"] == 1
    assert "temporary SQLite" in report["scope"]
    assert [profile["alerts"] for profile in report["profiles"]] == [100, 250]
    for profile in report["profiles"]:
        assert set(profile["latency_ms"]) == {
            "alert_api", "search", "analytics", "rule_coverage",
            "incident_workspace", "report_generation", "retention",
        }
        assert all(value >= 0 for value in profile["latency_ms"].values())
        assert profile["retention_archived"] > 0
        assert profile["retention_preserved_open_incidents"] > 0

    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "report.json"
        assert main(["--sizes", "100", "--repeats", "1", "--json-output", str(output)]) == 0
        assert json.loads(output.read_text(encoding="utf-8"))["profiles"][0]["alerts"] == 100

    for kwargs in (
        {"sizes": ()}, {"sizes": (250, 100)}, {"sizes": (100, 100)},
        {"sizes": (100_001,)}, {"sizes": (100,), "repeats": 0},
    ):
        try:
            run_benchmark(**kwargs)
            raise AssertionError("Invalid benchmark settings were accepted")
        except ValueError:
            pass


if __name__ == "__main__":
    test_large_history_benchmark()
    print("M26.3 large-history benchmark passed")
