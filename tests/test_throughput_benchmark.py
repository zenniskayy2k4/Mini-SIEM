import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from tools.benchmark_throughput import main, run_benchmark


def test_single_node_throughput_benchmark():
    report = run_benchmark(
        rates=(100,), duration=0.05, burst_count=5,
        api_url="http://localhost:5000/health", api_samples=3,
        api_probe=lambda _url: 200,
    )
    assert report["schema_version"] == 1
    assert report["ai_enabled"] is report["threat_intelligence_enabled"] is False
    assert len(report["profiles"]) == 2
    for profile, expected in zip(report["profiles"], (5, 5)):
        assert profile["attempted_events"] == profile["processed_events"] == expected
        assert profile["sqlite_rows"] == expected
        assert profile["achieved_events_per_second"] > 0
        assert profile["cpu_percent"] >= 0
        assert profile["python_peak_memory_bytes"] > 0
        assert profile["queue_depth_max"] == 0
        assert profile["dropped_events"] == profile["rejected_events"] == 0
        assert set(profile["latency"]) == {"normalization", "detection", "sqlite_write"}
        assert all(metrics["p95_ms"] >= 0 for metrics in profile["latency"].values())
    assert report["dashboard_api"]["samples"] == 3
    assert report["dashboard_api"]["status"] == 200
    assert report["dashboard_api"]["latency"]["p95_ms"] >= 0

    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "report.json"
        with patch("tools.benchmark_throughput._request_api", return_value=200):
            assert main([
                "--rates", "100", "--duration", "0.01", "--burst-count", "1",
                "--api-samples", "1", "--json-output", str(output),
            ]) == 0
        assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == 1

    for kwargs in (
        {"rates": ()},
        {"rates": (10,), "duration": 0},
        {"rates": (10,), "burst_count": 100_001},
        {"rates": (10,), "api_url": "https://example.invalid/health"},
        {"rates": (10,), "api_url": "http://user:password@localhost/health"},
        {"rates": (10,), "api_url": "http://localhost/health?sample=1"},
    ):
        try:
            run_benchmark(api_probe=lambda _url: 200, **kwargs)
            raise AssertionError("Invalid benchmark settings were accepted")
        except ValueError:
            pass


if __name__ == "__main__":
    test_single_node_throughput_benchmark()
    print("M25.2 single-node throughput benchmark passed")
