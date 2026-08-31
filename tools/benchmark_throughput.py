"""Measure bounded single-node telemetry throughput without touching live alert data."""

import argparse
import json
import math
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import config
from src.alert_schema import build_alert, utc_iso
from src.detector import ThreatDetector
from src.event_envelope import validate_event_envelope
from src.rules import load_detection_rules
from src.sqlite_store import SQLiteAlertRepository
from tools.generate_telemetry_load import MAX_EVENTS, generate_events


DEFAULT_RATES = (10, 50, 100, 250)
MAX_RATE = 1_000
MAX_PROFILES = 10
MAX_API_SAMPLES = 100
LOCAL_API_HOSTS = {"localhost", "127.0.0.1", "::1", "dashboard"}


def _latency(values):
    ordered = sorted(values)
    p95 = ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]
    return {
        "mean_ms": round(statistics.fmean(ordered), 6),
        "p95_ms": round(p95, 6),
        "max_ms": round(ordered[-1], 6),
    }


def _detect(detector, event):
    if event["source_type"] == "HIDS_LOG":
        return detector.analyze(event["payload"]["message"])
    if event["source_type"] == "WINDOWS_EVENT":
        return detector.analyze_windows_event(event)
    return None


def _profile(name, mode, count, target_rate, duration, directory, rules):
    repository = SQLiteAlertRepository(str(Path(directory) / f"{name}.db"))
    repository.ensure_schema()
    detector = ThreatDetector(rules, load_models=False)
    normalization_ms, detection_ms, sqlite_ms = [], [], []
    detections = rejected = processed = 0

    tracemalloc.start()
    cpu_started = time.process_time()
    wall_started = time.perf_counter()
    for index, event in enumerate(generate_events(mode, count, duration=duration)):
        if target_rate:
            deadline = wall_started + index / target_rate
            time.sleep(max(0, deadline - time.perf_counter()))
        try:
            started = time.perf_counter_ns()
            event = validate_event_envelope(event)
            normalization_ms.append((time.perf_counter_ns() - started) / 1_000_000)

            started = time.perf_counter_ns()
            detections += _detect(detector, event) is not None
            detection_ms.append((time.perf_counter_ns() - started) / 1_000_000)

            alert = build_alert(
                alert_id=f"ALT-BENCH-{name}-{index:08d}",
                alert_name="Synthetic throughput benchmark event",
                severity="LOW",
                source_type=event["source_type"],
                description="Isolated local benchmark record.",
                timestamp=event["observed_at"],
                event_envelope_id=event["event_id"],
            )
            started = time.perf_counter_ns()
            repository.create_alert(alert)
            sqlite_ms.append((time.perf_counter_ns() - started) / 1_000_000)
            processed += 1
        except (KeyError, TypeError, ValueError):
            rejected += 1

    if target_rate:
        time.sleep(max(0, wall_started + count / target_rate - time.perf_counter()))
    wall_seconds = time.perf_counter() - wall_started
    cpu_seconds = time.process_time() - cpu_started
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if not processed:
        raise RuntimeError(f"profile {name} processed no events")
    return {
        "name": name,
        "mode": mode,
        "target_events_per_second": target_rate,
        "attempted_events": count,
        "processed_events": processed,
        "achieved_events_per_second": round(processed / wall_seconds, 3),
        "wall_seconds": round(wall_seconds, 6),
        "cpu_percent": round(100 * cpu_seconds / wall_seconds, 3),
        "python_peak_memory_bytes": peak_memory,
        "latency": {
            "normalization": _latency(normalization_ms),
            "detection": _latency(detection_ms),
            "sqlite_write": _latency(sqlite_ms),
        },
        "detections": detections,
        "sqlite_rows": repository.stats()["total"],
        "queue_depth_max": 0,
        "dropped_events": 0,
        "rejected_events": rejected,
    }


def _local_api_url(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in LOCAL_API_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/health"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("api-url must be the local HTTP(S) /health endpoint without credentials")
    return value


def _request_api(url):
    with build_opener(ProxyHandler({})).open(url, timeout=2) as response:
        body = response.read(64 * 1024)
        if response.status != 200 or not isinstance(json.loads(body), dict):
            raise ValueError("dashboard API did not return a successful JSON object")
        return response.status


def _api_latency(url, samples, probe=None):
    probe = probe or _request_api
    values = []
    status = None
    for _ in range(samples):
        started = time.perf_counter_ns()
        status = probe(url)
        values.append((time.perf_counter_ns() - started) / 1_000_000)
    return {"url": url, "samples": samples, "status": status, "latency": _latency(values)}


def run_benchmark(
    rates=DEFAULT_RATES, duration=1.0, burst_count=250,
    api_url="http://localhost:5000/health", api_samples=10, api_probe=None,
):
    rates = tuple(rates)
    if (
        not rates or len(rates) > MAX_PROFILES or len(rates) != len(set(rates))
        or any(not isinstance(rate, int) or isinstance(rate, bool) or not 1 <= rate <= MAX_RATE for rate in rates)
    ):
        raise ValueError(f"rates must contain 1-{MAX_PROFILES} unique integers within 1..{MAX_RATE}")
    if (
        not isinstance(duration, (int, float)) or isinstance(duration, bool)
        or not math.isfinite(duration) or not 0.01 <= duration <= 60
    ):
        raise ValueError("duration must be within 0.01..60 seconds")
    if not isinstance(burst_count, int) or isinstance(burst_count, bool) or not 1 <= burst_count <= MAX_EVENTS:
        raise ValueError(f"burst-count must be within 1..{MAX_EVENTS}")
    if not isinstance(api_samples, int) or isinstance(api_samples, bool) or not 1 <= api_samples <= MAX_API_SAMPLES:
        raise ValueError(f"api-samples must be within 1..{MAX_API_SAMPLES}")
    api_url = _local_api_url(api_url)
    counts = [max(1, round(rate * duration)) for rate in rates]
    if sum(counts) + burst_count > MAX_EVENTS:
        raise ValueError(f"total attempted events must not exceed {MAX_EVENTS}")

    rules = load_detection_rules(config.RULES_DIR, config.SIGNATURES, config.SIGMA_RULES_DIR)
    profiles = []
    with tempfile.TemporaryDirectory(prefix="mini-siem-throughput-") as directory:
        for rate, count in zip(rates, counts):
            profiles.append(_profile(
                f"rate-{rate}", "authentication-heavy", count, rate,
                duration, directory, rules,
            ))
        profiles.append(_profile(
            "burst", "burst", burst_count, None, 0, directory, rules,
        ))
    return {
        "schema_version": 1,
        "generated_at": utc_iso(),
        "scope": "isolated single-node process with temporary SQLite",
        "ai_enabled": False,
        "threat_intelligence_enabled": False,
        "profiles": profiles,
        "dashboard_api": _api_latency(api_url, api_samples, api_probe),
    }


def _rates(value):
    try:
        return tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("rates must be comma-separated integers") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rates", type=_rates, default=DEFAULT_RATES)
    parser.add_argument("--duration", type=float, default=1.0)
    parser.add_argument("--burst-count", type=int, default=250)
    parser.add_argument("--api-url", default="http://localhost:5000/health")
    parser.add_argument("--api-samples", type=int, default=10)
    parser.add_argument("--json-output", help="new report path; existing files are refused")
    args = parser.parse_args(argv)
    try:
        report = run_benchmark(
            args.rates, args.duration, args.burst_count,
            args.api_url, args.api_samples,
        )
        serialized = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.json_output:
            with Path(args.json_output).open("x", encoding="utf-8", newline="\n") as output:
                output.write(serialized)
        else:
            print(serialized, end="")
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        parser.error(str(exc))
    if args.json_output:
        print(f"Throughput report written to {args.json_output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
