"""Benchmark retained-alert read paths without touching live Mini-SIEM data."""

import argparse
import json
import sqlite3
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import config
from src.alert_schema import build_alert, utc_iso
from src.incident_report import generate_incident_pdf
from src.maintenance import apply_retention
from src.rules import build_detection_coverage
from src.sqlite_store import SQLiteAlertRepository


DEFAULT_SIZES = (10_000, 50_000, 100_000)
MAX_ALERTS = 100_000
NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)
RULES = [
    {"id": f"DET-BENCH-{index}", "title": f"Benchmark rule {index}",
     "severity": "HIGH" if index == 0 else "LOW",
     "mitre": {"tactic": "Discovery", "technique": f"T10{index:02d}"}}
    for index in range(4)
]


def _alert(index):
    incident = index % 20 == 0
    old = index % 2 == 0
    timestamp = (datetime(2026, 1, 1, tzinfo=timezone.utc) if old else NOW - timedelta(days=5))
    timestamp += timedelta(seconds=index)
    resolved = incident and index % 40 == 0
    return build_alert(
        alert_id=f"ALT-BENCH-{index:06d}",
        alert_name="Credential benchmark event" if index % 7 == 0 else "Telemetry benchmark event",
        severity="HIGH" if incident else ("MEDIUM" if index % 5 == 0 else "LOW"),
        source_type="HIDS_LOG",
        description="Large retained history benchmark record.",
        raw_log=f"offline benchmark event {index}",
        ip_address=f"198.51.100.{index % 250 + 1}",
        mitre_attck_id=RULES[index % len(RULES)]["mitre"]["technique"],
        rule_id=RULES[index % len(RULES)]["id"],
        timestamp=timestamp,
        incident_id=f"INC-BENCH-{index:06d}" if incident else None,
        incident_status="RESOLVED" if resolved else ("INVESTIGATING" if incident else None),
        assigned_to="benchmark-analyst" if incident and index % 60 == 0 else None,
        timeline=[{
            "event_type": "STATUS_CHANGED", "timestamp": utc_iso(timestamp + timedelta(seconds=30)),
            "from_status": "INVESTIGATING", "to_status": "RESOLVED",
        }] if resolved else [],
    )


def _measure(callback, repeats):
    values = []
    result = None
    for _ in range(repeats):
        started = time.perf_counter()
        result = callback()
        values.append((time.perf_counter() - started) * 1000)
    return round(statistics.median(values), 3), result


def _copy_database(source, target):
    with sqlite3.connect(source) as original, sqlite3.connect(target) as copy:
        original.backup(copy)


def _profile(repository, size, directory, repeats):
    latency = {}
    latency["alert_api"], latest = _measure(
        lambda: json.loads(json.dumps(repository.list_alerts(limit=50), ensure_ascii=False)),
        repeats,
    )
    if not latest:
        raise RuntimeError("alert API path returned no records")

    latency["search"], search = _measure(lambda: repository.search_alerts(
        {"severity": "HIGH", "q": "credential", "from": "2026-01-01T00:00:00Z"},
        limit=50,
    ), repeats)
    if search["total"] < 1:
        raise RuntimeError("large-history search returned no records")

    latency["analytics"], analytics = _measure(lambda: (
        repository.soc_kpis("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"),
        repository.soc_analytics("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"),
    ), repeats)
    if not analytics[1]["alert_trend"]:
        raise RuntimeError("analytics returned no trend")

    rule_ids = [rule["id"] for rule in RULES]
    latency["rule_coverage"], coverage = _measure(
        lambda: build_detection_coverage(RULES, repository.rule_hit_counts(rule_ids)), repeats,
    )
    if coverage["summary"]["rules_hit"] != len(RULES):
        raise RuntimeError("rule coverage missed seeded rules")

    latency["incident_workspace"], workspace = _measure(lambda: repository.search_alerts(
        {"open_incidents": True}, limit=50,
    ), repeats)
    if not workspace["items"]:
        raise RuntimeError("incident workspace returned no open incident")
    incident = repository.get_alert(workspace["items"][0]["alert_id"])

    latency["report_generation"], report = _measure(
        lambda: generate_incident_pdf(incident), repeats,
    )
    if not report.startswith(b"%PDF-1.4"):
        raise RuntimeError("incident report is not a PDF")

    retention_root = Path(directory) / f"retention-{size}"
    retention_root.mkdir()
    retention_db = retention_root / "alerts.db"
    _copy_database(repository.path, retention_db)
    original_backup_dir = config.SQLITE_BACKUP_DIR
    try:
        config.SQLITE_BACKUP_DIR = str(retention_root / "backups")
        latency["retention"], retention = _measure(lambda: apply_retention(
            30,
            db_path=retention_db,
            json_path=retention_root / "mirror.jsonl",
            archive_dir=retention_root / "archive",
            now=NOW,
        ), 1)
    finally:
        config.SQLITE_BACKUP_DIR = original_backup_dir
    if retention["archived"] < 1 or retention["preserved_open_incidents"] < 1:
        raise RuntimeError("retention did not archive old alerts and preserve open incidents")

    return {
        "alerts": size,
        "database_bytes": Path(repository.path).stat().st_size,
        "latency_ms": latency,
        "search_matches": search["total"],
        "open_incidents": workspace["total"],
        "retention_archived": retention["archived"],
        "retention_preserved_open_incidents": retention["preserved_open_incidents"],
    }


def run_benchmark(sizes=DEFAULT_SIZES, repeats=3):
    sizes = tuple(sizes)
    if (
        not 1 <= len(sizes) <= 3 or sizes != tuple(sorted(set(sizes)))
        or any(not isinstance(size, int) or isinstance(size, bool) or not 100 <= size <= MAX_ALERTS for size in sizes)
    ):
        raise ValueError("sizes must contain 1-3 increasing unique integers within 100..100000")
    if not isinstance(repeats, int) or isinstance(repeats, bool) or not 1 <= repeats <= 10:
        raise ValueError("repeats must be within 1..10")

    profiles = []
    with tempfile.TemporaryDirectory(prefix="mini-siem-large-history-") as directory:
        repository = SQLiteAlertRepository(str(Path(directory) / "alerts.db"))
        inserted = 0
        for size in sizes:
            started = time.perf_counter()
            for offset in range(inserted, size, 1_000):
                repository.create_alerts(
                    _alert(index) for index in range(offset, min(size, offset + 1_000))
                )
            setup_seconds = time.perf_counter() - started
            if repository.stats()["total"] != size:
                raise RuntimeError(f"seeded alert count does not match {size}")
            profile = _profile(repository, size, directory, repeats)
            profile["setup_seconds"] = round(setup_seconds, 3)
            profiles.append(profile)
            inserted = size
    return {
        "schema_version": 1,
        "generated_at": utc_iso(),
        "scope": "isolated temporary SQLite; no live data, network, AI, or JSON dual-write",
        "profiles": profiles,
    }


def _sizes(value):
    try:
        return tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("sizes must be comma-separated integers") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=_sizes, default=DEFAULT_SIZES)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--json-output", help="new report path; existing files are refused")
    args = parser.parse_args(argv)
    try:
        report = run_benchmark(args.sizes, args.repeats)
        serialized = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.json_output:
            with Path(args.json_output).open("x", encoding="utf-8", newline="\n") as output:
                output.write(serialized)
        else:
            print(serialized, end="")
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
