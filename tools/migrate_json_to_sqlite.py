"""Idempotently migrate JSONL alerts into the SQLite mirror."""

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from config import config
from src.alert_schema import SEVERITIES, SOURCE_TYPES, ensure_lifecycle
from src.sqlite_store import SQLiteAlertRepository


def _normalize(alert):
    if not isinstance(alert, dict):
        raise ValueError("alert must be a JSON object")
    if not alert.get("alert_id"):
        canonical = json.dumps(alert, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        alert["alert_id"] = f"ALT-{uuid5(NAMESPACE_URL, canonical)}"

    alert["severity"] = str(alert.get("severity") or "LOW").upper()
    alert["source_type"] = str(alert.get("source_type") or "HIDS_LOG").upper()
    if alert["severity"] not in SEVERITIES:
        raise ValueError(f"invalid severity: {alert['severity']}")
    if alert["source_type"] not in SOURCE_TYPES:
        raise ValueError(f"invalid source_type: {alert['source_type']}")

    alert.setdefault("alert_name", "Legacy Alert")
    alert.setdefault("description", "")
    alert.setdefault("status", "DETECTED")
    ensure_lifecycle(alert)
    alert.setdefault("timestamp", alert["created_at"])
    return alert


def _backup_database(db_path):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = db_path.with_name(f"{db_path.stem}.backup-{stamp}{db_path.suffix}")
    with sqlite3.connect(db_path) as source, sqlite3.connect(backup_path) as target:
        source.backup(target)
    return backup_path


def migrate(json_path=None, db_path=None):
    json_path = Path(json_path or config.OUTPUT_ALERT_FILE)
    db_path = Path(db_path or config.SQLITE_ALERT_DB)
    if not json_path.is_file():
        raise FileNotFoundError(f"JSON alert file not found: {json_path}")

    repository = SQLiteAlertRepository(str(db_path))
    repository.ensure_schema()
    backup_path = _backup_database(db_path)
    report = {"imported": 0, "skipped": 0, "failed": 0, "backup": str(backup_path)}

    with json_path.open("r", encoding="utf-8", errors="ignore") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                alert = _normalize(json.loads(line))
                if repository.get_alert(alert["alert_id"]):
                    report["skipped"] += 1
                    continue
                repository.create_alert(alert)
                report["imported"] += 1
            except (json.JSONDecodeError, KeyError, TypeError, ValueError, sqlite3.Error) as exc:
                report["failed"] += 1
                print(f"line {line_number}: {exc}", file=sys.stderr)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", default=config.OUTPUT_ALERT_FILE)
    parser.add_argument("--db", default=config.SQLITE_ALERT_DB)
    args = parser.parse_args()
    print(json.dumps(migrate(args.json, args.db), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
