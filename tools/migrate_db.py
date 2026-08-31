"""Apply versioned Mini-SIEM SQLite migrations."""

import argparse
import json
import sqlite3
from pathlib import Path

from config import config
from src.alert_schema import utc_iso
from src.maintenance import backup_database
from src.sqlite_store import (
    MIGRATIONS,
    SCHEMA_MIGRATIONS_TABLE,
)


if [migration[0] for migration in MIGRATIONS] != list(range(1, len(MIGRATIONS) + 1)):
    raise RuntimeError("Schema migration registry must be contiguous and version ordered")


def _integrity(connection):
    result = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        raise sqlite3.DatabaseError(f"Database integrity check failed: {result}")


def inspect_database(db_path) -> int:
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"SQLite database not found: {path}")
    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        _integrity(connection)
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone()
        if not exists:
            return 0
        rows = connection.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
        ).fetchall()

    if not rows:
        return 0
    versions = [row[0] for row in rows]
    if versions != list(range(1, versions[-1] + 1)):
        raise ValueError("Schema migration history is not contiguous")
    expected = {version: (name, checksum) for version, name, checksum, _ in MIGRATIONS}
    for version, name, checksum in rows:
        if expected.get(version) != (name, checksum):
            raise ValueError(f"Unknown or changed schema migration: {version}")
    return versions[-1]


def migrate_database(db_path=None, *, dry_run=False, backup_path=None) -> dict:
    path = Path(db_path or config.SQLITE_ALERT_DB)
    source_version = inspect_database(path)
    target_version = MIGRATIONS[-1][0]
    if source_version > target_version:
        raise ValueError(
            f"Database version {source_version} is newer than supported version {target_version}"
        )
    pending = [
        {"version": version, "name": name}
        for version, name, _, _ in MIGRATIONS
        if version > source_version
    ]
    report = {
        "database": str(path),
        "dry_run": bool(dry_run),
        "source_version": source_version,
        "target_version": target_version,
        "result_version": source_version,
        "pending_migrations": pending,
        "backup": None,
        "integrity": "ok",
    }
    if dry_run or not pending:
        return report

    report["backup"] = str(backup_database(path, backup_path))
    with sqlite3.connect(path, timeout=30) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        for version, name, checksum, ddl in MIGRATIONS:
            if version <= source_version:
                continue
            try:
                connection.executescript(
                    "BEGIN IMMEDIATE;\n" + ddl + SCHEMA_MIGRATIONS_TABLE
                )
                connection.execute(
                    """
                    INSERT INTO schema_migrations (version, name, applied_at, checksum)
                    VALUES (?, ?, ?, ?)
                    """,
                    (version, name, utc_iso(), checksum),
                )
                _integrity(connection)
            except Exception:
                connection.rollback()
                raise
            connection.commit()
    report["result_version"] = inspect_database(path)
    if report["result_version"] != target_version:
        raise RuntimeError("Database migration did not reach the target version")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=config.SQLITE_ALERT_DB)
    parser.add_argument("--backup")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.dry_run and args.backup:
        parser.error("--backup cannot be combined with --dry-run")
    try:
        report = migrate_database(args.db, dry_run=args.dry_run, backup_path=args.backup)
    except (FileNotFoundError, RuntimeError, ValueError, sqlite3.Error) as exc:
        parser.error(str(exc))
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
