import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import config
from src.alert_schema import utc_iso


TERMINAL_INCIDENT_STATUSES = {"RESOLVED", "FALSE_POSITIVE"}


def _stamp(now=None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def backup_database(db_path=None, output_path=None) -> Path:
    source_path = Path(db_path or config.SQLITE_ALERT_DB)
    if not source_path.is_file():
        raise FileNotFoundError(f"SQLite database not found: {source_path}")
    if output_path:
        backup_path = Path(output_path)
        if backup_path.exists():
            raise FileExistsError(f"Backup already exists: {backup_path}")
    else:
        directory = Path(config.SQLITE_BACKUP_DIR)
        backup_path = directory / f"{source_path.stem}.backup-{_stamp()}{source_path.suffix}"
    if source_path.resolve() == backup_path.resolve():
        raise ValueError("Backup path must differ from source database")
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sqlite3.connect(source_path) as source, sqlite3.connect(backup_path) as target:
            source.backup(target)
            if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise sqlite3.DatabaseError("Backup integrity check failed")
    except Exception:
        backup_path.unlink(missing_ok=True)
        raise
    return backup_path


def _write_archive(alerts: list[dict], directory: Path, now=None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"alerts-{_stamp(now)}.jsonl"
    if path.exists():
        raise FileExistsError(f"Archive already exists: {path}")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=directory, delete=False, suffix=".tmp"
        ) as output:
            temporary = Path(output.name)
            for alert in alerts:
                output.write(json.dumps(alert, ensure_ascii=False) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)
    return path


def _prune_json_mirror(path: Path, archived_ids: set[str]) -> int:
    if not path.exists() or not archived_ids:
        return 0
    kept, removed = [], 0
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True):
        try:
            archived = json.loads(line).get("alert_id") in archived_ids
        except (json.JSONDecodeError, AttributeError):
            archived = False
        if archived:
            removed += 1
        else:
            kept.append(line)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("".join(kept), encoding="utf-8")
    os.replace(temporary, path)
    return removed


def apply_retention(days=None, db_path=None, json_path=None, archive_dir=None, now=None) -> dict:
    days = int(config.ALERT_RETENTION_DAYS if days is None else days)
    if days < 1:
        raise ValueError("Retention days must be positive")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    cutoff = utc_iso(now - timedelta(days=days))
    db_path = Path(db_path or config.SQLITE_ALERT_DB)
    backup_path = backup_database(db_path)
    terminal = ",".join("?" for _ in TERMINAL_INCIDENT_STATUSES)
    eligible = f"""
        datetime(a.timestamp) < datetime(?)
        AND (
            a.incident_id IS NULL
            OR UPPER(COALESCE(i.status, json_extract(a.payload_json, '$.incident_status'), ''))
               IN ({terminal})
        )
    """
    terminal_values = sorted(TERMINAL_INCIDENT_STATUSES)
    with sqlite3.connect(db_path, timeout=30) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            f"SELECT a.alert_id, a.payload_json FROM alerts a LEFT JOIN incidents i ON i.alert_id=a.alert_id WHERE {eligible}",
            [cutoff, *terminal_values],
        ).fetchall()
        preserved_open = connection.execute(
            f"""
            SELECT COUNT(*) FROM alerts a JOIN incidents i ON i.alert_id=a.alert_id
            WHERE datetime(a.timestamp) < datetime(?) AND UPPER(i.status) NOT IN ({terminal})
            """,
            [cutoff, *terminal_values],
        ).fetchone()[0]
        alerts = [json.loads(payload) for _, payload in rows]
        archive_path = _write_archive(alerts, Path(archive_dir or config.ALERT_ARCHIVE_DIR), now) if rows else None
        if rows:
            connection.execute(
                f"DELETE FROM alerts WHERE alert_id IN (SELECT a.alert_id FROM alerts a LEFT JOIN incidents i ON i.alert_id=a.alert_id WHERE {eligible})",
                [cutoff, *terminal_values],
            )
        connection.commit()
        if rows:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("VACUUM")

    archived_ids = {alert_id for alert_id, _ in rows}
    mirror_removed = _prune_json_mirror(
        Path(json_path or config.OUTPUT_ALERT_FILE), archived_ids,
    )
    return {
        "cutoff": cutoff,
        "archived": len(rows),
        "preserved_open_incidents": int(preserved_open),
        "archive": str(archive_path) if archive_path else None,
        "backup": str(backup_path),
        "json_mirror_removed": mirror_removed,
    }


def rotate_logs(paths=None, max_bytes=None, backups=None) -> dict:
    paths = paths or [
        config.LOG_FILE_TO_WATCH,
        config.WINDOWS_EVENT_FILE,
        config.RESPONSE_LOG_FILE,
        config.NOTIFICATION_LOG_FILE,
    ]
    max_bytes = int(config.LOG_ROTATE_MAX_BYTES if max_bytes is None else max_bytes)
    backups = int(config.LOG_ROTATE_BACKUPS if backups is None else backups)
    if max_bytes < 1 or backups < 1:
        raise ValueError("Rotation size and backups must be positive")
    rotated = []
    for value in paths:
        path = Path(value)
        if not path.is_file() or path.stat().st_size < max_bytes:
            continue
        for index in range(backups, 1, -1):
            previous = Path(f"{path}.{index - 1}")
            if previous.exists():
                os.replace(previous, Path(f"{path}.{index}"))
        shutil.copy2(path, Path(f"{path}.1"))
        path.write_text("", encoding="utf-8")
        rotated.append(str(path))
    return {"rotated": rotated, "max_bytes": max_bytes, "backups": backups}
