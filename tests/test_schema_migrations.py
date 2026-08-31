import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.sqlite_store import (
    BASELINE_CHECKSUM,
    BASELINE_NAME,
    BASELINE_VERSION,
    SQLiteAlertRepository,
)


def test_schema_migrations():
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / "baseline.db"
        SQLiteAlertRepository(str(database)).ensure_schema()
        SQLiteAlertRepository(str(database)).ensure_schema()

        with sqlite3.connect(database) as connection:
            columns = [
                row[1] for row in connection.execute("PRAGMA table_info(schema_migrations)")
            ]
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            migrations = connection.execute(
                "SELECT version, name, applied_at, checksum "
                "FROM schema_migrations ORDER BY version"
            ).fetchall()
        assert columns == ["version", "name", "applied_at", "checksum"]
        assert {"alerts", "assets", "ingestion_failures", "ingestion_health"} <= tables
        assert len(migrations) == 1
        assert migrations[0][:2] == (BASELINE_VERSION, BASELINE_NAME)
        assert migrations[0][2].endswith("Z")
        assert migrations[0][3] == BASELINE_CHECKSUM

        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE schema_migrations SET checksum = ? WHERE version = ?",
                ("0" * 64, BASELINE_VERSION),
            )
        try:
            SQLiteAlertRepository(str(database)).ensure_schema()
            raise AssertionError("A changed baseline checksum must be rejected")
        except RuntimeError:
            pass

        failed_database = Path(directory) / "failed.db"
        with patch("src.sqlite_store.BASELINE_SCHEMA", "CREATE TABLE partial (id); INVALID;"):
            try:
                SQLiteAlertRepository(str(failed_database)).ensure_schema()
                raise AssertionError("Invalid baseline DDL must fail")
            except sqlite3.DatabaseError:
                pass
        with sqlite3.connect(failed_database) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('partial', 'schema_migrations')"
            ).fetchone()[0] == 0


if __name__ == "__main__":
    test_schema_migrations()
    print("M24.1 schema migration tracking passed")
