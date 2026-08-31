import sqlite3
import tempfile
from pathlib import Path

from tools.migrate_db import inspect_database, migrate_database


def test_db_migrations():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        database = root / "legacy.db"
        backup = root / "legacy.backup.db"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE legacy_marker (value TEXT NOT NULL)")
            connection.execute("INSERT INTO legacy_marker VALUES ('preserved')")

        dry_run = migrate_database(database, dry_run=True)
        assert dry_run["source_version"] == 0
        assert dry_run["target_version"] == 4
        assert dry_run["result_version"] == 0
        assert dry_run["pending_migrations"] == [
            {"version": 1, "name": "baseline_v0.7.0"},
            {"version": 2, "name": "query_indexes_v0.9.0"},
            {"version": 3, "name": "collector_identity_v0.9.0"},
            {"version": 4, "name": "collector_buffer_diagnostics_v0.9.0"},
        ]
        assert dry_run["backup"] is None and not backup.exists()
        assert inspect_database(database) == 0

        migrated = migrate_database(database, backup_path=backup)
        assert migrated["source_version"] == 0
        assert migrated["target_version"] == migrated["result_version"] == 4
        assert migrated["backup"] == str(backup)
        assert migrated["integrity"] == "ok" and backup.is_file()
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT value FROM legacy_marker").fetchone()[0] == "preserved"
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        with sqlite3.connect(backup) as connection:
            assert connection.execute("SELECT value FROM legacy_marker").fetchone()[0] == "preserved"
            assert connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'schema_migrations'"
            ).fetchone()[0] == 0

        no_op = migrate_database(database)
        assert no_op["source_version"] == no_op["target_version"] == 4
        assert no_op["pending_migrations"] == [] and no_op["backup"] is None

        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE schema_migrations SET checksum = ?", ("0" * 64,))
        try:
            inspect_database(database)
            raise AssertionError("Changed migration history must be rejected")
        except ValueError:
            pass


if __name__ == "__main__":
    test_db_migrations()
    print("M24.2 versioned database migration runner passed")
