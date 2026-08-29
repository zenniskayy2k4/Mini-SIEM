import json
import re
import sqlite3
import tempfile
from pathlib import Path

from tools.migrate_db import inspect_database, migrate_database


V06_SCHEMA = """
CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    alert_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_type TEXT NOT NULL,
    incident_id TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL UNIQUE REFERENCES alerts(alert_id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    assigned_to TEXT,
    created_at TEXT,
    updated_at TEXT
);
CREATE TABLE assets (
    asset_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL COLLATE NOCASE UNIQUE,
    os TEXT NOT NULL,
    owner TEXT NOT NULL,
    department TEXT NOT NULL,
    environment TEXT NOT NULL CHECK(environment IN ('dev', 'test', 'prod')),
    criticality TEXT NOT NULL CHECK(criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    tags_json TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE asset_ip_addresses (
    asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL UNIQUE,
    PRIMARY KEY (asset_id, ip_address)
);
"""

V07_ADDITIONS = """
CREATE TABLE detection_feedback (
    feedback_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE ingestion_health (
    source_type TEXT PRIMARY KEY,
    events_received INTEGER NOT NULL DEFAULT 0,
    events_normalized INTEGER NOT NULL DEFAULT 0,
    events_rejected INTEGER NOT NULL DEFAULT 0,
    events_deduplicated INTEGER NOT NULL DEFAULT 0,
    processing_seconds REAL NOT NULL DEFAULT 0,
    collector_last_seen_at TEXT
);
"""

V08_ADDITIONS = """
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK(version > 0),
    name TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL,
    checksum TEXT NOT NULL CHECK(length(checksum) = 64)
);
INSERT INTO schema_migrations VALUES (
    1,
    'baseline_v0.7.0',
    '2026-08-29T00:00:00Z',
    '3c2b9bbd28b2ae786760134a1eaa14a607ecfc1e92f4a3e33849091998f99b88'
);
"""

HISTORICAL_FIXTURES = {
    "v0.6.0": (V06_SCHEMA, 0),
    "v0.7.0": (V06_SCHEMA + V07_ADDITIONS, 0),
    "v0.8.0": (V06_SCHEMA + V07_ADDITIONS + V08_ADDITIONS, 1),
}


def _released_versions():
    headings = re.findall(
        r"^## \[(\d+)\.(\d+)\.(\d+)\] - \d{4}-\d{2}-\d{2}$",
        Path("CHANGELOG.md").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    return tuple(
        f"v{major}.{minor}.{patch}"
        for major, minor, patch in sorted(
            (tuple(map(int, version)) for version in headings)
        )
        if (major, minor, patch) >= (0, 6, 0)
    )


def _seed(connection, release, schema):
    connection.executescript(schema)
    suffix = release.removeprefix("v").replace(".", "")
    alert_id, incident_id, asset_id = (
        f"ALT-{suffix}", f"INC-{suffix}", f"AST-{suffix}",
    )
    timestamp = "2026-08-29T00:00:00Z"
    payload = {
        "alert_id": alert_id,
        "incident_id": incident_id,
        "alert_name": f"Historical {release}",
        "severity": "HIGH",
        "source_type": "HIDS_LOG",
        "rule_id": "DET-HIST-001",
        "external_cases": {"fixture": {"external_id": f"CASE-{suffix}"}},
    }
    connection.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            alert_id, timestamp, payload["alert_name"], "HIGH", "HIDS_LOG",
            incident_id, json.dumps(payload, sort_keys=True), timestamp, timestamp,
        ),
    )
    connection.execute(
        "INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?)",
        (incident_id, alert_id, "INVESTIGATING", "tier-2", timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO assets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            asset_id, f"{suffix}.example.test", "Linux", "SOC", "Security",
            "prod", "HIGH", '["historical"]', 1, timestamp, timestamp,
        ),
    )
    connection.execute(
        "INSERT INTO asset_ip_addresses VALUES (?, ?)",
        (asset_id, f"192.0.2.{60 if release == 'v0.6.0' else 70}"),
    )
    if release != "v0.6.0":
        connection.execute(
            "INSERT INTO detection_feedback VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("FB-070", alert_id, "DET-HIST-001", "TRUE_POSITIVE", "verified", "analyst", timestamp),
        )
        connection.execute(
            "INSERT INTO ingestion_health VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("WINDOWS_EVENT", 5, 4, 1, 0, 0.5, timestamp),
        )
    return alert_id, incident_id, asset_id, f"CASE-{suffix}"


def _verify_upgraded(database, expected):
    alert_id, incident_id, asset_id, external_id = expected
    with sqlite3.connect(database) as connection:
        payload = json.loads(connection.execute(
            "SELECT payload_json FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()[0])
        assert payload["external_cases"]["fixture"]["external_id"] == external_id
        assert connection.execute(
            "SELECT status, assigned_to FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone() == ("INVESTIGATING", "tier-2")
        assert connection.execute(
            "SELECT hostname FROM assets WHERE asset_id = ?", (asset_id,)
        ).fetchone() is not None
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_historical_upgrades():
    assert tuple(HISTORICAL_FIXTURES) == _released_versions()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for release, (schema, source_version) in HISTORICAL_FIXTURES.items():
            database = root / f"{release}.db"
            backup = root / f"{release}.backup.db"
            with sqlite3.connect(database) as connection:
                expected = _seed(connection, release, schema)
            report = migrate_database(database, backup_path=backup)
            assert report["source_version"] == source_version
            assert report["result_version"] == report["target_version"]
            if report["pending_migrations"]:
                assert backup.is_file() and inspect_database(backup) == source_version
            else:
                assert report["backup"] is None and not backup.exists()
            assert inspect_database(database) == report["target_version"]
            _verify_upgraded(database, expected)
            with sqlite3.connect(database) as connection:
                if release != "v0.6.0":
                    assert connection.execute("SELECT COUNT(*) FROM detection_feedback").fetchone()[0] == 1
                    assert connection.execute("SELECT events_received FROM ingestion_health").fetchone()[0] == 5

        fresh = root / "fresh.db"
        fresh.touch()
        report = migrate_database(fresh, backup_path=root / "fresh.backup.db")
        assert report["source_version"] == 0
        assert report["result_version"] == report["target_version"]
        assert inspect_database(fresh) == report["target_version"]


if __name__ == "__main__":
    test_historical_upgrades()
    print("M24.4 historical database upgrade matrix passed")
