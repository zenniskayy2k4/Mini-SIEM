import json
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from config import config
from src.assets import build_asset
from src.audit import verify_audit_log
from src.sqlite_store import SQLiteAssetRepository


def _reject(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError("Expected ValueError")


def test_asset_inventory():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        database = root / "assets.db"
        audit_file = root / "audit.jsonl"
        repository = SQLiteAssetRepository(str(database))

        with patch.object(config, "ANALYST_AUDIT_FILE", str(audit_file)):
            asset = build_asset(
                "web-01.example.test",
                ip_addresses=["192.0.2.10", "2001:0db8::1"],
                os="Ubuntu 24.04",
                owner="Platform Team",
                department="Engineering",
                environment="PROD",
                criticality="critical",
                tags=["internet-facing", "linux", "linux"],
            )
            created = repository.create_asset(asset, actor="asset-admin", role="admin")
            assert created["asset_id"].startswith("AST-")
            assert created["environment"] == "prod"
            assert created["criticality"] == "CRITICAL"
            assert created["ip_addresses"] == ["192.0.2.10", "2001:db8::1"]
            assert created["tags"] == ["internet-facing", "linux"]
            assert repository.find_by_hostname("WEB-01.EXAMPLE.TEST") == created
            assert repository.find_by_ip("2001:0DB8:0:0::1") == created
            assert repository.list_assets(enabled=True) == [created]
            assert repository.list_assets(enabled=False) == []

            _reject(lambda: repository.create_asset(build_asset(
                "WEB-01.EXAMPLE.TEST", ip_addresses=["192.0.2.20"],
            )))
            _reject(lambda: repository.create_asset(build_asset(
                "db-01.example.test", ip_addresses=["192.0.2.10"],
            )))

            updated = repository.update_asset(
                created["asset_id"],
                {
                    "hostname": "web-02.example.test",
                    "ip_addresses": ["192.0.2.11"],
                    "criticality": "HIGH",
                    "enabled": False,
                },
                actor="asset-admin",
                role="admin",
            )
            assert updated["asset_id"] == created["asset_id"]
            assert updated["created_at"] == created["created_at"]
            assert updated["criticality"] == "HIGH" and updated["enabled"] is False
            assert repository.find_by_hostname("web-01.example.test") is None
            assert repository.find_by_ip("192.0.2.10") is None
            assert repository.update_asset(updated["asset_id"], {}, actor="asset-admin") == updated

            second = repository.create_asset(
                build_asset("db-01.example.test", ip_addresses=["192.0.2.10"]),
                actor="asset-admin",
                role="admin",
            )
            _reject(lambda: repository.update_asset(
                second["asset_id"], {"ip_addresses": ["192.0.2.11"]},
            ))
            assert repository.find_by_ip("192.0.2.10")["asset_id"] == second["asset_id"]
            _reject(lambda: repository.update_asset(
                second["asset_id"], {"asset_id": updated["asset_id"]},
            ))
            _reject(lambda: repository.update_asset(second["asset_id"], {"extra": True}))

            assert repository.delete_asset(updated["asset_id"], actor="asset-admin", role="admin")
            assert not repository.delete_asset(updated["asset_id"], actor="asset-admin")
            assert repository.get_asset(updated["asset_id"]) is None

            for invalid in (
                lambda: build_asset(""),
                lambda: build_asset("bad-env", environment="stage"),
                lambda: build_asset("bad-criticality", criticality="urgent"),
                lambda: build_asset("bad-ip", ip_addresses=["999.1.1.1"]),
                lambda: build_asset("bad-tags", tags="server"),
                lambda: build_asset("bad-enabled", enabled=1),
            ):
                _reject(invalid)
            _reject(lambda: repository.find_by_ip("not-an-ip"))
            _reject(lambda: repository.list_assets(enabled="yes"))

            events = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").splitlines()]
            assert [event["event_type"] for event in events] == [
                "ASSET_CREATED", "ASSET_UPDATED", "ASSET_CREATED", "ASSET_DELETED",
            ]
            assert all(event["target_type"] == "asset" for event in events)
            assert verify_audit_log()[0] is True

        with sqlite3.connect(database) as connection:
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'",
                )
            }
        assert {"assets", "asset_ip_addresses"} <= tables


if __name__ == "__main__":
    test_asset_inventory()
    print("M13.1 asset inventory data model passed")
