import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.sqlite_store import SQLiteAssetRepository
from tests.auth_helpers import login_as


def test_asset_management():
    original_users_file = config.DASHBOARD_USERS_FILE
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repository = SQLiteAssetRepository(str(root / "assets.db"))
        audit_file = root / "audit.jsonl"
        try:
            with (
                patch.object(config, "ANALYST_AUDIT_FILE", str(audit_file)),
                patch.object(dashboard, "asset_repository", repository),
            ):
                anonymous = dashboard.app.test_client()
                assert anonymous.get("/assets").status_code == 302
                assert anonymous.get("/api/assets").status_code == 401

                analyst = dashboard.app.test_client()
                login_as(analyst, directory, role="analyst", username="asset-analyst")
                assert analyst.get("/assets").status_code == 403
                assert analyst.get("/api/assets").status_code == 403
                assert analyst.post("/api/assets", json={"hostname": "denied"}).status_code == 403

                admin = dashboard.app.test_client()
                login_as(admin, directory, role="admin", username="asset-admin")
                page = admin.get("/assets")
                assert page.status_code == 200
                assert b'asset-table-body' in page.data and b'asset-dialog' in page.data
                assert b'href="/assets" class="active"' in page.data

                assert admin.post(
                    "/api/assets", json={"hostname": "csrf-denied"},
                    headers={"X-CSRF-Token": "bad"},
                ).status_code == 400
                assert admin.post("/api/assets", json=[]).status_code == 400
                assert admin.post("/api/assets", json={"owner": "missing hostname"}).status_code == 400
                assert admin.post(
                    "/api/assets", json={"hostname": "unknown", "extra": True},
                ).status_code == 400

                first_response = admin.post("/api/assets", json={
                    "hostname": "web-01.example.test",
                    "ip_addresses": ["192.0.2.10"],
                    "os": "Ubuntu",
                    "owner": "Platform",
                    "department": "Engineering",
                    "environment": "prod",
                    "criticality": "CRITICAL",
                    "tags": ["internet-facing", "linux"],
                    "enabled": True,
                })
                assert first_response.status_code == 201
                first = first_response.get_json()
                assert first["asset_id"].startswith("AST-")
                assert admin.get(f"/api/assets/{first['asset_id']}").get_json() == first
                assert analyst.get(f"/api/assets/{first['asset_id']}").status_code == 403
                assert analyst.patch(
                    f"/api/assets/{first['asset_id']}", json={"owner": "denied"},
                ).status_code == 403
                assert analyst.delete(f"/api/assets/{first['asset_id']}").status_code == 403

                duplicate = admin.post("/api/assets", json={
                    "hostname": "WEB-01.EXAMPLE.TEST", "ip_addresses": ["192.0.2.11"],
                })
                assert duplicate.status_code == 409
                second = admin.post("/api/assets", json={
                    "hostname": "db-01.example.test",
                    "ip_addresses": ["192.0.2.20"],
                    "owner": "Database Team",
                    "department": "Engineering",
                    "environment": "test",
                    "criticality": "HIGH",
                    "tags": ["database"],
                    "enabled": True,
                }).get_json()

                all_assets = admin.get("/api/assets").get_json()
                assert all_assets["total"] == 2
                assert admin.get("/api/assets?q=internet-facing").get_json()["assets"] == [first]
                assert admin.get("/api/assets?environment=test").get_json()["assets"] == [second]
                assert admin.get("/api/assets?criticality=HIGH").get_json()["assets"] == [second]
                assert admin.get("/api/assets?enabled=maybe").status_code == 400
                assert admin.get("/api/assets?environment=stage").status_code == 400
                assert admin.post("/api/assets", json={
                    "hostname": "too-many-tags", "tags": [str(index) for index in range(33)],
                }).status_code == 400

                assert admin.patch(f"/api/assets/{first['asset_id']}", json={}).status_code == 400
                update = admin.patch(f"/api/assets/{first['asset_id']}", json={
                    "owner": "SOC", "criticality": "HIGH", "enabled": False,
                })
                assert update.status_code == 200
                updated = update.get_json()
                assert updated["asset_id"] == first["asset_id"]
                assert updated["owner"] == "SOC" and updated["enabled"] is False
                assert admin.get("/api/assets?enabled=false").get_json()["assets"] == [updated]

                conflict = admin.patch(f"/api/assets/{second['asset_id']}", json={
                    "ip_addresses": ["192.0.2.10"],
                })
                assert conflict.status_code == 409
                assert admin.get("/api/assets/AST-00000000-0000-0000-0000-000000000000").status_code == 404
                assert admin.delete(f"/api/assets/{second['asset_id']}").status_code == 204
                assert admin.delete(f"/api/assets/{second['asset_id']}").status_code == 404

                events = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").splitlines()]
                assert [event["event_type"] for event in events] == [
                    "ASSET_CREATED", "ASSET_CREATED", "ASSET_UPDATED", "ASSET_DELETED",
                ]
                assert all(event["actor"] == "asset-admin" for event in events)

                script = Path("static/js/app.js").read_text(encoding="utf-8")
                assert 'path === "/assets"' in script
                assert '"X-CSRF-Token": CSRF_TOKEN' in script
        finally:
            config.DASHBOARD_USERS_FILE = original_users_file


if __name__ == "__main__":
    test_asset_management()
    print("M13.2 asset management API/UI passed")
