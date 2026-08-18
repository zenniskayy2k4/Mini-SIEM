import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from config import config
from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert
from src.assets import build_asset
from src.sqlite_store import SQLiteAssetRepository


class FailingAssetRepository:
    def find_by_hostname(self, _hostname):
        raise RuntimeError("asset store unavailable")


def _alert(**values):
    defaults = {
        "alert_name": "Asset enrichment fixture",
        "severity": "HIGH",
        "source_type": "HIDS_LOG",
        "description": "Deterministic asset lookup",
    }
    return build_alert(**(defaults | values))


def test_asset_enrichment():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repository = SQLiteAssetRepository(str(root / "assets.db"))
        with patch.object(config, "ANALYST_AUDIT_FILE", str(root / "audit.jsonl")):
            ip_asset = repository.create_asset(build_asset(
                "edge-01.example.test", ip_addresses=["192.0.2.10"],
            ))
            host_asset = repository.create_asset(build_asset(
                "win-01.example.test", ip_addresses=["192.0.2.20"],
            ))
            repository.create_asset(build_asset(
                "disabled.example.test", ip_addresses=["192.0.2.30"], enabled=False,
            ))

        notifier = Mock()
        with (
            patch("src.alert_pipeline.upsert_alert") as upsert,
            patch("src.alert_pipeline.notification_service", notifier),
        ):
            by_ip = persist_and_enrich(
                _alert(ip_address="192.0.2.10"),
                stix_store=None,
                asset_repository=repository,
            )
            assert by_ip["asset_id"] == ip_asset["asset_id"]

            hostname_wins = persist_and_enrich(
                _alert(
                    source_type="WINDOWS_EVENT",
                    computer="WIN-01.EXAMPLE.TEST",
                    ip_address="192.0.2.10",
                ),
                stix_store=None,
                asset_repository=repository,
            )
            assert hostname_wins["asset_id"] == host_asset["asset_id"]

            for alert in (
                _alert(ip_address="not-an-ip"),
                _alert(ip_address="192.0.2.30"),
                _alert(hostname="missing.example.test"),
            ):
                persist_and_enrich(alert, stix_store=None, asset_repository=repository)
                assert alert["asset_id"] is None

            store_failure = _alert(hostname="edge-01.example.test")
            persist_and_enrich(
                store_failure,
                stix_store=None,
                asset_repository=FailingAssetRepository(),
            )
            assert store_failure["asset_id"] is None

        assert upsert.call_count == 6
        assert notifier.notify.call_count == 6
        assert all("asset" not in alert and "asset_context" not in alert for alert in (
            by_ip, hostname_wins, store_failure,
        ))

    dashboard_template = Path("templates/dashboard.html").read_text(encoding="utf-8")
    dashboard_script = Path("static/js/app.js").read_text(encoding="utf-8")
    assert "<th>Asset</th>" in dashboard_template
    assert 'href="/assets?q=${encodeURIComponent(assetId)}"' in dashboard_script


if __name__ == "__main__":
    test_asset_enrichment()
    print("M13.3 alert-to-asset enrichment passed")
