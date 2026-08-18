import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from config import config
from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert
from src.threat_intel import STIXIndicatorStore, pull_taxii, pull_taxii_safe
from tools import import_stix


FIXTURE = Path("tests/fixtures/stix/sample_bundle.json")


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, limit):
        return self.payload[:limit]


def test_stix_taxii():
    bundle = json.loads(FIXTURE.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        store_path = directory / "indicators.json"
        store = STIXIndicatorStore(store_path)
        stats = store.import_bundle(bundle, "lab-feed")
        assert stats == {"imported": 3, "deduplicated": 1, "expired": 1, "skipped": 1}
        assert store.match("ip", "198.51.100.44")[0]["source"] == "lab-feed"
        assert store.match("domain", "EVIL.EXAMPLE")[0]["confidence"] == 70
        assert store.match("ip", "203.0.113.55") == []
        persisted = store_path.read_text(encoding="utf-8")
        assert "pattern" not in persisted and "lab-feed" in persisted
        assert len(STIXIndicatorStore(store_path).match("sha256", "c" * 64)) == 1

        alert = build_alert(
            alert_name="STIX match",
            severity="HIGH",
            source_type="WINDOWS_EVENT",
            description="Normalized IOC evidence",
            ip_address="198.51.100.44",
            hashes={"SHA256": "c" * 64},
        )
        with (
            patch("src.alert_pipeline.upsert_alert") as upsert,
            patch("src.alert_pipeline.notification_service"),
        ):
            persist_and_enrich(alert, stix_store=store)
        stix = alert["threat_intel"]["stix"]
        assert stix["status"] == "ok" and stix["sources"] == ["lab-feed"]
        assert stix["match_count"] == 2 and stix["confidence"] == 95
        assert alert["severity"] == "HIGH" and upsert.call_count == 1

        requests = []

        def opener(request, timeout):
            requests.append((request, timeout))
            return FakeResponse({"objects": [bundle["objects"][2]], "more": False})

        taxii_store = STIXIndicatorStore(directory / "taxii.json")
        taxii_stats = pull_taxii(
            taxii_store,
            "https://taxii.example/collections/lab/objects/",
            "taxii-feed",
            "secret-token",
            opener=opener,
        )
        assert taxii_stats["imported"] == 1
        assert requests[0][0].get_header("Authorization") == "Bearer secret-token"
        assert taxii_store.match("domain", "evil.example")[0]["source"] == "taxii-feed"

        failed = pull_taxii_safe(
            taxii_store,
            "https://taxii.example/collections/lab/objects/",
            opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
        )
        assert failed == {"status": "error", "error": "TAXII feed unavailable"}
        assert taxii_store.match("domain", "evil.example")

        manual_path = directory / "manual.json"
        with (
            patch.object(config, "STIX_INDICATOR_FILE", str(manual_path)),
            patch.object(sys, "argv", ["import_stix", str(FIXTURE), "--source", "manual-feed"]),
        ):
            import_stix.main()
        assert STIXIndicatorStore(manual_path).match("ip", "198.51.100.44")[0]["source"] == "manual-feed"

    script = Path("static/js/app.js").read_text(encoding="utf-8")
    assert '"virustotal", "stix"' in script
    assert 'stix: "STIX/TAXII"' in script and "entry.sources" in script
    agent = Path("main.py").read_text(encoding="utf-8")
    assert "pull_taxii_safe" in agent and "TAXII_PULL_INTERVAL_SECONDS" in agent


if __name__ == "__main__":
    test_stix_taxii()
    print("M12.6 STIX/TAXII ingestion passed")
