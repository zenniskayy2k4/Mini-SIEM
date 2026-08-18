import json
from concurrent.futures import Future
from pathlib import Path
from unittest.mock import Mock, patch

from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert, utc_iso
from src.threat_intel import (
    GEOIP_FIELDS,
    GeoIPProvider,
    ThreatIntelResult,
    ThreatIntelService,
)


class FakeResponse:
    def __init__(self, payload):
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit):
        return self.body[:limit]


class ImmediateGeoIPService:
    def lookup_async(self, ioc_type, ioc):
        future = Future()
        future.set_result(ThreatIntelResult(
            ioc_type=ioc_type,
            ioc=ioc,
            provider="fixture-geoip",
            status="ok",
            checked_at=utc_iso(),
            data={
                "country": "Example Country",
                "country_code": "EC",
                "city": "Example City",
                "asn": 64500,
                "organization": "Example Network",
                "is_private": False,
            },
        ))
        return future


def test_geoip_enrichment():
    calls = []

    def opener(request, timeout):
        calls.append((request.full_url, timeout))
        return FakeResponse({
            "success": True,
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "connection": {"asn": 15169, "org": "Google LLC"},
        })

    provider = GeoIPProvider(opener=opener)
    expected_empty = {
        "country": None,
        "country_code": None,
        "city": None,
        "asn": None,
        "organization": None,
        "is_private": True,
    }
    for local_ip in ("10.0.0.8", "127.0.0.1", "169.254.10.20", "::1", "fe80::1"):
        assert provider.lookup("ip", local_ip, 1) == expected_empty
    assert calls == []

    service = ThreatIntelService(
        provider, cache_ttl_seconds=60, rate_limit_per_second=1000,
    )
    first = service.lookup("ip", "8.8.8.8")
    cached = service.lookup("ip", "8.8.8.8")
    assert first.status == "ok" and cached.cached is True
    assert list(first.data) == list(GEOIP_FIELDS)
    assert first.data == {
        "country": "United States",
        "country_code": "US",
        "city": "Mountain View",
        "asn": 15169,
        "organization": "Google LLC",
        "is_private": False,
    }
    assert calls == [("https://ipwho.is/8.8.8.8", 3.0)]
    service.close()

    alert = build_alert(
        alert_name="Public source",
        severity="HIGH",
        source_type="NIDS",
        description="GeoIP context only",
        ip_address="8.8.8.8",
    )
    notifier = Mock()
    with (
        patch("src.alert_pipeline.upsert_alert") as upsert,
        patch("src.alert_pipeline.notification_service", notifier),
    ):
        persist_and_enrich(alert, geoip_service=ImmediateGeoIPService())
    assert upsert.call_count == 2
    assert notifier.notify.call_count == 1
    assert alert["geoip"]["country_code"] == "EC"
    assert alert["geoip_lookup"]["provider"] == "fixture-geoip"
    assert alert["severity"] == "HIGH"

    dashboard_script = Path("static/js/app.js").read_text(encoding="utf-8")
    assert "function renderGeoIP(alert)" in dashboard_script
    assert "Private/local address" in dashboard_script


if __name__ == "__main__":
    test_geoip_enrichment()
    print("M12.2 GeoIP enrichment passed")
