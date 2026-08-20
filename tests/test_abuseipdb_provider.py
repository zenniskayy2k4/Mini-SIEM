import json
from concurrent.futures import Future
from urllib.error import HTTPError
from unittest.mock import Mock, patch

from src.ai_analyst import AIAnalyst
from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert, utc_iso
from src.threat_intel import (
    ABUSEIPDB_FIELDS,
    AbuseIPDBProvider,
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


class ImmediateAbuseIPDBService:
    def lookup_async(self, ioc_type, ioc):
        future = Future()
        future.set_result(ThreatIntelResult(
            ioc_type=ioc_type,
            ioc=ioc,
            provider="abuseipdb",
            status="ok",
            checked_at=utc_iso(),
            data={
                "abuse_confidence": 85,
                "total_reports": 12,
                "last_reported_at": "2026-08-17T12:00:00Z",
                "isp": "Example ISP",
                "domain": "example.test",
                "usage_type": "Data Center/Web Hosting/Transit",
            },
        ))
        return future


class CapturingAnalyst:
    def __init__(self):
        self.seen = None

    def enrich_async(self, alert, on_complete):
        self.seen = json.loads(json.dumps(alert.get("threat_intel")))


def test_abuseipdb_provider():
    try:
        AbuseIPDBProvider("")
        raise AssertionError("missing API key must disable provider construction")
    except ValueError:
        pass

    calls = []

    def opener(request, timeout):
        calls.append(request)
        return FakeResponse({"data": {
            "abuseConfidenceScore": 73,
            "totalReports": 19,
            "lastReportedAt": "2026-08-17T10:00:00+00:00",
            "isp": "Example ISP",
            "domain": "example.net",
            "usageType": "Data Center/Web Hosting/Transit",
            "reports": [{"comment": "raw-provider-secret"}],
        }})

    api_key = "fixture"
    provider = AbuseIPDBProvider(api_key, opener=opener)
    for local_ip in ("10.0.0.8", "127.0.0.1", "169.254.10.20", "::1", "fe80::1"):
        assert provider.lookup("ip", local_ip, 1) is None
    assert calls == []

    service = ThreatIntelService(
        provider, cache_ttl_seconds=60, rate_limit_per_second=1000,
    )
    first = service.lookup("ip", "8.8.8.8")
    cached = service.lookup("ip", "8.8.8.8")
    assert first.status == "ok" and cached.cached is True
    assert list(first.data) == list(ABUSEIPDB_FIELDS)
    assert first.data["abuse_confidence"] == 73
    assert first.data["total_reports"] == 19
    assert len(calls) == 1
    assert calls[0].get_method() == "GET"
    assert calls[0].get_header("Key") == api_key
    assert "ipAddress=8.8.8.8" in calls[0].full_url
    assert "raw-provider-secret" not in json.dumps(first.as_dict())
    assert api_key not in json.dumps(first.as_dict()) and api_key not in calls[0].full_url
    service.close()

    rate_calls = []

    def rate_limited(request, timeout):
        rate_calls.append(request)
        raise HTTPError(request.full_url, 429, "Too Many Requests", {}, None)

    limited_service = ThreatIntelService(
        AbuseIPDBProvider(api_key, opener=rate_limited),
        rate_limit_per_second=1000,
        max_attempts=2,
    )
    limited = limited_service.lookup("ip", "1.1.1.1")
    assert limited.status == "error" and limited.attempts == 1
    assert limited.error == {
        "code": "rate_limited",
        "message": "AbuseIPDB rate limit exceeded",
        "retryable": False,
    }
    assert len(rate_calls) == 1
    limited_service.close()

    alert = build_alert(
        alert_name="Public source",
        severity="HIGH",
        source_type="NIDS",
        description="AbuseIPDB context",
        raw_log="raw-log-must-not-go-to-abuseipdb",
        ip_address="8.8.8.8",
    )
    analyst = CapturingAnalyst()
    notifier = Mock()
    with (
        patch("src.alert_pipeline.upsert_alert") as upsert,
        patch("src.alert_pipeline.notification_service", notifier),
    ):
        persist_and_enrich(
            alert, ai_analyst=analyst,
            abuseipdb_service=ImmediateAbuseIPDBService(),
        )
    assert upsert.call_count == 2 and notifier.notify.call_count == 1
    assert analyst.seen["abuseipdb"]["abuse_confidence"] == 85
    assert alert["severity"] == "HIGH"

    alert["threat_intel"]["abuseipdb"]["raw_provider_response"] = "do-not-send"
    ai_summary = AIAnalyst._threat_intel_summary(alert)
    assert "do-not-send" not in ai_summary
    assert json.loads(ai_summary)["abuse_confidence"] == 85


if __name__ == "__main__":
    test_abuseipdb_provider()
    print("M12.3 AbuseIPDB provider passed")
