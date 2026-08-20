import json
from concurrent.futures import Future
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import Mock, patch

from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert, utc_iso
from src.threat_intel import (
    VIRUSTOTAL_FIELDS,
    ThreatIntelProviderError,
    ThreatIntelResult,
    ThreatIntelService,
    VirusTotalProvider,
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


class ImmediateVirusTotalService:
    def __init__(self):
        self.calls = []

    def lookup_async(self, ioc_type, ioc):
        self.calls.append((ioc_type, ioc))
        future = Future()
        future.set_result(ThreatIntelResult(
            ioc_type=ioc_type,
            ioc=ioc,
            provider="virustotal",
            status="ok",
            checked_at=utc_iso(),
            data={
                "malicious": 4,
                "suspicious": 1,
                "harmless": 60,
                "undetected": 5,
                "reputation": -2,
                "last_analysis_at": "2026-08-18T00:00:00Z",
            },
        ))
        return future


def test_virustotal_provider():
    try:
        VirusTotalProvider("")
        raise AssertionError("missing API key must disable provider construction")
    except ValueError:
        pass

    calls = []

    def opener(request, timeout):
        calls.append(request)
        return FakeResponse({"data": {"attributes": {
            "last_analysis_stats": {
                "malicious": 7,
                "suspicious": 2,
                "harmless": 55,
                "undetected": 6,
            },
            "last_analysis_date": 1787011200,
            "reputation": -5,
            "last_analysis_results": {"engine": {"result": "raw-engine-detail"}},
        }}})

    api_key = "fixture"
    provider = VirusTotalProvider(api_key, opener=opener)
    for unsupported in ("ip", "domain", "url"):
        try:
            provider.lookup(unsupported, "example", 1)
            raise AssertionError(unsupported)
        except ThreatIntelProviderError as exc:
            assert getattr(exc, "code", None) == "unsupported_ioc"

    digest = "a" * 64
    service = ThreatIntelService(
        provider, cache_ttl_seconds=60, rate_limit_per_second=1000,
    )
    first = service.lookup("sha256", digest.upper())
    cached = service.lookup("sha256", digest)
    assert first.status == "ok" and cached.cached is True
    assert list(first.data) == list(VIRUSTOTAL_FIELDS)
    assert first.data["malicious"] == 7 and first.data["suspicious"] == 2
    assert len(calls) == 1 and calls[0].get_method() == "GET"
    assert calls[0].data is None and calls[0].full_url.endswith(f"/files/{digest}")
    assert calls[0].get_header("X-apikey") == api_key
    assert api_key not in calls[0].full_url and api_key not in json.dumps(first.as_dict())
    assert "raw-engine-detail" not in json.dumps(first.as_dict())
    service.close()

    missing_calls = []

    def not_found(request, timeout):
        missing_calls.append(request)
        raise HTTPError(request.full_url, 404, "Not Found", {}, None)

    missing_service = ThreatIntelService(
        VirusTotalProvider(api_key, opener=not_found),
        cache_ttl_seconds=60,
        rate_limit_per_second=1000,
    )
    missing = missing_service.lookup("md5", "c" * 32)
    missing_cached = missing_service.lookup("md5", "c" * 32)
    assert missing.status == "not_found" and missing_cached.cached is True
    assert len(missing_calls) == 1
    missing_service.close()

    def rate_limited(request, timeout):
        raise HTTPError(request.full_url, 429, "Too Many Requests", {}, None)

    limited_service = ThreatIntelService(
        VirusTotalProvider(api_key, opener=rate_limited),
        rate_limit_per_second=1000,
        max_attempts=2,
    )
    limited = limited_service.lookup("md5", "b" * 32)
    assert limited.status == "error" and limited.attempts == 1
    assert limited.error["code"] == "rate_limited" and limited.error["retryable"] is False
    limited_service.close()

    alert = build_alert(
        alert_name="Suspicious process",
        severity="HIGH",
        source_type="WINDOWS_EVENT",
        description="Hash metadata lookup",
        hashes={"MD5": "b" * 32, "SHA256": digest},
    )
    vt_service = ImmediateVirusTotalService()
    notifier = Mock()
    with (
        patch("src.alert_pipeline.upsert_alert") as upsert,
        patch("src.alert_pipeline.notification_service", notifier),
    ):
        persist_and_enrich(alert, virustotal_service=vt_service)
    assert vt_service.calls == [("sha256", digest)]
    assert upsert.call_count == 2 and notifier.notify.call_count == 1
    assert alert["threat_intel"]["virustotal"]["malicious"] == 4
    assert alert["severity"] == "HIGH"

    provider_source = Path("src/threat_intel/virustotal.py").read_text(encoding="utf-8").lower()
    assert "upload" not in provider_source and "download" not in provider_source


if __name__ == "__main__":
    test_virustotal_provider()
    print("M12.4 VirusTotal metadata provider passed")
