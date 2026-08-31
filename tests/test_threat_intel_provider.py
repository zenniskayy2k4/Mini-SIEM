import json
import threading
import time

from src.threat_intel import (
    ThreatIntelProvider,
    ThreatIntelProviderError,
    ThreatIntelService,
    normalize_ioc,
)


class DummyProvider(ThreatIntelProvider):
    name = "dummy"

    def __init__(self, *, fail_once=False, delay=0, gate=None):
        self.calls = []
        self.fail_once = fail_once
        self.delay = delay
        self.gate = gate
        self.started = threading.Event()

    def lookup(self, ioc_type, ioc, timeout_seconds):
        self.calls.append((ioc_type, ioc, timeout_seconds, time.monotonic()))
        self.started.set()
        if self.fail_once:
            self.fail_once = False
            raise ThreatIntelProviderError("temporary", "Temporary provider failure", retryable=True)
        if self.gate:
            self.gate.wait()
        if self.delay:
            time.sleep(self.delay)
        return {"verdict": "unknown", "confidence": 0}


class SecretFailureProvider(ThreatIntelProvider):
    name = "secret-failure"
    private_marker = "provider-private-marker"

    def lookup(self, ioc_type, ioc, timeout_seconds):
        raise RuntimeError(self.private_marker)


def test_threat_intel_provider():
    assert normalize_ioc("ip", " 2001:0DB8::1 ") == ("ip", "2001:db8::1")
    assert normalize_ioc("domain", "Exämple.COM.") == ("domain", "xn--exmple-cua.com")
    assert normalize_ioc("url", "HTTPS://Example.COM:443/a?q=1#x") == (
        "url", "https://example.com/a?q=1",
    )
    assert normalize_ioc("md5", "A" * 32) == ("md5", "a" * 32)
    assert normalize_ioc("sha256", "B" * 64) == ("sha256", "b" * 64)
    for kind, value in (("ip", "999.1.1.1"), ("url", "file:///tmp/x"), ("sha1", "a" * 40)):
        try:
            normalize_ioc(kind, value)
            raise AssertionError((kind, value))
        except ValueError:
            pass

    provider = DummyProvider()
    service = ThreatIntelService(provider, cache_ttl_seconds=60, rate_limit_per_second=1000)
    first = service.lookup("domain", "EXAMPLE.com")
    cached = service.lookup("domain", "example.com.")
    assert first.status == "ok" and cached.cached is True
    assert len(provider.calls) == 1
    assert first.provider == "dummy" and first.checked_at.endswith("Z")
    assert first.attempts == 1 and first.as_dict()["ioc"] == "example.com"
    service.close()

    secret_service = ThreatIntelService(SecretFailureProvider(), rate_limit_per_second=1000)
    secret_error = secret_service.lookup("domain", "example.com")
    assert secret_error.status == "error"
    assert "provider-private-marker" not in json.dumps(secret_error.as_dict())
    secret_service.close()

    retry_provider = DummyProvider(fail_once=True)
    retry_service = ThreatIntelService(retry_provider, rate_limit_per_second=1000, max_attempts=2)
    retried = retry_service.lookup("ip", "192.0.2.10")
    assert retried.status == "ok" and retried.attempts == 2
    retry_service.close()

    slow_provider = DummyProvider(delay=0.1)
    slow_service = ThreatIntelService(
        slow_provider, rate_limit_per_second=1000, timeout_seconds=0.01, max_attempts=1,
    )
    timed_out = slow_service.lookup("ip", "198.51.100.20")
    assert timed_out.status == "timeout"
    assert timed_out.error == {
        "code": "timeout", "message": "Provider lookup timed out", "retryable": True,
    }
    slow_service.close()

    gate = threading.Event()
    async_provider = DummyProvider(gate=gate)
    async_service = ThreatIntelService(async_provider, rate_limit_per_second=1000)
    future = async_service.lookup_async("md5", "c" * 32)
    assert async_provider.started.wait(0.5) and not future.done()
    busy = async_service.lookup_async("md5", "d" * 32).result(timeout=0.1)
    assert busy.status == "error" and busy.error["code"] == "busy" and busy.attempts == 0
    assert len(async_provider.calls) == 1
    persisted_alerts = [{"alert_id": "ALT-persisted-before-ti"}]
    gate.set()
    assert persisted_alerts and future.result(timeout=1).status == "ok"
    async_service.close()

    limited_provider = DummyProvider()
    limited_service = ThreatIntelService(limited_provider, rate_limit_per_second=20)
    limited_service.lookup("ip", "203.0.113.1")
    limited_service.lookup("ip", "203.0.113.2")
    assert limited_provider.calls[1][3] - limited_provider.calls[0][3] >= 0.04
    limited_service.close()


if __name__ == "__main__":
    test_threat_intel_provider()
    print("M12.1 threat intelligence provider abstraction passed")
