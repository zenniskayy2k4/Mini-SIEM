import ipaddress
import re
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import replace
from urllib.parse import urlsplit, urlunsplit

from src.alert_schema import utc_iso
from src.threat_intel.base import (
    ThreatIntelProvider,
    ThreatIntelProviderError,
    ThreatIntelResult,
)


IOC_TYPES = frozenset({"ip", "domain", "url", "sha256", "md5"})
_HEX = re.compile(r"^[0-9a-f]+$")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _domain(value: str) -> str:
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("IOC domain is invalid") from exc
    labels = domain.split(".")
    if not domain or len(domain) > 253 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("IOC domain is invalid")
    return domain


def normalize_ioc(ioc_type: str, value: str) -> tuple[str, str]:
    kind = str(ioc_type or "").strip().lower()
    raw = str(value or "").strip()
    if kind not in IOC_TYPES:
        raise ValueError(f"Unsupported IOC type: {kind or 'empty'}")
    if not raw:
        raise ValueError("IOC value must not be empty")
    if kind == "ip":
        try:
            return kind, str(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise ValueError("IOC IP is invalid") from exc
    if kind == "domain":
        return kind, _domain(raw)
    if kind in {"sha256", "md5"}:
        digest = raw.lower()
        expected = 64 if kind == "sha256" else 32
        if len(digest) != expected or not _HEX.fullmatch(digest):
            raise ValueError(f"IOC {kind} is invalid")
        return kind, digest

    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("IOC URL must use http or https and include a host")
    if parsed.username or parsed.password:
        raise ValueError("IOC URL must not contain credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("IOC URL port is invalid") from exc
    try:
        host = str(ipaddress.ip_address(parsed.hostname))
        host = f"[{host}]" if ":" in host else host
    except ValueError:
        host = _domain(parsed.hostname)
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    netloc = host if port is None or default_port else f"{host}:{port}"
    return kind, urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


class ThreatIntelService:
    def __init__(
        self,
        provider: ThreatIntelProvider,
        *,
        cache_ttl_seconds: float = 300,
        rate_limit_per_second: float = 5,
        timeout_seconds: float = 3,
        max_attempts: int = 2,
    ):
        if not isinstance(provider, ThreatIntelProvider):
            raise TypeError("provider must implement ThreatIntelProvider")
        if not isinstance(provider.name, str) or not provider.name.strip():
            raise ValueError("provider name must not be empty")
        if cache_ttl_seconds <= 0 or rate_limit_per_second <= 0 or timeout_seconds <= 0:
            raise ValueError("cache TTL, rate limit and timeout must be positive")
        if not isinstance(max_attempts, int) or not 1 <= max_attempts <= 3:
            raise ValueError("max_attempts must be between 1 and 3")
        self.provider = provider
        self.cache_ttl_seconds = float(cache_ttl_seconds)
        self.timeout_seconds = float(timeout_seconds)
        self.max_attempts = max_attempts
        self._interval = 1.0 / float(rate_limit_per_second)
        self._cache = {}
        self._cache_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._next_request = 0.0
        # ponytail: one provider worker bounds calls; split pools only when multiple providers need concurrency.
        self._provider_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ti-provider")
        self._control_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ti-control")

    def _cached(self, key) -> ThreatIntelResult | None:
        with self._cache_lock:
            item = self._cache.get(key)
            if not item:
                return None
            expires_at, result = item
            if expires_at <= time.monotonic():
                self._cache.pop(key, None)
                return None
            return replace(result, cached=True, duration_ms=0)

    def _limit_rate(self) -> None:
        with self._rate_lock:
            wait = self._next_request - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._next_request = time.monotonic() + self._interval

    def lookup(self, ioc_type: str, ioc: str) -> ThreatIntelResult:
        kind, normalized = normalize_ioc(ioc_type, ioc)
        key = (self.provider.name, kind, normalized)
        cached = self._cached(key)
        if cached:
            return cached

        started = time.monotonic()
        error = None
        attempts = 0
        for attempts in range(1, self.max_attempts + 1):
            self._limit_rate()
            future = self._provider_pool.submit(
                self.provider.lookup, kind, normalized, self.timeout_seconds,
            )
            try:
                data = future.result(timeout=self.timeout_seconds)
                if data is not None and not isinstance(data, dict):
                    raise ThreatIntelProviderError(
                        "invalid_response", "Provider returned an invalid response",
                    )
                result = ThreatIntelResult(
                    ioc_type=kind,
                    ioc=normalized,
                    provider=self.provider.name,
                    status="not_found" if data is None else "ok",
                    checked_at=utc_iso(),
                    data=data or {},
                    attempts=attempts,
                    duration_ms=round((time.monotonic() - started) * 1000),
                )
                with self._cache_lock:
                    self._cache[key] = (time.monotonic() + self.cache_ttl_seconds, result)
                return result
            except FutureTimeout:
                future.cancel()
                error = {"code": "timeout", "message": "Provider lookup timed out", "retryable": True}
            except ThreatIntelProviderError as exc:
                error = {
                    "code": exc.code,
                    "message": exc.safe_message,
                    "retryable": exc.retryable,
                }
                if not exc.retryable:
                    break
            except OSError:
                error = {"code": "network_error", "message": "Provider network error", "retryable": True}
            except Exception:
                error = {"code": "provider_error", "message": "Provider lookup failed", "retryable": False}
                break

        return ThreatIntelResult(
            ioc_type=kind,
            ioc=normalized,
            provider=self.provider.name,
            status="timeout" if error and error["code"] == "timeout" else "error",
            checked_at=utc_iso(),
            error=error,
            attempts=attempts,
            duration_ms=round((time.monotonic() - started) * 1000),
        )

    def lookup_async(self, ioc_type: str, ioc: str) -> Future:
        """Submit a lookup without blocking alert persistence or the caller."""
        return self._control_pool.submit(self.lookup, ioc_type, ioc)

    def close(self) -> None:
        self._control_pool.shutdown(wait=False, cancel_futures=True)
        self._provider_pool.shutdown(wait=False, cancel_futures=True)
