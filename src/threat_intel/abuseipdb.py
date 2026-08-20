import ipaddress
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from src.threat_intel.base import ThreatIntelProvider, ThreatIntelProviderError


ABUSEIPDB_FIELDS = (
    "abuse_confidence",
    "total_reports",
    "last_reported_at",
    "isp",
    "domain",
    "usage_type",
)
MAX_RESPONSE_BYTES = 64 * 1024


def _text(value, limit=200):
    value = str(value).strip() if value is not None else ""
    return value[:limit] or None


def _integer(value, maximum=None):
    try:
        value = max(0, int(value))
    except (TypeError, ValueError):
        return 0
    return min(value, maximum) if maximum is not None else value


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"

    def __init__(
        self, api_key: str, endpoint="https://api.abuseipdb.com/api/v2/check", opener=urlopen,
    ):
        self._api_key = str(api_key or "").strip()
        if not self._api_key:
            raise ValueError("AbuseIPDB API key must not be empty")
        self.endpoint = str(endpoint).strip()
        if not self.endpoint.startswith("https://"):
            raise ValueError("AbuseIPDB endpoint must use HTTPS")
        self._opener = opener

    def lookup(self, ioc_type: str, ioc: str, timeout_seconds: float) -> dict | None:
        if ioc_type != "ip":
            raise ThreatIntelProviderError(
                "unsupported_ioc", "AbuseIPDB provider only accepts IP addresses",
            )
        if not ipaddress.ip_address(ioc).is_global:
            return None

        query = urlencode({"ipAddress": ioc, "maxAgeInDays": 90})
        request = Request(
            f"{self.endpoint}?{query}",
            headers={"Accept": "application/json", "Key": self._api_key},
        )
        try:
            with self._opener(request, timeout=timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code == 429:
                raise ThreatIntelProviderError(
                    "rate_limited", "AbuseIPDB rate limit exceeded",
                ) from exc
            if exc.code in {401, 403}:
                raise ThreatIntelProviderError(
                    "authentication_error", "AbuseIPDB authentication failed",
                ) from exc
            raise ThreatIntelProviderError(
                "http_error", "AbuseIPDB request failed", retryable=exc.code >= 500,
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ThreatIntelProviderError(
                "network_error", "AbuseIPDB network error", retryable=True,
            ) from exc

        if len(raw) > MAX_RESPONSE_BYTES:
            raise ThreatIntelProviderError("invalid_response", "AbuseIPDB response is too large")
        try:
            payload = json.loads(raw.decode("utf-8"))
            data = payload["data"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ThreatIntelProviderError(
                "invalid_response", "AbuseIPDB returned an invalid response",
            ) from exc
        if not isinstance(data, dict):
            raise ThreatIntelProviderError("invalid_response", "AbuseIPDB returned an invalid response")

        return {
            "abuse_confidence": _integer(data.get("abuseConfidenceScore"), 100),
            "total_reports": _integer(data.get("totalReports")),
            "last_reported_at": _text(data.get("lastReportedAt"), 64),
            "isp": _text(data.get("isp")),
            "domain": _text(data.get("domain")),
            "usage_type": _text(data.get("usageType")),
        }
