import ipaddress
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from src.threat_intel.base import ThreatIntelProvider, ThreatIntelProviderError


GEOIP_FIELDS = ("country", "country_code", "city", "asn", "organization", "is_private")
MAX_RESPONSE_BYTES = 64 * 1024


def local_geoip_context(ip: str) -> dict | None:
    """Return local context for non-global IPs so they never leave the host."""
    address = ipaddress.ip_address(ip)
    if address.is_global:
        return None
    return {
        "country": None,
        "country_code": None,
        "city": None,
        "asn": None,
        "organization": None,
        "is_private": bool(address.is_private or address.is_loopback or address.is_link_local),
    }


def _text(value, limit=200):
    value = str(value).strip() if value is not None else ""
    return value[:limit] or None


class GeoIPProvider(ThreatIntelProvider):
    name = "ipwhois"

    def __init__(self, endpoint="https://ipwho.is", opener=urlopen):
        self.endpoint = str(endpoint).rstrip("/")
        if not self.endpoint.startswith("https://"):
            raise ValueError("GeoIP endpoint must use HTTPS")
        self._opener = opener

    def lookup(self, ioc_type: str, ioc: str, timeout_seconds: float) -> dict:
        if ioc_type != "ip":
            raise ThreatIntelProviderError(
                "unsupported_ioc", "GeoIP provider only accepts IP addresses",
            )
        local = local_geoip_context(ioc)
        if local is not None:
            return local

        request = Request(
            f"{self.endpoint}/{ioc}",
            headers={"Accept": "application/json", "User-Agent": "Mini-SIEM/0.4"},
        )
        try:
            with self._opener(request, timeout=timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise ThreatIntelProviderError(
                "http_error", "GeoIP provider request failed",
                retryable=exc.code == 429 or exc.code >= 500,
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ThreatIntelProviderError(
                "network_error", "GeoIP provider network error", retryable=True,
            ) from exc

        if len(raw) > MAX_RESPONSE_BYTES:
            raise ThreatIntelProviderError("invalid_response", "GeoIP response is too large")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ThreatIntelProviderError("invalid_response", "GeoIP provider returned invalid JSON") from exc
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise ThreatIntelProviderError("lookup_failed", "GeoIP provider could not locate the IP")

        connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
        asn = connection.get("asn")
        if not isinstance(asn, int):
            asn = _text(asn, 32)
        return {
            "country": _text(payload.get("country")),
            "country_code": _text(payload.get("country_code"), 8),
            "city": _text(payload.get("city")),
            "asn": asn,
            "organization": _text(connection.get("org")),
            "is_private": False,
        }
