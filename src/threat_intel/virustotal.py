import json
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from src.threat_intel.base import ThreatIntelProvider, ThreatIntelProviderError


VIRUSTOTAL_FIELDS = (
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
    "reputation",
    "last_analysis_at",
)
MAX_RESPONSE_BYTES = 64 * 1024


def _integer(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"

    def __init__(
        self, api_key: str, endpoint="https://www.virustotal.com/api/v3/files", opener=urlopen,
    ):
        self._api_key = str(api_key or "").strip()
        if not self._api_key:
            raise ValueError("VirusTotal API key must not be empty")
        self.endpoint = str(endpoint).rstrip("/")
        if not self.endpoint.startswith("https://"):
            raise ValueError("VirusTotal endpoint must use HTTPS")
        self._opener = opener

    def lookup(self, ioc_type: str, ioc: str, timeout_seconds: float) -> dict | None:
        if ioc_type not in {"sha256", "md5"}:
            raise ThreatIntelProviderError(
                "unsupported_ioc", "VirusTotal provider only accepts file hashes",
            )
        request = Request(
            f"{self.endpoint}/{ioc}",
            headers={"Accept": "application/json", "x-apikey": self._api_key},
        )
        try:
            with self._opener(request, timeout=timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code == 429:
                raise ThreatIntelProviderError(
                    "rate_limited", "VirusTotal rate limit exceeded",
                ) from exc
            if exc.code in {401, 403}:
                raise ThreatIntelProviderError(
                    "authentication_error", "VirusTotal authentication failed",
                ) from exc
            raise ThreatIntelProviderError(
                "http_error", "VirusTotal request failed", retryable=exc.code >= 500,
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ThreatIntelProviderError(
                "network_error", "VirusTotal network error", retryable=True,
            ) from exc

        if len(raw) > MAX_RESPONSE_BYTES:
            raise ThreatIntelProviderError("invalid_response", "VirusTotal response is too large")
        try:
            attributes = json.loads(raw.decode("utf-8"))["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ThreatIntelProviderError(
                "invalid_response", "VirusTotal returned an invalid response",
            ) from exc
        if not isinstance(attributes, dict) or not isinstance(stats, dict):
            raise ThreatIntelProviderError("invalid_response", "VirusTotal returned an invalid response")

        analysed = attributes.get("last_analysis_date")
        try:
            analysed = datetime.fromtimestamp(int(analysed), timezone.utc).isoformat().replace("+00:00", "Z")
        except (TypeError, ValueError, OSError, OverflowError):
            analysed = None
        return {
            "malicious": max(0, _integer(stats.get("malicious"))),
            "suspicious": max(0, _integer(stats.get("suspicious"))),
            "harmless": max(0, _integer(stats.get("harmless"))),
            "undetected": max(0, _integer(stats.get("undetected"))),
            "reputation": _integer(attributes.get("reputation")),
            "last_analysis_at": analysed,
        }
