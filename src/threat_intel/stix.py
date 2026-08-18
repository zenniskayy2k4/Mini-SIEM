import ipaddress
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from src.alert_schema import utc_iso
from src.threat_intel.service import normalize_ioc


_PATTERN = re.compile(
    r"^\s*\[\s*(ipv4-addr:value|domain-name:value|file:hashes\.(?:'SHA-256'|SHA-256|'MD5'|MD5))"
    r"\s*=\s*'([^']+)'\s*\]\s*$",
    re.IGNORECASE,
)
_MAX_TAXII_BYTES = 5 * 1024 * 1024


class STIXFeedError(RuntimeError):
    pass


def _time(value, fallback=None):
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid STIX timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return utc_iso(parsed)


def _expired(indicator, now=None):
    valid_until = indicator.get("valid_until")
    if not valid_until:
        return False
    now = now or datetime.now(timezone.utc)
    expires = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
    return expires <= now


def _normalize_indicator(obj, source, now):
    if not isinstance(obj, dict) or obj.get("type") != "indicator":
        raise ValueError("Object is not a STIX Indicator")
    if obj.get("pattern_type", "stix").lower() != "stix":
        raise ValueError("Unsupported indicator pattern type")
    match = _PATTERN.fullmatch(str(obj.get("pattern") or ""))
    if not match:
        raise ValueError("Unsupported STIX indicator pattern")

    path, value = match.groups()
    path = path.lower().replace("'", "")
    if path == "ipv4-addr:value":
        ioc_type = "ip"
    elif path == "domain-name:value":
        ioc_type = "domain"
    elif path.endswith("sha-256"):
        ioc_type = "sha256"
    else:
        ioc_type = "md5"
    ioc_type, ioc = normalize_ioc(ioc_type, value)
    if ioc_type == "ip" and not isinstance(ipaddress.ip_address(ioc), ipaddress.IPv4Address):
        raise ValueError("Only IPv4 STIX indicators are supported")

    confidence = obj.get("confidence")
    confidence = max(0, min(100, int(confidence))) if confidence is not None else None
    labels = obj.get("labels", [])
    if not isinstance(labels, list):
        raise ValueError("STIX indicator labels must be a list")
    labels = [str(label)[:100] for label in labels if str(label).strip()]
    return {
        "stix_id": str(obj.get("id") or ""),
        "ioc_type": ioc_type,
        "ioc": ioc,
        "source": str(source or "unknown")[:200],
        "source_ref": str(obj.get("created_by_ref") or "")[:200] or None,
        "valid_from": _time(obj.get("valid_from") or obj.get("created"), utc_iso(now)),
        "valid_until": _time(obj.get("valid_until")),
        "confidence": confidence,
        "labels": labels,
    }


class STIXIndicatorStore:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._indicators = []
        self._mtime = None
        self._reload()

    def _reload(self):
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            indicators = payload.get("indicators", [])
            self._indicators = indicators if isinstance(indicators, list) else []
            self._mtime = self.path.stat().st_mtime_ns
        except (OSError, json.JSONDecodeError, AttributeError):
            self._indicators = []
            self._mtime = None

    def _refresh(self):
        try:
            mtime = self.path.stat().st_mtime_ns
        except OSError:
            mtime = None
        if mtime != self._mtime:
            self._reload()

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps({
            "version": 1,
            "updated_at": utc_iso(),
            "indicators": self._indicators,
        }, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temporary, self.path)
        self._mtime = self.path.stat().st_mtime_ns

    def import_bundle(self, bundle, source="offline"):
        if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
            raise ValueError("Expected a STIX bundle")
        objects = bundle.get("objects")
        if not isinstance(objects, list):
            raise ValueError("STIX bundle objects must be a list")

        now = datetime.now(timezone.utc)
        stats = {"imported": 0, "deduplicated": 0, "expired": 0, "skipped": 0}
        with self._lock:
            self._refresh()
            active = [indicator for indicator in self._indicators if not _expired(indicator, now)]
            stats["expired"] += len(self._indicators) - len(active)
            by_key = {
                (item.get("ioc_type"), item.get("ioc"), item.get("source")): item
                for item in active
            }
            for obj in objects:
                try:
                    indicator = _normalize_indicator(obj, source, now)
                except (TypeError, ValueError):
                    stats["skipped"] += 1
                    continue
                if _expired(indicator, now):
                    stats["expired"] += 1
                    continue
                key = (indicator["ioc_type"], indicator["ioc"], indicator["source"])
                if key in by_key:
                    stats["deduplicated"] += 1
                else:
                    stats["imported"] += 1
                by_key[key] = indicator
            self._indicators = sorted(
                by_key.values(), key=lambda item: (item["ioc_type"], item["ioc"], item["source"]),
            )
            self._save()
        return stats

    def match(self, ioc_type, ioc, now=None):
        try:
            kind, normalized = normalize_ioc(ioc_type, ioc)
        except ValueError:
            return []
        now = now or datetime.now(timezone.utc)
        with self._lock:
            self._refresh()
            return [dict(item) for item in self._indicators if (
                item.get("ioc_type") == kind
                and item.get("ioc") == normalized
                and not _expired(item, now)
            )]

    def match_alert(self, alert):
        candidates = []
        if alert.get("ip_address"):
            candidates.append(("ip", alert["ip_address"]))
        domains = alert.get("domains") or []
        domains = [domains] if isinstance(domains, str) else domains
        for value in [alert.get("domain"), *domains]:
            if value:
                candidates.append(("domain", value))
        hashes = alert.get("hashes") if isinstance(alert.get("hashes"), dict) else {}
        hashes = {str(key).lower().replace("-", ""): value for key, value in hashes.items()}
        for kind in ("sha256", "md5"):
            value = alert.get(kind) or hashes.get(kind)
            if value:
                candidates.append((kind, value))
        matches = []
        for kind, value in dict.fromkeys(candidates):
            matches.extend(self.match(kind, value))
        return matches


def summarize_stix_matches(matches):
    if not matches:
        return None
    sources = sorted({item["source"] for item in matches})
    labels = sorted({label for item in matches for label in item.get("labels", [])})
    confidence = max(
        (item["confidence"] for item in matches if item.get("confidence") is not None),
        default=None,
    )
    first = matches[0]
    return {
        "provider": "stix",
        "status": "ok",
        "ioc_type": first["ioc_type"],
        "ioc": first["ioc"],
        "sources": sources,
        "confidence": confidence,
        "labels": labels,
        "match_count": len(matches),
        "matches": [{
            key: item.get(key) for key in (
                "ioc_type", "ioc", "source", "valid_from", "valid_until", "confidence", "labels",
            )
        } for item in matches],
    }


def _taxii_page_url(url, next_token):
    parsed = urlsplit(url)
    query = [(key, value) for key, value in parse_qsl(parsed.query) if key != "next"]
    query.append(("next", next_token))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def pull_taxii(store, url, source="taxii", token="", timeout_seconds=10, opener=urlopen):
    parsed = urlsplit(str(url or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("TAXII collection URL must be HTTP(S) without embedded credentials")
    objects = []
    current_url = url
    try:
        for _ in range(10):
            headers = {"Accept": "application/taxii+json;version=2.1"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            request = Request(current_url, headers=headers, method="GET")
            with opener(request, timeout=timeout_seconds) as response:
                raw = response.read(_MAX_TAXII_BYTES + 1)
            if len(raw) > _MAX_TAXII_BYTES:
                raise STIXFeedError("TAXII response exceeded size limit")
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise STIXFeedError("TAXII response must be an object")
            page_objects = payload.get("objects", [])
            if not isinstance(page_objects, list):
                raise STIXFeedError("TAXII response objects must be a list")
            objects.extend(page_objects)
            next_token = payload.get("next")
            if not payload.get("more") or not next_token:
                break
            current_url = _taxii_page_url(url, str(next_token))
        else:
            raise STIXFeedError("TAXII pagination limit exceeded")
    except STIXFeedError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise STIXFeedError("TAXII feed unavailable") from exc
    return store.import_bundle({"type": "bundle", "objects": objects}, source)


def pull_taxii_safe(*args, **kwargs):
    try:
        return {"status": "ok", **pull_taxii(*args, **kwargs)}
    except Exception:
        return {"status": "error", "error": "TAXII feed unavailable"}
