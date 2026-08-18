import ipaddress
from uuid import UUID, uuid4

from src.alert_schema import utc_iso


ENVIRONMENTS = {"dev", "test", "prod"}
CRITICALITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ASSET_FIELDS = {
    "asset_id", "hostname", "ip_addresses", "os", "owner", "department",
    "environment", "criticality", "tags", "enabled", "created_at", "updated_at",
}


def _text(value, field, max_length):
    if not isinstance(value, str):
        raise ValueError(f"Asset {field} must be a string")
    value = value.strip()
    if len(value) > max_length:
        raise ValueError(f"Asset {field} exceeds {max_length} characters")
    return value


def normalize_ip_address(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise ValueError("Invalid asset IP address") from exc


def validate_asset(asset: dict) -> dict:
    if not isinstance(asset, dict):
        raise ValueError("Asset must be an object")
    unknown = set(asset) - ASSET_FIELDS
    if unknown:
        raise ValueError(f"Asset contains unsupported fields: {', '.join(sorted(unknown))}")

    normalized = dict(asset)
    asset_id = _text(normalized.get("asset_id"), "asset_id", 64)
    try:
        if not asset_id.startswith("AST-"):
            raise ValueError
        UUID(asset_id[4:])
    except (ValueError, AttributeError) as exc:
        raise ValueError("Asset asset_id must use AST-<UUID>") from exc
    normalized["asset_id"] = asset_id

    hostname = _text(normalized.get("hostname"), "hostname", 253)
    if not hostname:
        raise ValueError("Asset hostname must be a non-empty string")
    normalized["hostname"] = hostname

    addresses = normalized.get("ip_addresses")
    if not isinstance(addresses, list):
        raise ValueError("Asset ip_addresses must be a list")
    if len(addresses) > 64:
        raise ValueError("Asset ip_addresses exceeds 64 entries")
    try:
        normalized["ip_addresses"] = sorted({normalize_ip_address(value) for value in addresses})
    except ValueError as exc:
        raise ValueError("Asset ip_addresses contains an invalid address") from exc

    for field, limit in (("os", 100), ("owner", 200), ("department", 200)):
        normalized[field] = _text(normalized.get(field, ""), field, limit)

    environment = _text(normalized.get("environment"), "environment", 20).lower()
    if environment not in ENVIRONMENTS:
        raise ValueError("Asset environment must be dev, test, or prod")
    normalized["environment"] = environment

    criticality = _text(normalized.get("criticality"), "criticality", 20).upper()
    if criticality not in CRITICALITIES:
        raise ValueError("Asset criticality must be LOW, MEDIUM, HIGH, or CRITICAL")
    normalized["criticality"] = criticality

    tags = normalized.get("tags")
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError("Asset tags must be a list of strings")
    if len(tags) > 32:
        raise ValueError("Asset tags exceeds 32 entries")
    normalized["tags"] = sorted(
        {_text(tag, "tag", 64) for tag in tags if tag.strip()}, key=str.casefold,
    )

    if not isinstance(normalized.get("enabled"), bool):
        raise ValueError("Asset enabled must be boolean")
    for field in ("created_at", "updated_at"):
        normalized[field] = _text(normalized.get(field), field, 40)
        if not normalized[field]:
            raise ValueError(f"Asset {field} must be a non-empty string")
    return normalized


def build_asset(
    hostname: str,
    *,
    ip_addresses: list[str] | None = None,
    os: str = "",
    owner: str = "",
    department: str = "",
    environment: str = "dev",
    criticality: str = "MEDIUM",
    tags: list[str] | None = None,
    enabled: bool = True,
) -> dict:
    timestamp = utc_iso()
    return validate_asset({
        "asset_id": f"AST-{uuid4()}",
        "hostname": hostname,
        "ip_addresses": [] if ip_addresses is None else ip_addresses,
        "os": os,
        "owner": owner,
        "department": department,
        "environment": environment,
        "criticality": criticality,
        "tags": [] if tags is None else tags,
        "enabled": enabled,
        "created_at": timestamp,
        "updated_at": timestamp,
    })


def enrich_alert_with_asset(alert: dict, repository) -> dict:
    """Attach only the matching enabled asset ID; hostname wins over IP."""
    match = None
    for field in ("hostname", "computer"):
        hostname = alert.get(field)
        if isinstance(hostname, str) and hostname.strip():
            candidate = repository.find_by_hostname(hostname)
            if candidate and candidate["enabled"]:
                match = candidate
                break
    if match is None and alert.get("ip_address"):
        try:
            candidate = repository.find_by_ip(alert["ip_address"])
        except ValueError:
            candidate = None
        if candidate and candidate["enabled"]:
            match = candidate
    alert["asset_id"] = match["asset_id"] if match else None
    return alert
