from uuid import UUID


SIGMA_LEVEL_SEVERITY = {
    "informational": "LOW",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}
SIGMA_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}


def validate_sigma_rule(rule: dict) -> dict:
    if not isinstance(rule, dict):
        raise ValueError("Sigma rule must be an object")

    title = rule.get("title")
    if not isinstance(title, str) or not title.strip():
        raise ValueError("Sigma title must be a non-empty string")

    sigma_id = rule.get("id")
    if not isinstance(sigma_id, str):
        raise ValueError("Sigma id must be a UUID string")
    try:
        normalized_id = str(UUID(sigma_id))
    except ValueError as exc:
        raise ValueError("Sigma id must be a valid UUID") from exc

    logsource = rule.get("logsource")
    if not isinstance(logsource, dict) or not logsource:
        raise ValueError(f"Sigma rule {normalized_id} requires logsource metadata")

    detection = rule.get("detection")
    if not isinstance(detection, dict) or not detection:
        raise ValueError(f"Sigma rule {normalized_id} requires detection")
    condition = detection.get("condition")
    valid_condition = (
        isinstance(condition, str) and bool(condition.strip())
    ) or (
        isinstance(condition, list)
        and bool(condition)
        and all(isinstance(item, str) and item.strip() for item in condition)
    )
    if not valid_condition:
        raise ValueError(f"Sigma rule {normalized_id} requires a condition")

    status = rule.get("status")
    if status is not None and status not in SIGMA_STATUSES:
        raise ValueError(f"Sigma rule {normalized_id} has invalid status")

    level = rule.get("level", "medium")
    if level not in SIGMA_LEVEL_SEVERITY:
        raise ValueError(f"Sigma rule {normalized_id} has invalid level")

    for field in ("description", "author"):
        if field in rule and not isinstance(rule[field], str):
            raise ValueError(f"Sigma rule {normalized_id} {field} must be a string")
    for field in ("references", "tags"):
        value = rule.get(field, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"Sigma rule {normalized_id} {field} must be a string list")

    normalized = dict(rule)
    normalized["id"] = normalized_id
    normalized["level"] = level
    return normalized
