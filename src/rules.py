import re

from src.alert_schema import SEVERITIES, SOURCE_TYPES


def validate_rule(rule: dict) -> dict:
    if not isinstance(rule, dict):
        raise ValueError("Rule must be an object")
    for field in ("id", "title", "description"):
        if not isinstance(rule.get(field), str) or not rule[field].strip():
            raise ValueError(f"Rule {field} must be a non-empty string")
    if not isinstance(rule.get("enabled"), bool):
        raise ValueError(f"Rule {rule['id']} enabled must be boolean")
    if rule.get("severity") not in SEVERITIES:
        raise ValueError(f"Rule {rule['id']} has invalid severity")
    if rule.get("source_type") not in SOURCE_TYPES:
        raise ValueError(f"Rule {rule['id']} has invalid source_type")

    mitre = rule.get("mitre")
    if not isinstance(mitre, dict) or not all(
        isinstance(mitre.get(field), str) and mitre[field].strip()
        for field in ("tactic", "technique")
    ):
        raise ValueError(f"Rule {rule['id']} requires MITRE tactic and technique")

    match = rule.get("match")
    if not isinstance(match, dict) or not isinstance(match.get("regex"), str):
        raise ValueError(f"Rule {rule['id']} requires match.regex")
    try:
        re.compile(match["regex"])
    except re.error as exc:
        raise ValueError(f"Rule {rule['id']} has invalid regex: {exc}") from exc
    return rule


def validate_rules(rules: list) -> list:
    validated = [validate_rule(rule) for rule in rules]
    ids = [rule["id"] for rule in validated]
    if len(ids) != len(set(ids)):
        raise ValueError("Rule IDs must be unique")
    return validated
