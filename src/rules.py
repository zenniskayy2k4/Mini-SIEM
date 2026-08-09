import logging
import re
from pathlib import Path

import yaml

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


def load_rules(directory: str, fallback: list) -> list:
    loaded = []
    valid_yaml_found = False
    seen_ids = set()

    for path in sorted(Path(directory).glob("*.yml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            candidates = document if isinstance(document, list) else [document]
        except (OSError, yaml.YAMLError) as exc:
            logging.warning("[-] Rule file skipped: %s (%s)", path.name, exc)
            continue

        for candidate in candidates:
            try:
                rule = validate_rule(candidate)
                if rule["id"] in seen_ids:
                    raise ValueError(f"Duplicate rule ID: {rule['id']}")
                seen_ids.add(rule["id"])
                valid_yaml_found = True
                if not rule["enabled"]:
                    logging.info("[-] Rule skipped (disabled): %s", rule["id"])
                    continue
                loaded.append(rule)
                logging.info("[+] Rule loaded: %s", rule["id"])
            except (KeyError, ValueError) as exc:
                logging.warning("[-] Rule skipped from %s: %s", path.name, exc)

    if valid_yaml_found:
        return loaded
    logging.warning("[-] No valid YAML rules found; using legacy signatures")
    return validate_rules(fallback)
