import logging
import os
import re
import tempfile
from pathlib import Path

import yaml

from config import config
from src.audit import append_audit_event
from src.alert_schema import SEVERITIES, SOURCE_TYPES
from src.sigma import load_sigma_rules

MATCH_OPERATORS = {
    "contains", "contains_any", "contains_all", "regex", "equals", "not_contains",
}


def set_rule_enabled(rule_id: str, enabled: bool, actor: str, directory: str | None = None) -> dict:
    if not isinstance(enabled, bool):
        raise ValueError("Rule enabled state must be boolean")
    directory = directory or config.RULES_DIR
    for path in sorted(Path(directory).glob("*.yml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"Cannot update {path.name}: {exc}") from exc
        candidates = document if isinstance(document, list) else [document]
        rule = next(
            (candidate for candidate in candidates if isinstance(candidate, dict) and candidate.get("id") == rule_id),
            None,
        )
        if rule is None:
            continue
        previous = rule.get("enabled")
        rule["enabled"] = enabled
        validate_rule(rule)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
            ) as file:
                temporary = file.name
                yaml.safe_dump(document, file, allow_unicode=True, sort_keys=False)
            os.replace(temporary, path)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
        append_audit_event(
            "RULE_ENABLED" if enabled else "RULE_DISABLED",
            actor,
            role="admin",
            target_type="detection_rule",
            target_id=rule_id,
            details={"from": previous, "to": enabled, "file": path.name},
        )
        return rule
    raise ValueError(f"Rule not found: {rule_id}")


def match_rule(match: dict, value: str):
    text = value.casefold()
    regex_match = None
    for operator, expected in match.items():
        if operator == "contains" and expected.casefold() not in text:
            return False
        if operator == "contains_any" and not any(item.casefold() in text for item in expected):
            return False
        if operator == "contains_all" and not all(item.casefold() in text for item in expected):
            return False
        if operator == "equals" and value.strip().casefold() != expected.casefold():
            return False
        if operator == "not_contains" and expected.casefold() in text:
            return False
        if operator == "regex":
            regex_match = re.search(expected, value, re.IGNORECASE)
            if not regex_match:
                return False
    return regex_match or True


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
    rule_source = rule.get("rule_source", "native")
    if rule_source not in {"native", "sigma"}:
        raise ValueError(f"Rule {rule['id']} has invalid rule_source")
    if rule_source == "sigma" and not rule.get("sigma_rule_id"):
        raise ValueError(f"Rule {rule['id']} requires sigma_rule_id")

    mitre = rule.get("mitre")
    if not isinstance(mitre, dict) or not all(
        isinstance(mitre.get(field), str) and mitre[field].strip()
        for field in ("tactic", "technique")
    ):
        raise ValueError(f"Rule {rule['id']} requires MITRE tactic and technique")

    match = rule.get("match")
    if not isinstance(match, dict) or not match or set(match) - MATCH_OPERATORS:
        raise ValueError(f"Rule {rule['id']} has invalid match operators")
    for operator, value in match.items():
        if operator in {"contains_any", "contains_all"}:
            if not isinstance(value, list) or not value or not all(
                isinstance(item, str) and item for item in value
            ):
                raise ValueError(f"Rule {rule['id']} {operator} requires a non-empty string list")
        elif not isinstance(value, str) or not value:
            raise ValueError(f"Rule {rule['id']} {operator} requires a non-empty string")
    compiled_regex = None
    if "regex" in match:
        try:
            compiled_regex = re.compile(match["regex"])
        except re.error as exc:
            raise ValueError(f"Rule {rule['id']} has invalid regex: {exc}") from exc

    threshold = rule.get("threshold")
    if threshold is not None:
        if not isinstance(threshold, dict) or set(threshold) != {"count", "window_seconds"}:
            raise ValueError(f"Rule {rule['id']} has invalid threshold references")
        if compiled_regex is None or not {"ip", "user"} <= set(compiled_regex.groupindex):
            raise ValueError(f"Rule {rule['id']} threshold regex requires named ip/user groups")
        for field, reference in threshold.items():
            if not isinstance(reference, str) or not hasattr(config, reference):
                raise ValueError(f"Rule {rule['id']} has invalid {field} reference")
            configured = getattr(config, reference)
            if not isinstance(configured, int) or isinstance(configured, bool) or configured <= 0:
                raise ValueError(f"Rule {rule['id']} {field} must reference a positive value")
    return rule


def validate_rules(rules: list) -> list:
    validated = [validate_rule(rule) for rule in rules]
    ids = [rule["id"] for rule in validated]
    if len(ids) != len(set(ids)):
        raise ValueError("Rule IDs must be unique")
    return validated


def build_detection_coverage(rules: list, hit_counts: dict) -> dict:
    report = []
    mitre = {}
    for rule in rules:
        hits = int(hit_counts.get(rule["id"], 0))
        technique = rule["mitre"]["technique"]
        report.append({
            "rule_id": rule["id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "rule_source": rule.get("rule_source", "native"),
            "validation_status": rule.get("validation_status", "valid"),
            "last_loaded_at": rule.get("last_loaded_at"),
            "mitre_tactic": rule["mitre"]["tactic"],
            "mitre_technique": technique,
            "hit_count": hits,
            "triggered": hits > 0,
            "never_hit": hits == 0,
        })
        item = mitre.setdefault(technique, {
            "technique": technique,
            "tactic": rule["mitre"]["tactic"],
            "rule_count": 0,
            "hit_count": 0,
        })
        item["rule_count"] += 1
        item["hit_count"] += hits

    rules_hit = sum(item["triggered"] for item in report)
    mitre_items = list(mitre.values())
    return {
        "summary": {
            "rules_total": len(report),
            "rules_hit": rules_hit,
            "rules_never_hit": len(report) - rules_hit,
            "mitre_techniques_total": len(mitre_items),
            "mitre_techniques_hit": sum(item["hit_count"] > 0 for item in mitre_items),
        },
        "rules": report,
        "mitre": mitre_items,
    }


def load_rules(directory: str, fallback: list, errors: list | None = None) -> list:
    loaded = []
    valid_yaml_found = False
    seen_ids = set()

    for path in sorted(Path(directory).glob("*.yml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            candidates = document if isinstance(document, list) else [document]
        except (OSError, yaml.YAMLError) as exc:
            if errors is not None:
                errors.append({"source_filename": path.name, "reason": str(exc)})
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
                if errors is not None:
                    errors.append({"source_filename": path.name, "reason": str(exc)})
                logging.warning("[-] Rule skipped from %s: %s", path.name, exc)

    if valid_yaml_found:
        return loaded
    logging.warning("[-] No valid YAML rules found; using legacy signatures")
    return validate_rules(fallback)


def load_detection_rules(
    directory: str, fallback: list, sigma_directory: str, errors: list | None = None,
) -> list:
    native = load_rules(directory, fallback, errors)
    sigma, sigma_errors = load_sigma_rules(sigma_directory)
    if errors is not None:
        errors.extend(sigma_errors)
    return validate_rules(native + [rule for rule in sigma if rule["enabled"]])
