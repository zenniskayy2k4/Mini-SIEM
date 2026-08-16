import json
import logging
import os
import tempfile
from pathlib import Path

import yaml

from config import config
from src.alert_schema import utc_iso
from src.audit import append_audit_event
from src.sigma.adapter import adapt_sigma_rule, translate_sigma_rule
from src.sigma.schema import validate_sigma_rule


def load_sigma_rule_states(path: str | None = None) -> dict[str, bool]:
    path = path or config.SIGMA_RULE_STATE_FILE
    try:
        states = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(states, dict) or not all(
            isinstance(rule_id, str) and isinstance(enabled, bool)
            for rule_id, enabled in states.items()
        ):
            raise ValueError("Sigma rule state must be a boolean map")
        return states
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        logging.warning("[-] Sigma rule state ignored: %s", exc)
        return {}


def _save_sigma_rule_states(states: dict[str, bool], path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=target.parent, delete=False, suffix=".tmp"
        ) as file:
            temporary = file.name
            json.dump(states, file, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(temporary, target)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def load_sigma_rules(
    directory: str, state_file: str | None = None,
) -> tuple[list[dict], list[dict]]:
    rules = []
    errors = []
    seen_ids = {}
    states = load_sigma_rule_states(state_file)
    loaded_at = utc_iso()
    root = Path(directory)
    paths = sorted({*root.glob("*.yml"), *root.glob("*.yaml")})

    for path in paths:
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except (OSError, yaml.YAMLError) as exc:
            errors.append({"source_filename": path.name, "reason": str(exc)})
            logging.warning("[-] Sigma file skipped: %s (%s)", path.name, exc)
            continue

        for document in documents:
            try:
                rule = validate_sigma_rule(document)
                previous = seen_ids.get(rule["id"])
                if previous:
                    raise ValueError(
                        f"Duplicate Sigma id {rule['id']} (already loaded from {previous})"
                    )
                seen_ids[rule["id"]] = path.name
                adapted = adapt_sigma_rule(rule, path.name)
                try:
                    adapted = translate_sigma_rule(adapted)
                    logging.info("[+] Sigma rule translated: %s", rule["id"])
                except ValueError as exc:
                    adapted["skip_reason"] = str(exc)
                    logging.warning("[-] Sigma rule disabled: %s", exc)
                if adapted["supported"]:
                    adapted["enabled"] = states.get(rule["id"], adapted["enabled"])
                adapted["last_loaded_at"] = loaded_at
                rules.append(adapted)
            except (KeyError, ValueError) as exc:
                errors.append({"source_filename": path.name, "reason": str(exc)})
                logging.warning("[-] Sigma rule skipped from %s: %s", path.name, exc)

    return rules, errors


def set_sigma_rule_enabled(
    rule_id: str,
    enabled: bool,
    actor: str,
    directory: str | None = None,
    state_file: str | None = None,
) -> dict:
    if not isinstance(enabled, bool):
        raise ValueError("Rule enabled state must be boolean")
    directory = directory or config.SIGMA_RULES_DIR
    state_file = state_file or config.SIGMA_RULE_STATE_FILE
    rules, _ = load_sigma_rules(directory, state_file)
    rule = next((item for item in rules if item["id"] == rule_id), None)
    if rule is None:
        raise ValueError(f"Sigma rule not found: {rule_id}")
    if not rule["supported"]:
        raise ValueError(f"Sigma rule cannot be enabled: {rule['skip_reason']}")

    previous = rule["enabled"]
    states = load_sigma_rule_states(state_file)
    states[rule_id] = enabled
    _save_sigma_rule_states(states, state_file)
    append_audit_event(
        "RULE_ENABLED" if enabled else "RULE_DISABLED",
        actor,
        role="admin",
        target_type="detection_rule",
        target_id=rule_id,
        details={"from": previous, "to": enabled, "source": "sigma"},
    )
    rule["enabled"] = enabled
    return rule
