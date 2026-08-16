import logging
from pathlib import Path

import yaml

from src.sigma.adapter import adapt_sigma_rule
from src.sigma.schema import validate_sigma_rule


def load_sigma_rules(directory: str) -> tuple[list[dict], list[dict]]:
    rules = []
    errors = []
    seen_ids = {}
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
                rules.append(adapt_sigma_rule(rule, path.name))
                logging.info("[+] Sigma metadata loaded (disabled): %s", rule["id"])
            except (KeyError, ValueError) as exc:
                errors.append({"source_filename": path.name, "reason": str(exc)})
                logging.warning("[-] Sigma rule skipped from %s: %s", path.name, exc)

    return rules, errors
