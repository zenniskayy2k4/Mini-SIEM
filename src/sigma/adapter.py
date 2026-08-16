import re

from src.sigma.schema import SIGMA_LEVEL_SEVERITY


_ATTACK_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def adapt_sigma_rule(rule: dict, source_filename: str) -> dict:
    tactics = []
    techniques = []
    for tag in rule.get("tags", []):
        technique = _ATTACK_TECHNIQUE.match(tag)
        if technique:
            techniques.append(technique.group(1).upper())
        elif tag.startswith("attack."):
            tactics.append(tag.removeprefix("attack.").replace("_", " ").title())

    return {
        "id": rule["id"],
        "title": rule["title"].strip(),
        "status": rule.get("status"),
        "description": rule.get("description", ""),
        "author": rule.get("author", ""),
        "references": list(rule.get("references", [])),
        "tags": list(rule.get("tags", [])),
        "logsource": dict(rule["logsource"]),
        "level": rule["level"],
        "severity": SIGMA_LEVEL_SEVERITY[rule["level"]],
        "detection": dict(rule["detection"]),
        "mitre_tactics": tactics,
        "mitre_techniques": techniques,
        "source_filename": source_filename,
        "rule_source": "sigma",
        "sigma_rule_id": rule["id"],
        "enabled": False,
        "validation_status": "unsupported",
        "skip_reason": "Sigma detection translation is pending M11.2",
    }
