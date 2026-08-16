import re

from src.sigma.schema import SIGMA_LEVEL_SEVERITY


_ATTACK_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_NEXT_FIELD = r" [a-z_]+="
FIELD_ALIASES = {
    "eventid": "event_id",
    "image": "process_image",
    "newprocessname": "process_image",
    "processname": "process_image",
    "commandline": "command_line",
    "processcommandline": "command_line",
    "parentimage": "parent_image",
    "parentprocessname": "parent_image",
    "targetimage": "target_image",
    "grantedaccess": "granted_access",
    "user": "user",
    "username": "user",
    "targetusername": "user",
    "subjectusername": "user",
    "taskname": "task_name",
    "taskcontent": "task_content",
    "newvalue": "defender_setting",
}


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
        "supported": False,
        "validation_status": "unsupported",
        "skip_reason": "Sigma detection translation is pending M11.2",
    }


def _strings(value, rule_id: str) -> list[str]:
    values = value if isinstance(value, list) else [value]
    if not values or any(item is None or isinstance(item, (dict, list)) for item in values):
        raise ValueError(f"Sigma rule {rule_id} requires scalar selection values")
    strings = [str(item) for item in values]
    if any(not item or "*" in item or "?" in item for item in strings):
        raise ValueError(f"Sigma rule {rule_id} uses unsupported empty/wildcard values")
    return strings


def _field_fragments(field_expression: str, value, rule_id: str) -> list[str]:
    parts = field_expression.split("|")
    field = FIELD_ALIASES.get(parts[0].casefold())
    if not field:
        raise ValueError(f"Sigma rule {rule_id} uses unsupported field: {parts[0]}")
    modifiers = tuple(item.casefold() for item in parts[1:])
    if modifiers not in {(), ("contains",), ("startswith",), ("endswith",), ("contains", "all")}:
        label = "|".join(parts[1:]) or "equals"
        raise ValueError(f"Sigma rule {rule_id} uses unsupported modifier: {label}")

    values = _strings(value, rule_id)
    alternatives = "(?:" + "|".join(re.escape(item) for item in values) + ")"
    prefix = rf"\b{field}="
    segment = rf"(?:(?!{_NEXT_FIELD}).)*"
    boundary = rf"(?={_NEXT_FIELD}|$)"
    if modifiers == ("contains", "all"):
        if len(values) < 2:
            raise ValueError(f"Sigma rule {rule_id} contains|all requires multiple values")
        return [rf"(?=.*{prefix}{segment}{re.escape(item)})" for item in values]
    if modifiers == ("contains",):
        return [rf"(?=.*{prefix}{segment}{alternatives})"]
    if modifiers == ("startswith",):
        return [rf"(?=.*{prefix}{alternatives})"]
    if modifiers == ("endswith",):
        return [rf"(?=.*{prefix}{segment}{alternatives}{boundary})"]
    return [rf"(?=.*{prefix}{alternatives}{boundary})"]


def _selection_fragment(selection, rule_id: str) -> str:
    if isinstance(selection, str) or (
        isinstance(selection, list) and all(isinstance(item, str) for item in selection)
    ):
        values = _strings(selection, rule_id)
        return rf"(?=.*(?:{'|'.join(re.escape(item) for item in values)}))"
    if not isinstance(selection, dict) or not selection:
        raise ValueError(f"Sigma rule {rule_id} uses an unsupported selection structure")
    fragments = []
    for field, value in selection.items():
        if not isinstance(field, str):
            raise ValueError(f"Sigma rule {rule_id} selection fields must be strings")
        fragments.extend(_field_fragments(field, value, rule_id))
    return "".join(fragments)


def _condition_regex(detection: dict, rule_id: str) -> str:
    condition = detection["condition"]
    if not isinstance(condition, str):
        raise ValueError(f"Sigma rule {rule_id} uses unsupported condition lists")
    parsed = re.fullmatch(
        rf"\s*({_IDENTIFIER})(?:\s+(and|or)\s+(?:(not)\s+)?({_IDENTIFIER}))?\s*",
        condition,
        re.IGNORECASE,
    )
    if not parsed:
        raise ValueError(f"Sigma rule {rule_id} uses unsupported condition: {condition}")
    left, operator, negate, right = parsed.groups()

    def fragment(name: str) -> str:
        if name not in detection or name == "condition":
            raise ValueError(f"Sigma rule {rule_id} references unknown selection: {name}")
        return _selection_fragment(detection[name], rule_id)

    left_fragment = fragment(left)
    if operator is None:
        return rf"^{left_fragment}.*$"
    right_fragment = fragment(right)
    if negate:
        if operator.casefold() != "and":
            raise ValueError(f"Sigma rule {rule_id} only supports negation with AND")
        return rf"^{left_fragment}(?!{right_fragment}.*$).*$"
    if operator.casefold() == "and":
        return rf"^{left_fragment}{right_fragment}.*$"
    return rf"^(?:{left_fragment}|{right_fragment}).*$"


def translate_sigma_rule(rule: dict) -> dict:
    rule_id = rule["sigma_rule_id"]
    if rule.get("status") in {"deprecated", "unsupported"}:
        raise ValueError(f"Sigma rule {rule_id} status is not enableable: {rule['status']}")
    if str(rule["logsource"].get("product", "")).casefold() != "windows":
        raise ValueError(f"Sigma rule {rule_id} only supports Windows logsource in phase 1")

    translated = dict(rule)
    translated.update({
        "description": rule["description"] or rule["title"],
        "source_type": "WINDOWS_EVENT",
        "mitre": {
            "tactic": (rule["mitre_tactics"] or ["Unknown"])[0],
            "technique": (rule["mitre_techniques"] or ["N/A"])[0],
        },
        "match": {"regex": _condition_regex(rule["detection"], rule_id)},
        "extract_ip": False,
        "enabled": True,
        "supported": True,
        "validation_status": "valid",
        "skip_reason": None,
    })
    return translated
