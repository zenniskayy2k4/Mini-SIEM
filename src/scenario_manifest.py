import re
from pathlib import Path, PureWindowsPath

import yaml

from src.alert_schema import SEVERITIES


SCENARIO_SOURCES = {"linux_auth", "windows_event", "network", "cross_source"}
SCENARIO_ID = re.compile(r"^SCN-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$")
MAX_MANIFEST_BYTES = 256 * 1024
FIXTURE_SUFFIXES = {".json", ".jsonl", ".ndjson", ".xml", ".log", ".txt"}
_TOP_LEVEL_FIELDS = {
    "schema_version", "id", "title", "source", "events", "expected",
    "negative_expectations",
}
_EXPECTED_FIELDS = {"rule_ids", "alert_count", "severity", "fields"}
_FIELD_OPERATORS = {"min", "max", "equals", "contains"}


class ScenarioManifestError(ValueError):
    pass


def _fail(path, message):
    raise ScenarioManifestError(f"{Path(path).name}: {message}")


def _string_list(path, value, field, *, allow_empty=False):
    if not isinstance(value, list) or (not value and not allow_empty) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        _fail(path, f"{field} must be {'a' if allow_empty else 'a non-empty'} string list")
    if len(value) != len(set(value)):
        _fail(path, f"{field} must not contain duplicates")


def resolve_scenario_fixture(manifest, fixture_root):
    fixture_root = Path(fixture_root).resolve()
    relative = Path(manifest["events"])
    windows_relative = PureWindowsPath(manifest["events"])
    if relative.is_absolute() or windows_relative.is_absolute() or windows_relative.drive:
        raise ScenarioManifestError("events must be relative to the tests directory")
    fixture = (fixture_root / relative).resolve()
    try:
        fixture.relative_to(fixture_root)
    except ValueError as exc:
        raise ScenarioManifestError("events must stay inside the tests directory") from exc
    if fixture.suffix.lower() not in FIXTURE_SUFFIXES:
        raise ScenarioManifestError(f"unsupported fixture type: {fixture.suffix or '<none>'}")
    if not fixture.is_file():
        raise ScenarioManifestError(f"fixture does not exist: {relative.as_posix()}")
    return fixture


def validate_scenario_manifest(document, path, fixture_root):
    if not isinstance(document, dict):
        _fail(path, "manifest must be an object")
    unknown = set(document) - _TOP_LEVEL_FIELDS
    if unknown:
        _fail(path, f"unknown fields: {', '.join(sorted(unknown))}")
    required = _TOP_LEVEL_FIELDS - {"negative_expectations"}
    missing = required - set(document)
    if missing:
        _fail(path, f"missing fields: {', '.join(sorted(missing))}")
    if (
        not isinstance(document["schema_version"], int)
        or isinstance(document["schema_version"], bool)
        or document["schema_version"] != 1
    ):
        _fail(path, "schema_version must be 1")
    if not isinstance(document["id"], str) or not SCENARIO_ID.fullmatch(document["id"]):
        _fail(path, "id must match SCN-<NAME>-NNN using uppercase letters, numbers and dashes")
    if not isinstance(document["title"], str) or not document["title"].strip() or len(document["title"]) > 160:
        _fail(path, "title must contain 1-160 characters")
    if not isinstance(document["source"], str) or document["source"] not in SCENARIO_SOURCES:
        _fail(path, f"source must be one of: {', '.join(sorted(SCENARIO_SOURCES))}")
    if not isinstance(document["events"], str) or not document["events"].strip():
        _fail(path, "events must be a non-empty relative path")
    try:
        resolve_scenario_fixture(document, fixture_root)
    except ScenarioManifestError as exc:
        _fail(path, str(exc))

    expected = document["expected"]
    if not isinstance(expected, dict):
        _fail(path, "expected must be an object")
    unknown = set(expected) - _EXPECTED_FIELDS
    missing = _EXPECTED_FIELDS - set(expected)
    if unknown or missing:
        detail = (
            f"unknown fields: {', '.join(sorted(unknown))}"
            if unknown else f"missing fields: {', '.join(sorted(missing))}"
        )
        _fail(path, f"expected has {detail}")
    _string_list(path, expected["rule_ids"], "expected.rule_ids")
    if not isinstance(expected["severity"], str) or expected["severity"] not in SEVERITIES:
        _fail(path, f"expected.severity must be one of: {', '.join(sorted(SEVERITIES))}")

    count = expected["alert_count"]
    if not isinstance(count, dict) or set(count) != {"min", "max"}:
        _fail(path, "expected.alert_count must contain only min and max")
    if not all(
        isinstance(count[key], int)
        and not isinstance(count[key], bool)
        and count[key] >= 0
        for key in ("min", "max")
    ):
        _fail(path, "expected.alert_count min and max must be non-negative integers")
    if count["min"] > count["max"]:
        _fail(path, "expected.alert_count min cannot exceed max")

    fields = expected["fields"]
    if not isinstance(fields, dict):
        _fail(path, "expected.fields must be an object")
    for name, constraints in fields.items():
        if not isinstance(name, str) or not name.strip():
            _fail(path, "expected.fields keys must be non-empty strings")
        if not isinstance(constraints, dict) or not constraints or set(constraints) - _FIELD_OPERATORS:
            _fail(path, f"expected.fields.{name} has invalid constraints")
        for operator in set(constraints) & {"min", "max"}:
            value = constraints[operator]
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                _fail(path, f"expected.fields.{name}.{operator} must be numeric")
        for operator in set(constraints) & {"equals", "contains"}:
            if not isinstance(constraints[operator], (str, int, float, bool)) and constraints[operator] is not None:
                _fail(path, f"expected.fields.{name}.{operator} must be scalar")
        if {"min", "max"} <= set(constraints) and constraints["min"] > constraints["max"]:
            _fail(path, f"expected.fields.{name} min cannot exceed max")

    negative = document.get("negative_expectations")
    if negative is not None:
        if not isinstance(negative, dict) or set(negative) != {"rule_ids"}:
            _fail(path, "negative_expectations must contain only rule_ids")
        _string_list(path, negative["rule_ids"], "negative_expectations.rule_ids")
        overlap = set(expected["rule_ids"]) & set(negative["rule_ids"])
        if overlap:
            _fail(path, f"positive and negative rule IDs overlap: {', '.join(sorted(overlap))}")
    return document


def load_scenario_manifest(path, fixture_root):
    path = Path(path)
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            _fail(path, f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        _fail(path, f"cannot read YAML: {exc}")
    return validate_scenario_manifest(document, path, fixture_root)


def load_scenario_manifests(directory, fixture_root=None):
    directory = Path(directory)
    fixture_root = Path(fixture_root) if fixture_root else directory.parent
    paths = sorted([*directory.rglob("*.yml"), *directory.rglob("*.yaml")])
    manifests = [load_scenario_manifest(path, fixture_root) for path in paths]
    seen = set()
    for manifest in manifests:
        if manifest["id"] in seen:
            raise ScenarioManifestError(f"Duplicate scenario ID: {manifest['id']}")
        seen.add(manifest["id"])
    return manifests


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Validate offline detection scenario manifests")
    parser.add_argument("directory", nargs="?", default="tests/scenarios")
    parser.add_argument("--fixture-root")
    args = parser.parse_args(argv)
    try:
        manifests = load_scenario_manifests(args.directory, args.fixture_root)
    except ScenarioManifestError as exc:
        parser.exit(1, f"Scenario validation failed: {exc}\n")
    print(f"Validated {len(manifests)} scenario manifests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
