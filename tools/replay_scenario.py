"""Deterministic, side-effect-free replay for detection scenario manifests."""

import argparse
import json
import math
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import config
from src.detector import ThreatDetector
from src.rules import load_rules, validate_rules
from src.scenario_manifest import (
    ScenarioManifestError,
    load_scenario_manifest,
    load_scenario_manifests,
    resolve_scenario_fixture,
)
from src.sigma import load_sigma_rules
from src.windows_events import normalize_windows_event


MAX_FIXTURE_BYTES = 10 * 1024 * 1024
MAX_EVENTS = 10_000
MAX_RELATIVE_SECONDS = 365 * 24 * 60 * 60
REPLAY_SOURCES = {"linux_auth", "windows_event"}
OUTPUT_FIELDS = {
    "computer", "correlation_type", "event_count", "mitre_attck_id",
    "rule_source", "sigma_rule_id", "source_type", "suppressed_count",
    "windows_event_id", "window_seconds",
}


class ScenarioReplayError(ValueError):
    pass


class ReplayClock:
    def __init__(self):
        self.current = datetime(2020, 1, 1, tzinfo=timezone.utc)

    def set(self, relative_seconds):
        self.current = datetime(2020, 1, 1, tzinfo=timezone.utc) + timedelta(
            seconds=relative_seconds
        )

    def __call__(self):
        return self.current


def _read_fixture(path, source):
    path = Path(path)
    try:
        if path.stat().st_size > MAX_FIXTURE_BYTES:
            raise ScenarioReplayError(f"fixture exceeds {MAX_FIXTURE_BYTES} bytes")
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ScenarioReplayError(f"cannot read fixture {path.name}: {exc}") from exc

    try:
        if path.suffix.lower() in {".jsonl", ".ndjson"}:
            events = [json.loads(line) for line in text.splitlines() if line.strip()]
        elif path.suffix.lower() == ".json":
            payload = json.loads(text)
            events = payload if isinstance(payload, list) else [payload]
        elif path.suffix.lower() in {".log", ".txt"}:
            events = [
                {"relative_seconds": index, "message": line}
                for index, line in enumerate(text.splitlines()) if line.strip()
            ]
        elif path.suffix.lower() == ".xml":
            events = [{"relative_seconds": 0, "record": text}]
        else:
            raise ScenarioReplayError(f"unsupported fixture type: {path.suffix}")
    except json.JSONDecodeError as exc:
        raise ScenarioReplayError(f"invalid JSON in {path.name}: {exc}") from exc

    if not events or len(events) > MAX_EVENTS:
        raise ScenarioReplayError(f"fixture must contain 1-{MAX_EVENTS} events")
    previous = -1
    for index, event in enumerate(events, 1):
        if not isinstance(event, dict):
            raise ScenarioReplayError(f"event {index} must be an object")
        relative = event.get("relative_seconds")
        if (
            not isinstance(relative, (int, float))
            or isinstance(relative, bool)
            or relative < 0
            or not math.isfinite(relative)
            or relative > MAX_RELATIVE_SECONDS
            or relative < previous
        ):
            raise ScenarioReplayError(
                f"event {index} relative_seconds must be ordered within 0..{MAX_RELATIVE_SECONDS}"
            )
        required = "message" if source == "linux_auth" else "record"
        if required not in event:
            raise ScenarioReplayError(f"event {index} requires {required}")
        if source == "linux_auth" and (
            not isinstance(event[required], str) or not event[required].strip()
        ):
            raise ScenarioReplayError(f"event {index} message must be a non-empty string")
        if source == "windows_event" and not isinstance(event[required], (dict, str)):
            raise ScenarioReplayError(f"event {index} record must be an object or XML string")
        previous = relative
    return events


def _rules(state_file):
    native = load_rules(config.RULES_DIR, config.SIGNATURES)
    sigma, _ = load_sigma_rules(config.SIGMA_RULES_DIR, state_file)
    return validate_rules(native + [rule for rule in sigma if rule["enabled"]])


def _constraint_matches(value, constraints):
    for operator, expected in constraints.items():
        if operator == "min" and (not isinstance(value, (int, float)) or value < expected):
            return False
        if operator == "max" and (not isinstance(value, (int, float)) or value > expected):
            return False
        if operator == "equals" and value != expected:
            return False
        if operator == "contains":
            if isinstance(value, str) and str(expected) not in value:
                return False
            if isinstance(value, (list, tuple, set)) and expected not in value:
                return False
            if not isinstance(value, (str, list, tuple, set)):
                return False
    return True


def _evaluate(manifest, alerts):
    failures = []
    observed = {alert.get("rule_id") for alert in alerts}
    expected = manifest["expected"]
    count = len(alerts)
    bounds = expected["alert_count"]
    if not bounds["min"] <= count <= bounds["max"]:
        failures.append(
            f"alert_count {count} outside {bounds['min']}..{bounds['max']}"
        )
    missing = set(expected["rule_ids"]) - observed
    if missing:
        failures.append(f"missing rule_ids: {', '.join(sorted(missing))}")
    forbidden = observed & set(manifest.get("negative_expectations", {}).get("rule_ids", []))
    if forbidden:
        failures.append(f"forbidden rule_ids observed: {', '.join(sorted(forbidden))}")

    relevant = [alert for alert in alerts if alert.get("rule_id") in expected["rule_ids"]]
    wrong_severity = [
        alert.get("rule_id") for alert in relevant
        if alert.get("severity") != expected["severity"]
    ]
    if wrong_severity:
        failures.append(f"unexpected severity for: {', '.join(sorted(set(wrong_severity)))}")
    if expected["fields"] and not any(
        all(_constraint_matches(alert.get(name), constraint) for name, constraint in expected["fields"].items())
        for alert in relevant
    ):
        failures.append("no expected alert satisfied all field constraints")
    return failures


def replay_manifest(manifest, fixture_root, state_file):
    if manifest["source"] not in REPLAY_SOURCES:
        raise ScenarioReplayError(
            f"source {manifest['source']} is not supported by the M19.2 replay engine"
        )
    unsupported = set(manifest["expected"]["fields"]) - OUTPUT_FIELDS
    if unsupported:
        raise ScenarioReplayError(
            f"unsupported output fields: {', '.join(sorted(unsupported))}"
        )

    events = _read_fixture(
        resolve_scenario_fixture(manifest, fixture_root), manifest["source"]
    )
    clock = ReplayClock()
    detector = ThreatDetector(_rules(state_file), load_models=False, clock=clock)
    found = {}
    for index, event in enumerate(events, 1):
        try:
            clock.set(event["relative_seconds"])
            if manifest["source"] == "linux_auth":
                alert = detector.analyze(event["message"])
            else:
                record = event["record"]
                if not isinstance(record, dict) or "event_uid" not in record:
                    record = normalize_windows_event(record)
                alert = detector.analyze_windows_event(record) if record else None
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise ScenarioReplayError(f"event {index} cannot be replayed: {exc}") from exc
        if alert:
            key = alert.get("correlation_key") or alert.get("alert_id")
            found[key] = alert

    alerts = list(found.values())
    failures = _evaluate(manifest, alerts)
    normalized = []
    requested = set(manifest["expected"]["fields"])
    for alert in alerts:
        item = {
            "rule_id": alert.get("rule_id"),
            "severity": alert.get("severity"),
            "source_type": alert.get("source_type"),
        }
        item.update({name: alert.get(name) for name in sorted(requested)})
        normalized.append(item)
    normalized.sort(
        key=lambda item: (item.get("rule_id") or "", item.get("source_type") or "")
    )
    return {
        "schema_version": 1,
        "scenario_id": manifest["id"],
        "title": manifest["title"],
        "source": manifest["source"],
        "passed": not failures,
        "events_replayed": len(events),
        "alerts_observed": len(alerts),
        "matched_rule_ids": sorted(
            rule_id for rule_id in {alert.get("rule_id") for alert in alerts} if rule_id
        ),
        "failures": failures,
        "alerts": normalized,
    }


def replay_path(path, fixture_root=None):
    path = Path(path)
    if fixture_root:
        fixture_root = Path(fixture_root)
    elif path.is_dir():
        fixture_root = path.parent
    else:
        scenario_directory = next(
            (parent for parent in path.parents if parent.name == "scenarios"),
            path.parent,
        )
        fixture_root = scenario_directory.parent
    manifests = (
        load_scenario_manifests(path, fixture_root)
        if path.is_dir() else [load_scenario_manifest(path, fixture_root)]
    )
    with tempfile.TemporaryDirectory(prefix="mini-siem-replay-") as directory:
        state_file = str(Path(directory) / "sigma_rule_states.json")
        results = [replay_manifest(item, fixture_root, state_file) for item in manifests]
    return {
        "passed": all(result["passed"] for result in results),
        "scenario_count": len(results),
        "results": results,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Replay offline detection scenarios")
    parser.add_argument("path", nargs="?", default="tests/scenarios")
    parser.add_argument("--fixture-root")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = replay_path(args.path, args.fixture_root)
    except (ScenarioManifestError, ScenarioReplayError, ValueError) as exc:
        parser.exit(2, f"Scenario replay failed: {exc}\n")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    else:
        for result in report["results"]:
            rules = ",".join(result["matched_rule_ids"]) or "none"
            print(
                f"{'PASS' if result['passed'] else 'FAIL'} {result['scenario_id']} "
                f"events={result['events_replayed']} alerts={result['alerts_observed']} rules={rules}"
            )
            for failure in result["failures"]:
                print(f"  - {failure}")
        print(f"{'PASS' if report['passed'] else 'FAIL'} {report['scenario_count']} scenario(s)")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
