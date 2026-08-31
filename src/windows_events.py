import hashlib
import json
import logging
import os
import threading
import time
from collections import namedtuple
from pathlib import Path
from xml.etree import ElementTree

from config import config
from src.alert_schema import utc_iso
from src.event_envelope import (
    build_event_envelope, normalize_collector_id, unwrap_event_envelope,
)
from src.ingestion_failures import record_ingestion_failure, record_ingestion_health


PRIORITY_EVENT_IDS = {
    1: "Process Create",
    3: "Network Connection",
    7: "Image Load",
    10: "Process Access",
    11: "File Create",
    13: "Registry Value Set",
    4624: "Successful Logon",
    4625: "Failed Logon",
    4688: "Process Creation",
    4698: "Scheduled Task Created",
    4720: "User Account Created",
    5007: "Defender Configuration Changed",
}
# ponytail: process-local lock fits the single-process dashboard; use DB locking if it becomes multi-worker.
_WRITE_LOCK = threading.Lock()
_FailedRecord = namedtuple("_FailedRecord", "failure_type reason payload")
logger = logging.getLogger(__name__)


def _ci(mapping, *names):
    if not isinstance(mapping, dict):
        return None
    lowered = {str(key).lower(): value for key, value in mapping.items()}
    for name in names:
        if str(name).lower() in lowered:
            return lowered[str(name).lower()]
    return None


def _scalar(value):
    if isinstance(value, dict):
        for key in ("#text", "text", "value", "Value"):
            if key in value:
                return value[key]
    return value


def _event_data(value):
    if not isinstance(value, dict):
        return {}
    items = _ci(value, "Data")
    if items is None:
        return {str(key): _scalar(item) for key, item in value.items() if not str(key).startswith("@")}
    if not isinstance(items, list):
        items = [items]
    result = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = _ci(item, "@Name", "Name")
        if name:
            result[str(name)] = _scalar(item)
    return result


def _json_common(record):
    event = _ci(record, "Event") or record
    system = _ci(event, "System") or {}
    winlog = _ci(record, "winlog") or {}
    event_meta = _ci(record, "event") or {}
    data = _event_data(_ci(event, "EventData") or _ci(record, "event_data") or _ci(winlog, "event_data") or {})

    provider_value = _ci(system, "Provider")
    provider = _ci(provider_value, "@Name", "Name") if isinstance(provider_value, dict) else provider_value
    provider = provider or _ci(winlog, "provider_name") or _ci(record, "provider")
    event_id = _scalar(_ci(system, "EventID")) or _ci(winlog, "event_id") or _ci(event_meta, "code") or _ci(record, "event_id")
    time_value = _ci(system, "TimeCreated")
    timestamp = _ci(time_value, "@SystemTime", "SystemTime") if isinstance(time_value, dict) else time_value
    timestamp = timestamp or _ci(event_meta, "created") or _ci(record, "timestamp", "@timestamp")

    process = _ci(record, "process") or {}
    parent = _ci(process, "parent") or _ci(record, "parent_process") or {}
    user = _ci(record, "user") or {}
    source = _ci(record, "source") or {}
    destination = _ci(record, "destination") or {}
    network = _ci(record, "network") or {}
    process_hash = _ci(process, "hash")
    if process_hash and not _ci(data, "Hashes"):
        data["Hashes"] = process_hash

    aliases = {
        "Image": _ci(process, "executable", "image", "name"),
        "ProcessId": _ci(process, "pid", "process_id"),
        "ProcessGuid": _ci(process, "entity_id", "guid"),
        "CommandLine": _ci(process, "command_line", "commandline"),
        "ParentImage": _ci(parent, "executable", "image", "name"),
        "ParentProcessId": _ci(parent, "pid", "process_id"),
        "ParentCommandLine": _ci(parent, "command_line", "commandline"),
        "User": _ci(user, "name", "user_name"),
        "SourceIp": _ci(source, "ip"),
        "SourcePort": _ci(source, "port"),
        "DestinationIp": _ci(destination, "ip"),
        "DestinationPort": _ci(destination, "port"),
        "Protocol": _ci(network, "transport", "protocol"),
    }
    for key, value in aliases.items():
        if value is not None and _ci(data, key) is None:
            data[key] = value

    return {
        "event_id": event_id,
        "provider": provider,
        "channel": _scalar(_ci(system, "Channel")) or _ci(winlog, "channel"),
        "computer": _scalar(_ci(system, "Computer")) or _ci(winlog, "computer_name") or _ci(record, "host_name"),
        "record_id": _scalar(_ci(system, "EventRecordID")) or _ci(winlog, "record_id"),
        "timestamp": timestamp,
        "data": data,
    }


def _local(tag):
    return str(tag).rsplit("}", 1)[-1]


def _xml_common(root):
    system = next((node for node in root if _local(node.tag) == "System"), None)
    event_data = next((node for node in root if _local(node.tag) in {"EventData", "UserData"}), None)
    fields = {}
    if event_data is not None:
        for node in event_data.iter():
            if node is event_data:
                continue
            name = node.attrib.get("Name") or _local(node.tag)
            if node.text and node.text.strip():
                fields[name] = node.text.strip()

    values = {}
    if system is not None:
        for node in system:
            name = _local(node.tag)
            if name == "Provider":
                values["provider"] = node.attrib.get("Name")
            elif name == "TimeCreated":
                values["timestamp"] = node.attrib.get("SystemTime")
            elif node.text:
                values[name] = node.text.strip()
    return {
        "event_id": values.get("EventID"),
        "provider": values.get("provider"),
        "channel": values.get("Channel"),
        "computer": values.get("Computer"),
        "record_id": values.get("EventRecordID"),
        "timestamp": values.get("timestamp"),
        "data": fields,
    }


def _pick(data, *names):
    value = _ci(data, *names)
    return None if value in (None, "", "-") else value


def _integer(value):
    if value in (None, "", "-"):
        return None
    try:
        return int(str(value), 0)
    except ValueError:
        return None


def _hashes(value):
    if isinstance(value, dict):
        return {str(key).upper(): str(item) for key, item in value.items() if item}
    result = {}
    for item in str(value or "").replace(";", ",").split(","):
        if "=" in item:
            algorithm, digest = item.split("=", 1)
            if algorithm.strip() and digest.strip():
                result[algorithm.strip().upper()] = digest.strip()
    return result


def normalize_windows_event(record):
    if isinstance(record, str):
        try:
            record = ElementTree.fromstring(record)
        except ElementTree.ParseError as exc:
            raise ValueError("Windows event contains invalid XML") from exc
    common = _xml_common(record) if isinstance(record, ElementTree.Element) else _json_common(record)
    try:
        event_id = int(str(common["event_id"]))
    except (TypeError, ValueError):
        raise ValueError("Windows event is missing a numeric Event ID")
    if event_id not in PRIORITY_EVENT_IDS:
        return None
    if not common.get("timestamp"):
        raise ValueError(f"Windows Event ID {event_id} is missing a timestamp")

    data = common["data"]
    if event_id in {4624, 4625}:
        user_name = _pick(data, "TargetUserName", "SubjectUserName", "User", "UserName")
        domain = _pick(data, "TargetDomainName", "SubjectDomainName", "UserDomain")
    elif event_id == 4688:
        user_name = _pick(data, "SubjectUserName", "User", "UserName", "TargetUserName")
        domain = _pick(data, "SubjectDomainName", "UserDomain", "TargetDomainName")
    else:
        user_name = _pick(data, "User", "UserName", "TargetUserName", "SubjectUserName")
        domain = _pick(data, "UserDomain", "TargetDomainName", "SubjectDomainName")
    user = f"{domain}\\{user_name}" if domain and user_name and "\\" not in str(user_name) and "@" not in str(user_name) else user_name
    process_id = _pick(data, "NewProcessId") if event_id == 4688 else _pick(data, "ProcessId")
    process_image = _pick(data, "NewProcessName") if event_id == 4688 else _pick(data, "Image", "SourceImage")
    parent_id = _pick(data, "CreatorProcessId", "ParentProcessId")
    if event_id == 4688 and parent_id is None:
        parent_id = _pick(data, "ProcessId")

    normalized = {
        "schema_version": 1,
        "event_id": event_id,
        "event_name": PRIORITY_EVENT_IDS[event_id],
        "provider": common.get("provider"),
        "channel": common.get("channel"),
        "computer": common.get("computer"),
        "record_id": str(common["record_id"]) if common.get("record_id") is not None else None,
        "timestamp": utc_iso(str(common["timestamp"])),
        "process": {
            "id": str(process_id) if process_id is not None else None,
            "guid": _pick(data, "ProcessGuid"),
            "image": process_image,
            "command_line": _pick(data, "CommandLine", "ProcessCommandLine"),
            "current_directory": _pick(data, "CurrentDirectory"),
        },
        "parent_process": {
            "id": str(parent_id) if parent_id is not None else None,
            "guid": _pick(data, "ParentProcessGuid"),
            "image": _pick(data, "CreatorProcessName", "ParentImage"),
            "command_line": _pick(data, "ParentCommandLine"),
        },
        "target_process": {
            "id": str(_pick(data, "TargetProcessId")) if _pick(data, "TargetProcessId") is not None else None,
            "guid": _pick(data, "TargetProcessGuid"),
            "image": _pick(data, "TargetImage"),
            "granted_access": _pick(data, "GrantedAccess"),
        },
        "user": user,
        "hashes": _hashes(_pick(data, "Hashes", "Hash")),
        "network": {
            "source_ip": _pick(data, "SourceIp", "IpAddress"),
            "source_port": _integer(_pick(data, "SourcePort")),
            "destination_ip": _pick(data, "DestinationIp"),
            "destination_port": _integer(_pick(data, "DestinationPort")),
            "protocol": _pick(data, "Protocol"),
            "initiated": _pick(data, "Initiated"),
        },
        "file": {"target": _pick(data, "TargetFilename")},
        "registry": {
            "target": _pick(data, "TargetObject"),
            "details": _pick(data, "Details"),
        },
        "logon": {
            "type": _pick(data, "LogonType"),
            "workstation": _pick(data, "WorkstationName"),
            "status": _pick(data, "Status", "SubStatus"),
        },
        "task": {
            "name": _pick(data, "TaskName"),
            "content": _pick(data, "TaskContent"),
        },
        "defender": {
            "setting": _pick(data, "New Value", "NewValue"),
        },
    }
    canonical = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    normalized["event_uid"] = f"WINEVT-{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:24]}"
    return normalized


def windows_event_text(event):
    """Stable searchable text consumed by the existing YAML rule engine."""
    fields = {
        "event_id": event.get("event_id"),
        "process_image": event.get("process", {}).get("image"),
        "command_line": event.get("process", {}).get("command_line"),
        "parent_image": event.get("parent_process", {}).get("image"),
        "target_image": event.get("target_process", {}).get("image"),
        "granted_access": event.get("target_process", {}).get("granted_access"),
        "user": event.get("user"),
        "task_name": event.get("task", {}).get("name"),
        "task_content": event.get("task", {}).get("content"),
        "defender_setting": event.get("defender", {}).get("setting"),
    }
    return " ".join(f"{key}={value}" for key, value in fields.items() if value not in (None, ""))


def _read_json(path):
    # ponytail: JSON arrays load in memory; use JSONL for large exports.
    text = path.read_text(encoding="utf-8-sig")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    yield _FailedRecord("parser", f"Invalid JSON: {exc.msg}", line)
        return
    if isinstance(payload, list):
        yield from payload
    elif isinstance(payload, dict) and isinstance(_ci(payload, "Events"), list):
        yield from _ci(payload, "Events")
    else:
        yield payload


def iter_windows_events(path):
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in {".json", ".jsonl", ".ndjson"}:
        yield from _read_json(path)
    elif suffix == ".xml":
        try:
            root = ElementTree.parse(path).getroot()
        except ElementTree.ParseError as exc:
            yield _FailedRecord("parser", f"Invalid XML: {exc}", path.read_text(
                encoding="utf-8", errors="ignore",
            ))
            return
        if _local(root.tag) == "Event":
            yield root
        else:
            yield from (node for node in root.iter() if _local(node.tag) == "Event")
    elif suffix == ".evtx":
        from Evtx.Evtx import Evtx

        with Evtx(str(path)) as log:
            for record in log.records():
                raw = record.xml()
                try:
                    yield ElementTree.fromstring(raw)
                except ElementTree.ParseError as exc:
                    yield _FailedRecord("parser", f"Invalid EVTX XML: {exc}", raw)
    else:
        raise ValueError("Supported Windows event formats: .json, .jsonl, .ndjson, .xml, .evtx")


def _store_windows_events(records, source_name, output_path=None):
    started = time.monotonic()
    output_path = Path(output_path or config.WINDOWS_EVENT_FILE)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    collector_id = normalize_collector_id(source_name)
    summary = {"read": 0, "imported": 0, "duplicates": 0, "unsupported": 0, "errors": 0}
    with _WRITE_LOCK:
        existing = set()
        if output_path.exists():
            with output_path.open(encoding="utf-8", errors="ignore") as file:
                for line in file:
                    try:
                        _, metadata = unwrap_event_envelope(
                            json.loads(line), "WINDOWS_EVENT",
                        )
                        existing.add(metadata["event_id"])
                    except (json.JSONDecodeError, ValueError):
                        continue

        with output_path.open("a", encoding="utf-8") as output:
            for record in records:
                summary["read"] += 1
                if isinstance(record, _FailedRecord):
                    _record_ingestion_failure(
                        summary, record.failure_type, record.reason, record.payload,
                        collector_id,
                    )
                    continue
                try:
                    event = normalize_windows_event(record)
                except (TypeError, ValueError) as exc:
                    failure_type = "parser" if "invalid XML" in str(exc) else "schema"
                    _record_ingestion_failure(
                        summary, failure_type, str(exc), record, collector_id,
                    )
                    continue
                if event is None:
                    _record_ingestion_failure(
                        summary, "unsupported", "Windows event type is not supported",
                        record, collector_id,
                    )
                    continue
                try:
                    envelope = build_event_envelope(
                        event, source_type="WINDOWS_EVENT", collector_id=collector_id,
                        observed_at=event["timestamp"],
                    )
                except ValueError as exc:
                    _record_ingestion_failure(
                        summary, "schema", str(exc), event, collector_id,
                    )
                    continue
                if envelope["event_id"] in existing:
                    summary["duplicates"] += 1
                    continue
                output.write(json.dumps(envelope, ensure_ascii=False) + "\n")
                existing.add(envelope["event_id"])
                summary["imported"] += 1
    try:
        record_ingestion_health(summary, "WINDOWS_EVENT", time.monotonic() - started)
    except Exception as exc:
        logger.warning("Could not persist ingestion health: %s", type(exc).__name__)
    return summary


def _record_ingestion_failure(summary, failure_type, reason, payload, collector_id):
    summary["unsupported" if failure_type == "unsupported" else "errors"] += 1
    try:
        record_ingestion_failure(
            failure_type, reason, payload, collector_id=collector_id,
        )
    except Exception as exc:
        # Diagnostics must never block the primary ingestion path.
        logger.warning("Could not persist ingestion failure: %s", type(exc).__name__)


def ingest_windows_events(records, source_name="windows-collector", output_path=None):
    if not isinstance(records, list):
        raise ValueError("Windows collector events must be a list")
    return _store_windows_events(records, source_name, output_path)


def import_windows_events(input_path, output_path=None):
    input_path = Path(input_path)
    if not input_path.is_file():
        raise ValueError(f"Windows event input not found: {input_path}")
    return _store_windows_events(iter_windows_events(input_path), input_path.name, output_path)
