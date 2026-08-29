"""Generate deterministic local JSONL telemetry without sending network traffic."""

import argparse
import json
import math
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.event_envelope import build_event_envelope


MAX_EVENTS = 100_000
MAX_DURATION_SECONDS = 86_400
DEFAULT_START = "2026-01-01T00:00:00Z"
MODE_SOURCES = {
    "steady": ("HIDS_LOG",),
    "burst": ("HIDS_LOG",),
    "mixed-source": ("HIDS_LOG", "WINDOWS_EVENT", "NIDS", "HONEYPOT"),
    "windows-heavy": ("WINDOWS_EVENT",) * 8 + ("HIDS_LOG", "NIDS"),
    "authentication-heavy": ("HIDS_LOG", "WINDOWS_EVENT"),
}


def _start_time(value):
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("start must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("start must include a timezone")
    return parsed.astimezone(timezone.utc)


def _offset(index, count, duration, mode):
    if mode != "burst":
        return duration * index / max(1, count - 1)
    buckets = min(10, count)
    bucket = min(buckets - 1, index * buckets // count)
    return duration * bucket / max(1, buckets - 1)


def _payload(source, sequence, mode, timestamp, randomizer):
    source_ip = f"192.0.2.{1 + sequence % 200}"
    common = {
        "synthetic": True,
        "sequence": sequence,
        "load_mode": mode,
        "timestamp": timestamp,
    }
    if source == "HIDS_LOG":
        failed = mode == "authentication-heavy" or sequence % 5 == 0
        outcome = "Failed password for" if failed else "Accepted publickey for"
        common["message"] = (
            f"load-host sshd[{1000 + sequence}]: {outcome} load-user "
            f"from {source_ip} port {randomizer.randint(1024, 65535)} ssh2"
        )
    elif source == "WINDOWS_EVENT":
        authentication = mode == "authentication-heavy" or sequence % 2 == 0
        common.update({
            "schema_version": 1,
            "event_uid": f"WINEVT-LOAD-{sequence:08d}",
            "event_id": 4625 if authentication else 4688,
            "computer": f"load-win-{sequence % 20:02d}",
            "user": {"name": "load-user"},
            "process": {
                "image": r"C:\Windows\System32\notepad.exe",
                "command_line": "notepad.exe synthetic-load.txt",
            },
            "network": {"source_ip": source_ip},
        })
    elif source == "NIDS":
        common.update({
            "protocol": "TCP",
            "flags": "A",
            "source_ip": source_ip,
            "destination_port": 443,
        })
    else:
        common.update({
            "event_type": "connection",
            "source_ip": source_ip,
            "destination_port": 22,
            "sensor": f"load-honeypot-{sequence % 4}",
        })
    return common


def generate_events(mode, count, duration=60.0, seed=1, start=DEFAULT_START):
    if mode not in MODE_SOURCES:
        raise ValueError(f"mode must be one of: {', '.join(MODE_SOURCES)}")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= MAX_EVENTS:
        raise ValueError(f"count must be within 1..{MAX_EVENTS}")
    if (
        not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or not math.isfinite(duration)
        or not 0 <= duration <= MAX_DURATION_SECONDS
    ):
        raise ValueError(f"duration must be within 0..{MAX_DURATION_SECONDS} seconds")
    started_at = _start_time(start)
    randomizer = random.Random(seed)
    sources = MODE_SOURCES[mode]
    for index in range(count):
        observed_at = started_at + timedelta(
            seconds=_offset(index, count, duration, mode)
        )
        timestamp = observed_at.isoformat().replace("+00:00", "Z")
        source = sources[index % len(sources)]
        yield build_event_envelope(
            _payload(source, index, mode, timestamp, randomizer),
            source_type=source,
            collector_id=f"synthetic-{mode}",
            observed_at=timestamp,
            received_at=timestamp,
        )


def write_jsonl(events, output_path="-"):
    if output_path == "-":
        for event in events:
            print(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return
    path = Path(output_path)
    with path.open("x", encoding="utf-8", newline="\n") as output:
        for event in events:
            output.write(json.dumps(
                event, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODE_SOURCES, default="steady")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--start", default=DEFAULT_START)
    parser.add_argument(
        "--output", default="-",
        help="new JSONL path (existing files are refused); default is stdout",
    )
    args = parser.parse_args(argv)
    try:
        write_jsonl(
            generate_events(args.mode, args.count, args.duration, args.seed, args.start),
            args.output,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(
        f"Generated {args.count} {args.mode} event(s); AI/TI disabled; output={args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
