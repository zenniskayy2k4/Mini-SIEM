import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.windows_events import import_windows_events


def main():
    parser = argparse.ArgumentParser(description="Import offline Sysmon/Windows events")
    parser.add_argument("input", help="Path to .json, .jsonl, .ndjson, .xml or .evtx export")
    parser.add_argument("--output", help="Normalized JSONL output path")
    args = parser.parse_args()
    print(json.dumps(import_windows_events(args.input, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
