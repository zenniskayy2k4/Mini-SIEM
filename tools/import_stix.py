import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import config
from src.threat_intel import STIXIndicatorStore, pull_taxii


def main():
    parser = argparse.ArgumentParser(description="Import an offline STIX bundle or pull a TAXII collection")
    parser.add_argument("bundle", nargs="?", help="Path to an offline STIX bundle")
    parser.add_argument("--taxii-url", default=config.TAXII_COLLECTION_URL)
    parser.add_argument("--source", default="")
    args = parser.parse_args()
    if bool(args.bundle) == bool(args.taxii_url):
        parser.error("provide either a bundle path or --taxii-url")

    store = STIXIndicatorStore(config.STIX_INDICATOR_FILE)
    source = args.source or ("offline" if args.bundle else config.TAXII_FEED_SOURCE)
    try:
        if args.bundle:
            bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
            stats = store.import_bundle(bundle, source)
        else:
            stats = pull_taxii(
                store, args.taxii_url, source, config.TAXII_BEARER_TOKEN,
            )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"STIX/TAXII import failed: {exc}") from exc
    print(json.dumps(stats, sort_keys=True))


if __name__ == "__main__":
    main()
