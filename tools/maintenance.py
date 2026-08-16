import argparse
import json

from config import config
from src.maintenance import apply_retention, backup_database, rotate_logs


def main():
    parser = argparse.ArgumentParser(description="Mini-SIEM retention, backup and log rotation")
    commands = parser.add_subparsers(dest="command", required=True)

    backup = commands.add_parser("backup")
    backup.add_argument("--db", default=config.SQLITE_ALERT_DB)
    backup.add_argument("--output")

    retention = commands.add_parser("retention")
    retention.add_argument("--days", type=int, default=config.ALERT_RETENTION_DAYS)
    retention.add_argument("--db", default=config.SQLITE_ALERT_DB)
    retention.add_argument("--json", default=config.OUTPUT_ALERT_FILE)
    retention.add_argument("--archive-dir", default=config.ALERT_ARCHIVE_DIR)

    rotate = commands.add_parser("rotate")
    rotate.add_argument("--max-bytes", type=int, default=config.LOG_ROTATE_MAX_BYTES)
    rotate.add_argument("--backups", type=int, default=config.LOG_ROTATE_BACKUPS)

    args = parser.parse_args()
    if args.command == "backup":
        result = {"backup": str(backup_database(args.db, args.output))}
    elif args.command == "retention":
        result = apply_retention(args.days, args.db, args.json, args.archive_dir)
    else:
        result = rotate_logs(max_bytes=args.max_bytes, backups=args.backups)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
