import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.dashboard_auth import ROLES, save_user


def main():
    parser = argparse.ArgumentParser(description="Create or update a Mini-SIEM dashboard user")
    parser.add_argument("username")
    parser.add_argument("role", choices=ROLES)
    args = parser.parse_args()
    password = os.getenv("DASHBOARD_USER_PASSWORD") or getpass.getpass("Password: ")
    confirmation = os.getenv("DASHBOARD_USER_PASSWORD") or getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    save_user(args.username, password, args.role)
    print(f"Dashboard user '{args.username.lower()}' saved with role '{args.role}'.")


if __name__ == "__main__":
    main()
