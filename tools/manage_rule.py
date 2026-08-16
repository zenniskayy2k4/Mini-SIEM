import argparse

from src.rules import set_rule_enabled


def main():
    parser = argparse.ArgumentParser(description="Enable or disable a YAML detection rule with audit")
    parser.add_argument("rule_id")
    parser.add_argument("state", choices=("enabled", "disabled"))
    parser.add_argument("--actor", required=True, help="Admin username making the change")
    args = parser.parse_args()
    rule = set_rule_enabled(args.rule_id, args.state == "enabled", args.actor)
    print(f"{rule['id']} is now {args.state}")


if __name__ == "__main__":
    main()
