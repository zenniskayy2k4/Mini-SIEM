from config import config
from src.detector import ThreatDetector
from src.rules import load_rules, match_rule, validate_rule


def test_rule_matching():
    line = "alpha beta gamma"
    assert match_rule({"contains": "BETA"}, line)
    assert match_rule({"contains_any": ["missing", "gamma"]}, line)
    assert match_rule({"contains_all": ["alpha", "gamma"]}, line)
    assert match_rule({"regex": r"b.ta"}, line)
    assert match_rule({"equals": "ALPHA BETA GAMMA"}, line)
    assert match_rule({"not_contains": "delta"}, line)
    assert not match_rule({"contains": "alpha", "not_contains": "beta"}, line)

    broken = dict(config.SIGNATURES[1], match={"regex": "["})
    try:
        validate_rule(broken)
        raise AssertionError("Invalid regex was accepted")
    except ValueError:
        pass

    detector = ThreatDetector(load_rules(config.RULES_DIR, config.SIGNATURES))
    sudo = detector._rule_based_detect(
        "srv sudo: user : USER=root ; COMMAND=/usr/bin/su"
    )
    account = detector._rule_based_detect(
        "srv useradd[1]: new user: name=m53test, UID=5300"
    )
    assert sudo["rule_id"] == "DET-LNX-001"
    assert account["rule_id"] == "DET-LNX-002"

    ssh = None
    for port in range(config.SSH_BRUTE_FORCE_THRESHOLD):
        _, ssh = detector._check_ssh_bruteforce(
            f"srv sshd[1]: Failed password for admin from 192.168.53.1 port {5300 + port} ssh2"
        )
    assert ssh["rule_id"] == "DET-SSH-001"
    assert ssh["event_count"] == config.SSH_BRUTE_FORCE_THRESHOLD


if __name__ == "__main__":
    test_rule_matching()
    print("M5.3 rule matching passed")
