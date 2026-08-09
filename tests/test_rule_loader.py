import tempfile
from pathlib import Path

from config import config
from src.rules import load_rules


def test_rule_loader():
    actual = load_rules(config.RULES_DIR, config.SIGNATURES)
    assert [rule["id"] for rule in actual] == ["DET-LNX-002", "DET-LNX-001"]

    with tempfile.TemporaryDirectory() as directory:
        Path(directory, "rules.yml").write_text(
            """\
- id: DET-TEST-001
  title: Valid
  description: Valid test rule
  enabled: true
  severity: LOW
  source_type: HIDS_LOG
  mitre: {tactic: Test, technique: T0000}
  match: {regex: valid}
- id: DET-TEST-002
  title: Disabled
  description: Disabled test rule
  enabled: false
  severity: LOW
  source_type: HIDS_LOG
  mitre: {tactic: Test, technique: T0000}
  match: {regex: disabled}
- id: DET-TEST-003
  title: Broken
  description: Broken test rule
  enabled: true
  severity: LOW
  source_type: HIDS_LOG
  mitre: {tactic: Test, technique: T0000}
  match: {regex: '['}
""",
            encoding="utf-8",
        )
        assert [rule["id"] for rule in load_rules(directory, config.SIGNATURES)] == ["DET-TEST-001"]

    with tempfile.TemporaryDirectory() as directory:
        assert load_rules(directory, config.SIGNATURES) == config.SIGNATURES


if __name__ == "__main__":
    test_rule_loader()
    print("M5.2 rule loader passed")
