import tempfile
from pathlib import Path

from config import config
from src.detector import ThreatDetector
from src.rules import load_rules
from src.sigma import load_sigma_rules


SIGMA_ID = "7c4f8f2e-1e7b-4d95-9f76-8c731fef60a3"


def test_sigma_loader():
    rules, errors = load_sigma_rules(config.SIGMA_RULES_DIR)
    assert not errors
    assert len(rules) == 1
    sigma = rules[0]
    assert sigma["sigma_rule_id"] == SIGMA_ID
    assert sigma["rule_source"] == "sigma"
    assert sigma["severity"] == "HIGH"
    assert sigma["mitre_tactics"] == ["Execution"]
    assert sigma["mitre_techniques"] == ["T1059.001"]
    assert sigma["source_filename"] == "suspicious_powershell.yml"
    assert sigma["detection"]["condition"] == "selection"
    assert sigma["enabled"] is False
    assert sigma["validation_status"] == "unsupported"

    with tempfile.TemporaryDirectory() as directory:
        Path(directory, "valid.yml").write_text(
            Path(config.SIGMA_RULES_DIR, "suspicious_powershell.yml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        Path(directory, "invalid.yml").write_text("title: Missing required fields\n", encoding="utf-8")
        loaded, failures = load_sigma_rules(directory)
        assert len(loaded) == 1
        assert len(failures) == 1
        assert failures[0]["source_filename"] == "invalid.yml"

    with tempfile.TemporaryDirectory() as directory:
        sample = Path(config.SIGMA_RULES_DIR, "suspicious_powershell.yml").read_text(encoding="utf-8")
        Path(directory, "first.yml").write_text(sample, encoding="utf-8")
        Path(directory, "second.yaml").write_text(sample, encoding="utf-8")
        loaded, failures = load_sigma_rules(directory)
        assert len(loaded) == 1
        assert len(failures) == 1
        assert "Duplicate Sigma id" in failures[0]["reason"]

    native_rules = load_rules(config.RULES_DIR, config.SIGNATURES)
    native_alert = ThreatDetector(native_rules)._rule_based_detect(
        "srv sudo: user : USER=root ; COMMAND=/usr/bin/su"
    )
    assert native_alert["rule_source"] == "native"
    assert native_alert["sigma_rule_id"] is None

    translated = {
        "id": SIGMA_ID,
        "title": "Translated Sigma fixture",
        "description": "Provenance contract fixture",
        "enabled": True,
        "severity": "HIGH",
        "source_type": "HIDS_LOG",
        "mitre": {"tactic": "Execution", "technique": "T1059.001"},
        "match": {"contains": "sigma-fixture"},
        "rule_source": "sigma",
        "sigma_rule_id": SIGMA_ID,
    }
    sigma_alert = ThreatDetector([translated])._rule_based_detect("sigma-fixture")
    assert sigma_alert["rule_source"] == "sigma"
    assert sigma_alert["sigma_rule_id"] == SIGMA_ID


if __name__ == "__main__":
    test_sigma_loader()
    print("M11.1 Sigma loader passed")
