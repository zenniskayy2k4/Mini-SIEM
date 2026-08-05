"""Small runnable check for the Milestone M2 alert pipeline."""

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import config
from src import ai_analyst
from src.alert_schema import build_alert, utc_iso
from src.alert_store import upsert_alert
from src.correlator import AlertCorrelator
from src.detector import ThreatDetector


def check_contract_and_upsert():
    required = {
        "alert_id", "timestamp", "alert_name", "severity", "status",
        "source_type", "description", "raw_log", "ip_address",
        "mitre_attck_id", "event_count", "first_seen", "last_seen",
        "correlation_key", "ml_confidence", "ai_analysis",
        "ai_recommended_severity", "ai_disposition",
    }
    for source in ("HIDS_LOG", "NIDS", "HONEYPOT", "CORRELATION"):
        alert = build_alert(
            alert_name="Check", severity="HIGH", source_type=source,
            description="check",
        )
        assert required <= alert.keys()
        assert alert["timestamp"].endswith("Z") and alert["ip_address"] is None

    original_path = config.OUTPUT_ALERT_FILE
    with tempfile.TemporaryDirectory() as directory:
        config.OUTPUT_ALERT_FILE = str(Path(directory) / "alerts.json")
        upsert_alert(alert)
        alert["event_count"] = 2
        upsert_alert(alert)
        rows = Path(config.OUTPUT_ALERT_FILE).read_text(encoding="utf-8").splitlines()
        assert len(rows) == 1 and json.loads(rows[0])["event_count"] == 2
    config.OUTPUT_ALERT_FILE = original_path


def check_ssh_campaign():
    loader = ThreatDetector._load_all_models
    ThreatDetector._load_all_models = lambda self: None
    detector = ThreatDetector([])
    ThreatDetector._load_all_models = loader

    def send(ip, count):
        result = None
        for index in range(count):
            result = detector.analyze(
                f"Aug 02 17:41:{index:02d} host sshd[20{index:02d}]: "
                f"Failed password for invalid user admin from {ip} port 52000 ssh2"
            )
        return result

    first_four = [send("192.0.2.10", 1) for _ in range(4)]
    assert first_four == [None] * 4
    first = send("192.0.2.10", 1)
    first_id = first["alert_id"]
    final = send("192.0.2.10", 15)
    other = send("192.0.2.11", 5)
    assert final["alert_id"] == first_id and final["event_count"] == 20
    assert final["suppressed_count"] == 15 and other["alert_id"] != first_id

    detector._ssh_failures["192.0.2.10"] = type(detector._ssh_failures["192.0.2.10"])(
        (datetime.now(timezone.utc) - timedelta(seconds=61), user, raw)
        for _, user, raw in detector._ssh_failures["192.0.2.10"]
    )
    assert send("192.0.2.10", 1) is None
    new_campaign = send("192.0.2.10", 4)
    assert new_campaign["alert_id"] != first_id


def check_correlator_and_prompt():
    correlator = AlertCorrelator(window_minutes=5)
    start = datetime.now(timezone.utc)

    def recon(ip, offset):
        return build_alert(
            alert_name="Network Port Scanning", severity="HIGH", source_type="NIDS",
            description="scan", raw_log=f"scan {offset}", ip_address=ip,
            timestamp=utc_iso(start + timedelta(seconds=offset)),
            correlation_key=f"Network Port Scanning|{ip}",
        )

    campaign = None
    for offset in range(5):
        campaign = correlator.correlate(recon("198.51.100.4", offset))
    campaign_id = campaign["alert_id"]
    updated = correlator.correlate(recon("198.51.100.4", 5))
    assert updated["alert_id"] == campaign_id
    assert updated["event_count"] == 6 and updated["deduplicated_events"] == 1

    for offset in range(301, 306):
        new_campaign = correlator.correlate(recon("198.51.100.4", offset))
    assert new_campaign["alert_id"] != campaign_id

    assert "Event Count" in ai_analyst._USER_TEMPLATE
    assert "observed_facts" in ai_analyst._SYSTEM_PROMPT
    assert "never claim successful" in ai_analyst._SYSTEM_PROMPT


if __name__ == "__main__":
    check_contract_and_upsert()
    check_ssh_campaign()
    check_correlator_and_prompt()
    print("Milestone M2 check passed")
