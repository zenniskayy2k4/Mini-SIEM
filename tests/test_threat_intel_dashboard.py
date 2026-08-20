from concurrent.futures import Future
from pathlib import Path
from unittest.mock import Mock, patch

from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert


class PendingService:
    def __init__(self):
        self.calls = []

    def lookup_async(self, ioc_type, ioc):
        self.calls.append((ioc_type, ioc))
        return Future()


def test_threat_intel_dashboard():
    digest = "a" * 64
    alert = build_alert(
        alert_name="Threat intelligence UI",
        severity="HIGH",
        source_type="WINDOWS_EVENT",
        description="Observed evidence",
        ip_address="8.8.8.8",
        hashes={"SHA256": digest, "MD5": "b" * 32},
    )
    geoip = PendingService()
    abuseipdb = PendingService()
    virustotal = PendingService()
    notifier = Mock()
    with (
        patch("src.alert_pipeline.upsert_alert") as upsert,
        patch("src.alert_pipeline.notification_service", notifier),
    ):
        persist_and_enrich(
            alert,
            geoip_service=geoip,
            abuseipdb_service=abuseipdb,
            virustotal_service=virustotal,
        )
    assert upsert.call_count == 1 and notifier.notify.call_count == 1
    assert geoip.calls == [("ip", "8.8.8.8")]
    assert abuseipdb.calls == [("ip", "8.8.8.8")]
    assert virustotal.calls == [("sha256", digest)]
    assert {key: value["status"] for key, value in alert["threat_intel"].items()} == {
        "ipwhois": "pending",
        "abuseipdb": "pending",
        "virustotal": "pending",
    }
    assert alert["severity"] == "HIGH"

    unavailable = build_alert(
        alert_name="Disabled providers",
        severity="MEDIUM",
        source_type="WINDOWS_EVENT",
        description="Provider unavailable state",
        ip_address="10.0.0.5",
        sha256=digest,
    )
    with (
        patch("src.alert_pipeline.upsert_alert"),
        patch("src.alert_pipeline.notification_service"),
    ):
        persist_and_enrich(unavailable)
    assert all(
        entry["status"] == "unavailable"
        for entry in unavailable["threat_intel"].values()
    )

    script = Path("static/js/app.js").read_text(encoding="utf-8")
    panel = script.split("function renderThreatIntelligence", 1)[1].split(
        "function renderIncidentPanel", 1,
    )[0]
    for expected in (
        "Observed IOC", "Third-party intelligence only", "Lookup pending",
        "Provider unavailable", "Cache hit", "Live lookup", "system severity unchanged",
    ):
        assert expected in panel
    assert "raw_provider" not in panel and "JSON.stringify" not in panel
    assert "renderThreatIntelligence(alert)" in script

    styles = Path("static/css/style.css").read_text(encoding="utf-8")
    assert ".threat-intel-panel" in styles and ".threat-intel-card" in styles


if __name__ == "__main__":
    test_threat_intel_dashboard()
    print("M12.5 threat intelligence dashboard passed")
