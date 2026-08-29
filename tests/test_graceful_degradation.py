import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from config import config
from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert
from src.notifier import WebhookNotifier


def _alert(name):
    return build_alert(
        alert_name=name,
        severity="CRITICAL",
        source_type="HIDS_LOG",
        description="overload policy fixture",
        ip_address="192.0.2.80",
        sha256="a" * 64,
    )


def test_graceful_degradation():
    ai = Mock()
    geoip = Mock()
    abuseipdb = Mock()
    virustotal = Mock()
    stix = Mock()
    notifier = Mock()
    order = []
    notifier.notify.side_effect = lambda *_args, **_kwargs: order.append("notify")

    with (
        patch("src.alert_pipeline.upsert_alert", side_effect=lambda _alert: order.append("persist")) as upsert,
        patch("src.alert_pipeline.notification_service", notifier),
    ):
        degraded = persist_and_enrich(
            _alert("Degraded"), ai, geoip, abuseipdb, virustotal,
            stix_store=stix, overload_state="degraded",
        )
        assert order == ["persist", "notify"]
        assert upsert.call_count == 1
        assert degraded["processing_state"] == "degraded"
        assert degraded["ai_analysis"] == {"skipped": "overload"}
        assert all(
            degraded["threat_intel"][provider]["status"] == "skipped"
            for provider in ("ipwhois", "abuseipdb", "virustotal")
        )
        ai.enrich_async.assert_not_called()
        geoip.lookup_async.assert_not_called()
        abuseipdb.lookup_async.assert_not_called()
        virustotal.lookup_async.assert_not_called()
        stix.match_alert.assert_not_called()
        notifier.notify.assert_called_once_with(degraded, overload_state="degraded")

    with tempfile.TemporaryDirectory() as directory:
        original_log = config.NOTIFICATION_LOG_FILE
        config.NOTIFICATION_LOG_FILE = str(Path(directory, "notifications.jsonl"))
        try:
            saturated = _alert("Saturated")
            real_notifier = WebhookNotifier("https://hooks.example.test/overload")
            with (
                patch("src.alert_pipeline.upsert_alert") as upsert,
                patch("src.alert_pipeline.notification_service", real_notifier),
                patch("src.notifier.requests.post") as post,
            ):
                persist_and_enrich(
                    saturated, ai, geoip, abuseipdb, virustotal,
                    stix_store=None, overload_state="saturated",
                )
            upsert.assert_called_once()
            post.assert_not_called()
            audit = json.loads(Path(config.NOTIFICATION_LOG_FILE).read_text(encoding="utf-8"))
            assert audit["status"] == "SKIPPED_OVERLOAD" and audit["attempts"] == 0
            assert saturated["degraded_features"] == [
                "ai", "external_threat_intelligence", "notifications",
            ]
        finally:
            config.NOTIFICATION_LOG_FILE = original_log


if __name__ == "__main__":
    test_graceful_degradation()
    print("M25.4 graceful overload degradation passed")
