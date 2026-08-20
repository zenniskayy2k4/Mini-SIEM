import copy
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from config import config
from src.alert_pipeline import persist_and_enrich
from src.alert_schema import build_alert
from src.assets import build_asset
from src.risk import score_alert_risk
from src.sqlite_store import SQLiteAssetRepository


class ImmediateAnalyst:
    def enrich_async(self, alert, on_complete):
        alert["ai_analysis"] = {
            "threat_confidence": 80,
            "escalate_to_human": True,
            "risk_score": 100,
        }
        alert["ai_disposition"] = "REQUIRES_HUMAN_REVIEW"
        on_complete(alert)


def _alert(**values):
    defaults = {
        "alert_name": "Risk scoring fixture",
        "severity": "HIGH",
        "source_type": "CORRELATION",
        "description": "Deterministic risk inputs",
    }
    return build_alert(**(defaults | values))


def test_risk_scoring():
    weights = {key: 10 for key in config.RISK_WEIGHTS}
    alert = _alert(
        event_count=10,
        ai_analysis={
            "threat_confidence": 80,
            "escalate_to_human": True,
            "risk_score": 100,
        },
        threat_intel={
            "abuseipdb": {"status": "ok", "abuse_confidence": 90},
            "stix": {"status": "ok", "match_count": 1, "confidence": 70},
        },
    )
    asset = {"criticality": "CRITICAL"}
    scored = score_alert_risk(copy.deepcopy(alert), asset=asset, weights=weights)
    assert scored["risk_score"] == 54 and scored["risk_level"] == "HIGH"
    assert [factor["factor"] for factor in scored["risk_factors"]] == [
        "detection_severity", "asset_criticality", "threat_confidence",
        "ti_reputation", "correlation_count", "human_review",
    ]
    assert next(
        factor for factor in scored["risk_factors"] if factor["factor"] == "ti_reputation"
    )["provider"] == "abuseipdb"
    assert score_alert_risk(copy.deepcopy(alert), asset=asset, weights=weights) == scored
    assert scored["risk_score"] != alert["ai_analysis"]["risk_score"]

    missing_ti = score_alert_risk(_alert(severity="LOW", threat_intel=None))
    assert missing_ti["risk_score"] == 4 and missing_ti["risk_level"] == "LOW"
    assert all(factor["factor"] != "ti_reputation" for factor in missing_ti["risk_factors"])

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repository = SQLiteAssetRepository(str(root / "assets.db"))
        with patch.object(config, "ANALYST_AUDIT_FILE", str(root / "audit.jsonl")):
            asset = repository.create_asset(build_asset(
                "critical.example.test",
                ip_addresses=["192.0.2.50"],
                criticality="CRITICAL",
            ))

        pipeline_alert = _alert(ip_address="192.0.2.50", event_count=5)
        notifier = Mock()
        with (
            patch("src.alert_pipeline.upsert_alert") as upsert,
            patch("src.alert_pipeline.notification_service", notifier),
        ):
            persist_and_enrich(
                pipeline_alert,
                ai_analyst=ImmediateAnalyst(),
                stix_store=None,
                asset_repository=repository,
            )
        assert pipeline_alert["asset_id"] == asset["asset_id"]
        assert pipeline_alert["risk_score"] == 67
        assert pipeline_alert["risk_level"] == "HIGH"
        assert upsert.call_count == 2 and notifier.notify.call_count == 2

    script = Path("static/js/app.js").read_text(encoding="utf-8")
    assert "function renderRiskScore(alert)" in script
    assert "renderRiskScore(alert)" in script


if __name__ == "__main__":
    test_risk_scoring()
    print("M13.4 explainable risk scoring passed")
