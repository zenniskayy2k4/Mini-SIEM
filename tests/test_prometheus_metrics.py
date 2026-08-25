import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import dashboard
from config import config
from src.alert_schema import build_alert


class AlertSource:
    def __init__(self, alerts):
        self.alerts = alerts

    def list_alerts(self):
        return self.alerts


class FailingAlertSource:
    def list_alerts(self):
        raise RuntimeError("database secret must not leak")


def test_prometheus_metrics():
    successful = build_alert(
        alert_name="Successful enrichment",
        severity="HIGH",
        source_type="NIDS",
        description="Metrics fixture",
        ip_address="192.0.2.99",
    )
    successful.update({
        "assigned_to": "secret-user",
        "ai_analysis": {"analysed_at": "2026-08-19T00:00:00Z"},
        "threat_intel": {"abuseipdb": {"status": "ok"}},
        "response_actions": [{"mode": "simulation", "status": "SIMULATED"}],
    })
    failed = build_alert(
        alert_name="Failed enrichment",
        severity="CRITICAL",
        source_type="HIDS_LOG",
        description="Metrics fixture",
        incident_status="RESOLVED",
    )
    failed.update({
        "ai_analysis": {"error": "provider secret"},
        "threat_intel": {"virustotal": {"status": "timeout"}},
    })
    system_status = {
        "agent": {"age_seconds": 2.5},
        "queue": {"busy": True, "backlog": 3},
    }
    rules = [{"rule_id": "DET-TEST-001", "rule_source": "native", "hit_count": 2}]

    with tempfile.TemporaryDirectory() as directory:
        notification_log = Path(directory, "notifications.jsonl")
        notification_log.write_text("\n".join((
            json.dumps({"status": "SENT", "error": "notification secret"}),
            json.dumps({"status": "FAILED", "error": "notification secret"}),
            "invalid-json",
        )), encoding="utf-8")
        original_token = config.METRICS_BEARER_TOKEN
        original_log = config.NOTIFICATION_LOG_FILE
        try:
            config.NOTIFICATION_LOG_FILE = str(notification_log)
            client = dashboard.app.test_client()
            with (
                patch.object(dashboard, "alert_repository", AlertSource([successful, failed])),
                patch.object(dashboard, "_detection_rule_records", return_value=rules),
                patch.object(dashboard, "build_system_status", return_value=system_status),
                patch.object(dashboard, "get_ingestion_failure_diagnostics", return_value={
                    "counts": {"parser": 2, "schema": 1, "unsupported": 3},
                }),
            ):
                config.METRICS_BEARER_TOKEN = ""
                response = client.get("/metrics")
                assert response.status_code == 200
                assert response.content_type.startswith("text/plain")
                body = response.get_data(as_text=True)
                for sample in (
                    'mini_siem_alerts{severity="HIGH"} 1',
                    'mini_siem_alerts{severity="CRITICAL"} 1',
                    'mini_siem_incidents{status="NEW"} 1',
                    'mini_siem_incidents{status="RESOLVED"} 1',
                    'mini_siem_detection_hits{rule_id="DET-TEST-001",source="native"} 2',
                    'mini_siem_ai_enrichments{result="success"} 1',
                    'mini_siem_ai_enrichments{result="failure"} 1',
                    'mini_siem_ti_lookups{provider="abuseipdb",result="success"} 1',
                    'mini_siem_ti_lookups{provider="virustotal",result="failure"} 1',
                    'mini_siem_notifications{result="success"} 1',
                    'mini_siem_notifications{result="failure"} 1',
                    "mini_siem_response_simulations 1",
                    "mini_siem_agent_heartbeat_age_seconds 2.5",
                    "mini_siem_ai_worker_busy 1",
                    "mini_siem_ai_queue_backlog 3",
                    'mini_siem_ingestion_failures{type="parser"} 2',
                    'mini_siem_ingestion_failures{type="schema"} 1',
                    'mini_siem_ingestion_failures{type="unsupported"} 3',
                ):
                    assert sample in body
                for secret in ("192.0.2.99", "secret-user", "provider secret", "notification secret"):
                    assert secret not in body

                config.METRICS_BEARER_TOKEN = "metrics-secret"
                assert client.get("/metrics").status_code == 401
                assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
                authorized = client.get(
                    "/metrics", headers={"Authorization": "Bearer metrics-secret"},
                )
                assert authorized.status_code == 200

            with patch.object(dashboard, "alert_repository", FailingAlertSource()):
                unavailable = client.get(
                    "/metrics", headers={"Authorization": "Bearer metrics-secret"},
                )
                assert unavailable.status_code == 503
                assert "mini_siem_metrics_up 0" in unavailable.get_data(as_text=True)
                assert "database secret" not in unavailable.get_data(as_text=True)
        finally:
            config.METRICS_BEARER_TOKEN = original_token
            config.NOTIFICATION_LOG_FILE = original_log


if __name__ == "__main__":
    test_prometheus_metrics()
    print("M14.1 Prometheus operational metrics passed")
