import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from config import config
from dashboard import app
from src.ai_analyst import AIAnalyst
from src.ai_provider import OllamaCloudProvider
from src.alert_schema import build_alert
from src.health import write_agent_heartbeat
from src.ingestion_failures import record_collector_heartbeat
from src.sqlite_store import SQLiteAlertRepository
from tests.auth_helpers import login_as


def test_health():
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        original = (
            config.AGENT_HEARTBEAT_FILE,
            config.SQLITE_ALERT_DB,
            config.DASHBOARD_USERS_FILE,
            config.WINDOWS_COLLECTOR_SECRET,
        )
        config.AGENT_HEARTBEAT_FILE = str(directory / "heartbeat.json")
        config.SQLITE_ALERT_DB = str(directory / "alerts.db")
        config.WINDOWS_COLLECTOR_SECRET = ""
        repository = SQLiteAlertRepository(config.SQLITE_ALERT_DB)
        alert = build_alert(
            alert_name="Health test",
            severity="HIGH",
            source_type="HIDS_LOG",
            description="diagnostic state",
        )
        alert["ai_analysis"] = {"analysed_at": "2026-08-14T01:02:03Z"}
        repository.create_alert(alert)
        write_agent_heartbeat(
            {
                "enabled": True,
                "provider": "ollama_cloud",
                "model": "test-model",
                "available": True,
                "last_successful_enrichment": None,
                "last_failure": None,
                "busy": True,
                "backlog": 0,
            },
            True,
            False,
        )
        try:
            with patch("src.health.alert_repository", repository), patch(
                "dashboard.RUNTIME_SETTINGS_FILE", str(directory / "runtime.json")
            ):
                public = app.test_client()
                health = public.get("/health")
                assert health.status_code == 200
                assert health.get_json()["status"] == "healthy"
                assert health.get_json()["ingestion"] == "disabled"
                assert public.get("/api/system/status").status_code == 401

                viewer = app.test_client()
                login_as(viewer, directory, "viewer", "health-viewer")
                assert viewer.get("/api/system/status").status_code == 403

                admin = app.test_client()
                login_as(admin, directory, "admin", "health-admin")
                response = admin.get("/api/system/status")
                assert response.status_code == 200
                status = response.get_json()
                assert status["agent"]["status"] == "healthy"
                assert status["alert_store"] == {"status": "healthy", "alerts": 1}
                assert status["database"]["check"] == "ok"
                assert status["ai"]["available"] is True
                assert status["ai"]["last_successful_enrichment"] == "2026-08-14T01:02:03Z"
                assert status["queue"] == {"busy": True, "backlog": 0}
                assert status["sensors"]["nids"]["enabled"] is True
                assert status["sensors"]["honeypot"]["enabled"] is False

                config.WINDOWS_COLLECTOR_SECRET = "collector-test-secret"
                assert public.get("/health").get_json()["ingestion"] == "offline"
                record_collector_heartbeat("win-lab")
                idle_health = public.get("/health").get_json()
                assert idle_health["status"] == "healthy"
                assert idle_health["ingestion"] == "idle"
                record_collector_heartbeat("win-lab", endpoint_available=False)
                assert public.get("/health").get_json()["ingestion"] == "endpoint_unavailable"
                config.WINDOWS_COLLECTOR_SECRET = ""

                heartbeat = json.loads(Path(config.AGENT_HEARTBEAT_FILE).read_text(encoding="utf-8"))
                heartbeat["timestamp"] = (
                    datetime.now(timezone.utc) - timedelta(minutes=1)
                ).isoformat().replace("+00:00", "Z")
                Path(config.AGENT_HEARTBEAT_FILE).write_text(json.dumps(heartbeat), encoding="utf-8")
                assert public.get("/health").get_json()["status"] == "degraded"

                config.SQLITE_ALERT_DB = str(directory / "missing.db")
                assert public.get("/health").status_code == 503

            analyst = AIAnalyst(OllamaCloudProvider("test-key"))
            with patch.object(
                analyst, "_enrich", return_value={"ai_analysis": {"analysed_at": "2026-08-14T02:00:00Z"}}
            ):
                analyst._safe_enrich({})
            assert analyst.health_status()["available"] is True
            with (
                patch.object(analyst, "_enrich", side_effect=RuntimeError("offline")),
                patch("src.ai_analyst.logger.warning"),
            ):
                analyst._safe_enrich({})
            assert analyst.health_status()["available"] is False
            analyst.shutdown()
        finally:
            (
                config.AGENT_HEARTBEAT_FILE,
                config.SQLITE_ALERT_DB,
                config.DASHBOARD_USERS_FILE,
                config.WINDOWS_COLLECTOR_SECRET,
            ) = original


if __name__ == "__main__":
    test_health()
    print("M8.3 health and diagnostics passed")
