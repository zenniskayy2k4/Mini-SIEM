import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from config import config
from src.alert_schema import utc_iso
from src.storage import alert_repository


HEARTBEAT_STALE_SECONDS = 15


def write_agent_heartbeat(ai: dict, nids_enabled: bool, honeypot_enabled: bool) -> None:
    path = Path(config.AGENT_HEARTBEAT_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": utc_iso(),
        "pid": os.getpid(),
        "sensors": {
            "nids_enabled": bool(nids_enabled),
            "honeypot_enabled": bool(honeypot_enabled),
        },
        "ai": ai,
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)


def _agent_status() -> dict:
    try:
        payload = json.loads(Path(config.AGENT_HEARTBEAT_FILE).read_text(encoding="utf-8"))
        timestamp = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
        age = max(0, (datetime.now(timezone.utc) - timestamp).total_seconds())
        payload.update(status="healthy" if age <= HEARTBEAT_STALE_SECONDS else "stale", age_seconds=round(age, 1))
        return payload
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {"status": "missing", "timestamp": None, "age_seconds": None, "sensors": {}, "ai": {}}


def _database_status() -> dict:
    path = Path(config.SQLITE_ALERT_DB)
    if not path.exists():
        return {"status": "unhealthy", "path": str(path), "check": "missing"}
    try:
        with sqlite3.connect(path, timeout=2) as connection:
            check = connection.execute("PRAGMA quick_check(1)").fetchone()[0]
            last_ai = connection.execute(
                "SELECT MAX(json_extract(payload_json, '$.ai_analysis.analysed_at')) FROM alerts"
            ).fetchone()[0]
        return {
            "status": "healthy" if check == "ok" else "unhealthy",
            "path": str(path),
            "check": check,
            "last_successful_ai_enrichment": last_ai,
        }
    except (OSError, sqlite3.Error) as exc:
        return {"status": "unhealthy", "path": str(path), "check": type(exc).__name__}


def build_system_status(settings: dict | None = None) -> dict:
    agent = _agent_status()
    database = _database_status()
    try:
        stats = alert_repository.stats()
        alert_store = {"status": "healthy", "alerts": stats.get("total", 0)}
    except Exception as exc:
        alert_store = {"status": "unhealthy", "error": type(exc).__name__}

    settings = settings or {}
    sensors = agent.get("sensors") or {}
    ai = agent.get("ai") or {}
    ai["last_successful_enrichment"] = (
        ai.get("last_successful_enrichment")
        or database.get("last_successful_ai_enrichment")
    )
    ai.setdefault("available", None)
    ai.setdefault("enabled", False)
    queue = {"busy": bool(ai.pop("busy", False)), "backlog": int(ai.pop("backlog", 0))}
    sensors = {
        "nids": {
            "configured": bool(settings.get("NIDS_ENABLED", False)),
            "enabled": sensors.get("nids_enabled"),
        },
        "honeypot": {
            "configured": bool(settings.get("HONEYPOT_ENABLED", False)),
            "enabled": sensors.get("honeypot_enabled"),
        },
    }
    status = "healthy"
    if database["status"] != "healthy" or alert_store["status"] != "healthy":
        status = "unhealthy"
    elif agent["status"] != "healthy" or ai.get("enabled") and ai.get("available") is False:
        status = "degraded"
    return {
        "status": status,
        "timestamp": utc_iso(),
        "dashboard": {"status": "healthy"},
        "agent": agent,
        "alert_store": alert_store,
        "database": database,
        "ai": ai,
        "queue": queue,
        "sensors": sensors,
    }
