import logging

from src.alert_store import upsert_alert
from src.notifier import notification_service
from src.threat_intel import ABUSEIPDB_FIELDS, GEOIP_FIELDS


logger = logging.getLogger(__name__)


def _persist_and_notify(alert):
    upsert_alert(alert)
    notification_service.notify(alert)


def _persist_geoip(alert, future):
    try:
        result = future.result()
        alert["geoip_lookup"] = {
            key: value for key, value in result.as_dict().items() if key != "data"
        }
        if result.status == "ok":
            alert["geoip"] = {key: result.data.get(key) for key in GEOIP_FIELDS}
        upsert_alert(alert)
    except Exception as exc:
        logger.warning("GeoIP enrichment failed for %s: %s", alert.get("alert_id"), exc)


def _dispatch_ai(alert, ai_analyst):
    if (
        ai_analyst
        and alert.get("severity") in {"HIGH", "CRITICAL"}
        and not alert.get("suppressed_count")
        and not alert.get("deduplicated_events")
    ):
        ai_analyst.enrich_async(alert, on_complete=_persist_and_notify)


def _persist_abuseipdb(alert, future, ai_analyst):
    try:
        result = future.result()
        summary = {
            "ioc_type": result.ioc_type,
            "ioc": result.ioc,
            "provider": result.provider,
            "status": result.status,
            "checked_at": result.checked_at,
            "cached": result.cached,
            "attempts": result.attempts,
            "duration_ms": result.duration_ms,
        }
        if result.status == "ok":
            summary.update({key: result.data.get(key) for key in ABUSEIPDB_FIELDS})
        if result.error:
            summary["error"] = result.error
        alert.setdefault("threat_intel", {})["abuseipdb"] = summary
        upsert_alert(alert)
    except Exception as exc:
        logger.warning("AbuseIPDB enrichment failed for %s: %s", alert.get("alert_id"), exc)
    finally:
        _dispatch_ai(alert, ai_analyst)


def persist_and_enrich(
    alert: dict, ai_analyst=None, geoip_service=None, abuseipdb_service=None,
) -> dict:
    """Persist every alert before dispatching optional asynchronous enrichment."""
    upsert_alert(alert)
    if geoip_service and alert.get("ip_address"):
        future = geoip_service.lookup_async("ip", alert["ip_address"])
        future.add_done_callback(lambda completed: _persist_geoip(alert, completed))
    if abuseipdb_service and alert.get("ip_address"):
        future = abuseipdb_service.lookup_async("ip", alert["ip_address"])
        future.add_done_callback(
            lambda completed: _persist_abuseipdb(alert, completed, ai_analyst)
        )
    else:
        _dispatch_ai(alert, ai_analyst)
    notification_service.notify(alert)
    return alert
