import logging

from src.alert_store import upsert_alert
from src.notifier import notification_service
from src.threat_intel import GEOIP_FIELDS


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


def persist_and_enrich(alert: dict, ai_analyst=None, geoip_service=None) -> dict:
    """Persist every alert before dispatching optional asynchronous enrichment."""
    upsert_alert(alert)
    if geoip_service and alert.get("ip_address"):
        future = geoip_service.lookup_async("ip", alert["ip_address"])
        future.add_done_callback(lambda completed: _persist_geoip(alert, completed))
    if (
        ai_analyst
        and alert.get("severity") in {"HIGH", "CRITICAL"}
        and not alert.get("suppressed_count")
        and not alert.get("deduplicated_events")
    ):
        ai_analyst.enrich_async(alert, on_complete=_persist_and_notify)
    notification_service.notify(alert)
    return alert
