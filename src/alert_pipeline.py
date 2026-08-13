from src.alert_store import upsert_alert
from src.notifier import notification_service


def _persist_and_notify(alert):
    upsert_alert(alert)
    notification_service.notify(alert)


def persist_and_enrich(alert: dict, ai_analyst=None) -> dict:
    """Persist every alert and dispatch eligible alerts through the shared analyst."""
    upsert_alert(alert)
    if (
        ai_analyst
        and alert.get("severity") in {"HIGH", "CRITICAL"}
        and not alert.get("suppressed_count")
        and not alert.get("deduplicated_events")
    ):
        ai_analyst.enrich_async(alert, on_complete=_persist_and_notify)
    notification_service.notify(alert)
    return alert
