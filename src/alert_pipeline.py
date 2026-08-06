from src.alert_store import upsert_alert


def persist_and_enrich(alert: dict, ai_analyst=None) -> dict:
    """Persist every alert and dispatch eligible alerts through the shared analyst."""
    upsert_alert(alert)
    if (
        ai_analyst
        and alert.get("severity") in {"HIGH", "CRITICAL"}
        and not alert.get("suppressed_count")
        and not alert.get("deduplicated_events")
    ):
        ai_analyst.enrich_async(alert, on_complete=upsert_alert)
    return alert
