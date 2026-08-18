import logging

from src.alert_store import upsert_alert
from src.notifier import notification_service
from src.threat_intel import ABUSEIPDB_FIELDS, GEOIP_FIELDS, VIRUSTOTAL_FIELDS


logger = logging.getLogger(__name__)


def _persist_and_notify(alert):
    upsert_alert(alert)
    notification_service.notify(alert)


def _persist_geoip(alert, future):
    try:
        result = future.result()
        alert.setdefault("threat_intel", {})[result.provider] = _result_summary(
            result, GEOIP_FIELDS,
        )
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


def _result_summary(result, fields):
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
        summary.update({key: result.data.get(key) for key in fields})
    if result.error:
        summary["error"] = result.error
    return summary


def _persist_threat_intel(alert, future, fields):
    result = future.result()
    summary = _result_summary(result, fields)
    alert.setdefault("threat_intel", {})[result.provider] = summary
    upsert_alert(alert)


def _persist_abuseipdb(alert, future, ai_analyst):
    try:
        _persist_threat_intel(alert, future, ABUSEIPDB_FIELDS)
    except Exception as exc:
        logger.warning("AbuseIPDB enrichment failed for %s: %s", alert.get("alert_id"), exc)
    finally:
        _dispatch_ai(alert, ai_analyst)


def _persist_virustotal(alert, future):
    try:
        _persist_threat_intel(alert, future, VIRUSTOTAL_FIELDS)
    except Exception as exc:
        logger.warning("VirusTotal enrichment failed for %s: %s", alert.get("alert_id"), exc)


def _file_hash(alert):
    hashes = alert.get("hashes") if isinstance(alert.get("hashes"), dict) else {}
    hashes = {str(key).lower(): value for key, value in hashes.items()}
    for kind in ("sha256", "md5"):
        value = alert.get(kind) or hashes.get(kind)
        if value:
            return kind, value
    return None


def _initial_threat_intel(alert, geoip_service, abuseipdb_service, virustotal_service):
    intel = alert.setdefault("threat_intel", {})

    def state(provider, ioc_type, ioc, enabled):
        intel[provider] = {
            "ioc_type": ioc_type,
            "ioc": ioc,
            "provider": provider,
            "status": "pending" if enabled else "unavailable",
        }

    ip = alert.get("ip_address")
    if ip:
        state("ipwhois", "ip", ip, bool(geoip_service))
        state("abuseipdb", "ip", ip, bool(abuseipdb_service))
    file_hash = _file_hash(alert)
    if file_hash:
        state("virustotal", file_hash[0], file_hash[1], bool(virustotal_service))
    if not intel:
        alert.pop("threat_intel", None)
    return file_hash


def persist_and_enrich(
    alert: dict, ai_analyst=None, geoip_service=None, abuseipdb_service=None,
    virustotal_service=None,
) -> dict:
    """Persist every alert before dispatching optional asynchronous enrichment."""
    file_hash = _initial_threat_intel(
        alert, geoip_service, abuseipdb_service, virustotal_service,
    )
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
    if virustotal_service and file_hash:
        future = virustotal_service.lookup_async(*file_hash)
        future.add_done_callback(lambda completed: _persist_virustotal(alert, completed))
    notification_service.notify(alert)
    return alert
