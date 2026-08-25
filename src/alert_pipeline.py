import logging

from config import config
from src.alert_store import upsert_alert
from src.assets import enrich_alert_with_asset
from src.notifier import notification_service
from src.risk import score_alert_risk
from src.sqlite_store import SQLiteAssetRepository
from src.storage import alert_repository
from src.threat_intel import (
    ABUSEIPDB_FIELDS,
    GEOIP_FIELDS,
    VIRUSTOTAL_FIELDS,
    STIXIndicatorStore,
    summarize_stix_matches,
)


logger = logging.getLogger(__name__)
_STIX_STORE = STIXIndicatorStore(config.STIX_INDICATOR_FILE)
_ASSET_REPOSITORY = SQLiteAssetRepository()


def _score_alert(alert, asset_repository):
    asset = None
    try:
        if alert.get("asset_id"):
            asset = asset_repository.get_asset(alert["asset_id"])
    except Exception as exc:
        logger.warning("Asset risk lookup failed for %s: %s", alert.get("alert_id"), exc)
    score_alert_risk(alert, asset=asset, weights=config.RISK_WEIGHTS)


def handle_detection_exception(
    alert, asset_repository=_ASSET_REPOSITORY, exception_repository=None,
):
    """Persist exact exception matches as non-notifying telemetry."""
    exception_repository = exception_repository or alert_repository
    try:
        enrich_alert_with_asset(alert, asset_repository)
    except Exception as exc:
        alert["asset_id"] = None
        logger.warning("Asset enrichment failed for %s: %s", alert.get("alert_id"), exc)
    try:
        matched = exception_repository.match_detection_exception(alert)
    except Exception as exc:
        logger.warning("Detection exception lookup failed for %s: %s", alert.get("alert_id"), exc)
        return False
    if not matched:
        return False
    alert.update({
        "status": "EXCEPTED",
        "incident_id": None,
        "incident_status": None,
        "detection_exception_match": matched,
    })
    upsert_alert(alert)
    return True


def handle_alert_suppression(alert, suppression_repository=None):
    """Persist a grouped representative and stop repeated alert side effects."""
    suppression_repository = suppression_repository or alert_repository
    try:
        result = suppression_repository.apply_alert_suppression(alert)
    except Exception as exc:
        logger.warning("Alert suppression lookup failed for %s: %s", alert.get("alert_id"), exc)
        return False
    grouped = result["alert"]
    if grouped is not alert:
        alert.clear()
        alert.update(grouped)
    return result["suppressed"]


def _persist_and_notify(alert, asset_repository=_ASSET_REPOSITORY):
    if handle_detection_exception(alert, asset_repository):
        return
    if handle_alert_suppression(alert):
        return
    _score_alert(alert, asset_repository)
    upsert_alert(alert)
    notification_service.notify(alert)


def _persist_geoip(alert, future, asset_repository):
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
        _score_alert(alert, asset_repository)
        upsert_alert(alert)
    except Exception as exc:
        logger.warning("GeoIP enrichment failed for %s: %s", alert.get("alert_id"), exc)


def _dispatch_ai(alert, ai_analyst, asset_repository):
    if (
        ai_analyst
        and alert.get("severity") in {"HIGH", "CRITICAL"}
        and not alert.get("suppressed_count")
        and not alert.get("deduplicated_events")
    ):
        ai_analyst.enrich_async(
            alert,
            on_complete=lambda completed: _persist_and_notify(completed, asset_repository),
        )


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


def _persist_threat_intel(alert, future, fields, asset_repository):
    result = future.result()
    summary = _result_summary(result, fields)
    alert.setdefault("threat_intel", {})[result.provider] = summary
    _score_alert(alert, asset_repository)
    upsert_alert(alert)


def _persist_abuseipdb(alert, future, ai_analyst, asset_repository):
    try:
        _persist_threat_intel(alert, future, ABUSEIPDB_FIELDS, asset_repository)
    except Exception as exc:
        logger.warning("AbuseIPDB enrichment failed for %s: %s", alert.get("alert_id"), exc)
    finally:
        _dispatch_ai(alert, ai_analyst, asset_repository)


def _persist_virustotal(alert, future, asset_repository):
    try:
        _persist_threat_intel(alert, future, VIRUSTOTAL_FIELDS, asset_repository)
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


def _initial_threat_intel(
    alert, geoip_service, abuseipdb_service, virustotal_service, stix_store,
):
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
    try:
        stix_summary = summarize_stix_matches(stix_store.match_alert(alert)) if stix_store else None
        if stix_summary:
            intel["stix"] = stix_summary
    except Exception as exc:
        logger.warning("STIX matching failed for %s: %s", alert.get("alert_id"), exc)
    if not intel:
        alert.pop("threat_intel", None)
    return file_hash


def persist_and_enrich(
    alert: dict, ai_analyst=None, geoip_service=None, abuseipdb_service=None,
    virustotal_service=None, stix_store=_STIX_STORE, asset_repository=_ASSET_REPOSITORY,
) -> dict:
    """Persist every alert before dispatching optional asynchronous enrichment."""
    if handle_detection_exception(alert, asset_repository):
        return alert
    if handle_alert_suppression(alert):
        return alert
    file_hash = _initial_threat_intel(
        alert, geoip_service, abuseipdb_service, virustotal_service, stix_store,
    )
    _score_alert(alert, asset_repository)
    upsert_alert(alert)
    if geoip_service and alert.get("ip_address"):
        future = geoip_service.lookup_async("ip", alert["ip_address"])
        future.add_done_callback(
            lambda completed: _persist_geoip(alert, completed, asset_repository)
        )
    if abuseipdb_service and alert.get("ip_address"):
        future = abuseipdb_service.lookup_async("ip", alert["ip_address"])
        future.add_done_callback(
            lambda completed: _persist_abuseipdb(
                alert, completed, ai_analyst, asset_repository,
            )
        )
    else:
        _dispatch_ai(alert, ai_analyst, asset_repository)
    if virustotal_service and file_hash:
        future = virustotal_service.lookup_async(*file_hash)
        future.add_done_callback(
            lambda completed: _persist_virustotal(alert, completed, asset_repository)
        )
    notification_service.notify(alert)
    return alert
