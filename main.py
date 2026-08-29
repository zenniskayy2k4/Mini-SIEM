import time, os
import threading
import json
import logging

from watchdog.observers.polling import PollingObserver as Observer
from config import config
from src.detector import ThreatDetector
from src.correlator import AlertCorrelator
from src.response import IncidentResponder
from src.handler import LogHandler, WindowsEventHandler
from src.network_monitor import NetworkMonitor
from src.honeypot import MiniHoneypot
from src.ai_analyst import AIAnalyst
from src.ai_provider import build_ai_provider
from src.rules import load_detection_rules
from src.health import write_agent_heartbeat
from src.ingestion_queue import BoundedIngestionQueue
from src.threat_intel import (
    AbuseIPDBProvider,
    GeoIPProvider,
    STIXIndicatorStore,
    ThreatIntelService,
    VirusTotalProvider,
    pull_taxii_safe,
)

RUNTIME_SETTINGS_FILE = os.path.join(config.BASE_DIR, "data", "runtime_settings.json")

logging.basicConfig(level=logging.INFO, format="%(message)s")

def _load_runtime_settings() -> dict:
    try:
        if not os.path.exists(RUNTIME_SETTINGS_FILE):
            return {}
        with open(RUNTIME_SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _apply_runtime_settings():
    s = _load_runtime_settings()
    for k in [
        "NIDS_ENABLED",
        "HONEYPOT_ENABLED",
    ]:
        if k in s:
            setattr(config, k, s[k])

def setup_environment():
    """Create necessary directories and files."""
    # Create logs and data directories if they don't exist
    os.makedirs(os.path.dirname(config.LOG_FILE_TO_WATCH), exist_ok=True)
    os.makedirs(os.path.dirname(config.OUTPUT_ALERT_FILE), exist_ok=True)

    # Create dummy log file for testing if not present
    if not os.path.exists(config.LOG_FILE_TO_WATCH):
        print(f"[+] Init: Creating dummy log file at {config.LOG_FILE_TO_WATCH}")
        with open(config.LOG_FILE_TO_WATCH, 'w', encoding="utf-8") as f:
            f.write("--- Log Monitor Started ---\n")
    if not os.path.exists(config.WINDOWS_EVENT_FILE):
        open(config.WINDOWS_EVENT_FILE, "a", encoding="utf-8").close()

def main():
    setup_environment()
    _apply_runtime_settings()

    print("---------------------------------------------------------")
    print(" Pro Mini-SIEM / Blue Team Agent with ML, Response, Dashboard - Started")
    print(f"    Monitoring Log: {config.LOG_FILE_TO_WATCH}")
    print(f"    Alerts Output: {config.OUTPUT_ALERT_FILE}")
    print(f"    Dashboard: http://localhost:{config.DASHBOARD_PORT}")
    print(" Press Ctrl+C to stop.")
    print("---------------------------------------------------------")

    # Initialize modules
    ai_analyst = AIAnalyst(build_ai_provider(
        config.AI_PROVIDER,
        api_key=config.OLLAMA_API_KEY,
        base_url=config.OLLAMA_BASE_URL,
        model=config.OLLAMA_MODEL,
        local_base_url=config.OLLAMA_LOCAL_BASE_URL,
        local_model=config.OLLAMA_LOCAL_MODEL,
        fallback_name=config.AI_FALLBACK_PROVIDER,
    ))
    geoip_service = None
    if config.GEOIP_ENABLED:
        geoip_service = ThreatIntelService(
            GeoIPProvider(config.GEOIP_ENDPOINT),
            cache_ttl_seconds=config.GEOIP_CACHE_TTL_SECONDS,
            rate_limit_per_second=config.GEOIP_RATE_LIMIT_PER_SECOND,
            timeout_seconds=config.GEOIP_TIMEOUT_SECONDS,
            max_attempts=config.GEOIP_MAX_ATTEMPTS,
        )
    abuseipdb_service = None
    if config.ABUSEIPDB_API_KEY:
        abuseipdb_service = ThreatIntelService(
            AbuseIPDBProvider(config.ABUSEIPDB_API_KEY),
            cache_ttl_seconds=86400,
            rate_limit_per_second=0.2,
            timeout_seconds=3,
            max_attempts=2,
        )
    virustotal_service = None
    if config.VIRUSTOTAL_API_KEY:
        virustotal_service = ThreatIntelService(
            VirusTotalProvider(config.VIRUSTOTAL_API_KEY),
            cache_ttl_seconds=86400,
            rate_limit_per_second=4 / 60,
            timeout_seconds=3,
            max_attempts=2,
        )
    stix_store = STIXIndicatorStore(config.STIX_INDICATOR_FILE)
    if config.STIX_BUNDLE_FILE:
        try:
            with open(config.STIX_BUNDLE_FILE, "r", encoding="utf-8") as feed:
                stats = stix_store.import_bundle(json.load(feed), "offline")
            logging.info("[+] STIX offline bundle imported: %s", stats)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logging.warning("[-] STIX offline bundle import failed: %s", exc)

    detector = ThreatDetector(
        load_detection_rules(config.RULES_DIR, config.SIGNATURES, config.SIGMA_RULES_DIR),
        ai_analyst=ai_analyst,
    )
    
    correlator = AlertCorrelator(config.CORRELATION_WINDOW_MINUTES)
    responder = IncidentResponder()
    ingestion_queue = BoundedIngestionQueue(config.INGESTION_QUEUE_CAPACITY)

    # --- HIDS: file watcher ---
    observer = Observer()
    event_handler = LogHandler(
        config.LOG_FILE_TO_WATCH, detector, correlator, responder,
        geoip_service, abuseipdb_service, virustotal_service,
        ingestion_queue,
    )

    log_dir = os.path.dirname(config.LOG_FILE_TO_WATCH) or "."
    observer.schedule(event_handler, path=log_dir, recursive=False)
    windows_handler = WindowsEventHandler(
        config.WINDOWS_EVENT_FILE, detector, correlator, responder,
        geoip_service, abuseipdb_service, virustotal_service,
        ingestion_queue,
    )
    observer.schedule(
        windows_handler,
        path=os.path.dirname(config.WINDOWS_EVENT_FILE) or ".",
        recursive=False,
    )

    observer.start()

    # Managed modules
    nids = None
    hp = None

    def start_nids():
        nonlocal nids
        if nids is not None:
            return
        nids = NetworkMonitor(
            correlator=correlator, responder=responder, ai_analyst=ai_analyst,
            geoip_service=geoip_service,
            abuseipdb_service=abuseipdb_service,
            virustotal_service=virustotal_service,
            overload_state=lambda: ingestion_queue.status()["status"],
        )
        threading.Thread(target=nids.start, daemon=True).start()
        print("[+] NIDS enabled.")

    def stop_nids():
        nonlocal nids
        if nids is None:
            return
        nids.stop()
        nids = None
        print("[-] NIDS disabled.")

    def start_honeypot():
        nonlocal hp
        if hp is not None:
            return
        hp = MiniHoneypot(
            port=getattr(config, "HONEYPOT_PORT", 2222),
            bind_ip=getattr(config, "HONEYPOT_BIND_IP", "0.0.0.0"),
            ai_analyst=ai_analyst,
            responder=responder,
            geoip_service=geoip_service,
            abuseipdb_service=abuseipdb_service,
            virustotal_service=virustotal_service,
            overload_state=lambda: ingestion_queue.status()["status"],
        )
        threading.Thread(target=hp.start, daemon=True).start()
        print("[+] Honeypot enabled.")

    def stop_honeypot():
        nonlocal hp
        if hp is None:
            return
        hp.stop()
        hp = None
        print("[-] Honeypot disabled.")

    # Initial start based on current config
    if getattr(config, "NIDS_ENABLED", False):
        start_nids()
    if getattr(config, "HONEYPOT_ENABLED", False):
        start_honeypot()

    # Watch runtime settings changes
    stop_event = threading.Event()
    if config.TAXII_COLLECTION_URL:
        def taxii_feed_worker():
            while not stop_event.is_set():
                result = pull_taxii_safe(
                    stix_store,
                    config.TAXII_COLLECTION_URL,
                    config.TAXII_FEED_SOURCE,
                    config.TAXII_BEARER_TOKEN,
                )
                if result["status"] == "error":
                    logging.warning("[-] TAXII feed refresh failed")
                stop_event.wait(config.TAXII_PULL_INTERVAL_SECONDS)

        threading.Thread(target=taxii_feed_worker, daemon=True).start()
    last_settings_mtime = 0.0
    last_sigma_mtime = 0.0

    def settings_watcher():
        nonlocal last_settings_mtime, last_sigma_mtime
        while not stop_event.is_set():
            try:
                mtime = os.path.getmtime(RUNTIME_SETTINGS_FILE) if os.path.exists(RUNTIME_SETTINGS_FILE) else 0.0
                if mtime != last_settings_mtime:
                    last_settings_mtime = mtime
                    _apply_runtime_settings()

                    if getattr(config, "NIDS_ENABLED", False):
                        start_nids()
                    else:
                        stop_nids()

                    if getattr(config, "HONEYPOT_ENABLED", False):
                        start_honeypot()
                    else:
                        stop_honeypot()
                sigma_mtime = (
                    os.path.getmtime(config.SIGMA_RULE_STATE_FILE)
                    if os.path.exists(config.SIGMA_RULE_STATE_FILE) else 0.0
                )
                if sigma_mtime != last_sigma_mtime:
                    last_sigma_mtime = sigma_mtime
                    detector.signatures = load_detection_rules(
                        config.RULES_DIR, config.SIGNATURES, config.SIGMA_RULES_DIR,
                    )
                    logging.info("[+] Detection rules reloaded after Sigma lifecycle change")
            except Exception:
                pass
            time.sleep(1.0)

    threading.Thread(target=settings_watcher, daemon=True).start()

    def heartbeat_writer():
        while not stop_event.is_set():
            try:
                write_agent_heartbeat(
                    ai_analyst.health_status(), nids is not None, hp is not None,
                    ingestion_queue.status(),
                )
            except OSError as exc:
                logging.warning("[-] Agent heartbeat write failed: %s", exc)
            stop_event.wait(5)

    threading.Thread(target=heartbeat_writer, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        observer.stop()
        stop_nids()
        stop_honeypot()
        print("\n[+] Monitoring SIEM Agent stopped.")

    observer.join()
    ingestion_queue.shutdown()
    if geoip_service:
        geoip_service.close()
    if abuseipdb_service:
        abuseipdb_service.close()
    if virustotal_service:
        virustotal_service.close()

if __name__ == "__main__":
    main()
