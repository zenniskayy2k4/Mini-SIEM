import time, os
import threading
import json

from watchdog.observers.polling import PollingObserver as Observer
from config import config
from src.detector import ThreatDetector
from src.correlator import AlertCorrelator
from src.response import IncidentResponder
from src.handler import LogHandler
from src.network_monitor import NetworkMonitor
from src.honeypot import MiniHoneypot

RUNTIME_SETTINGS_FILE = os.path.join(config.BASE_DIR, "data", "runtime_settings.json")

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
    detector = ThreatDetector(config.SIGNATURES)
    correlator = AlertCorrelator(config.CORRELATION_WINDOW_MINUTES)
    responder = IncidentResponder()

    # --- HIDS: file watcher ---
    observer = Observer()
    event_handler = LogHandler(config.LOG_FILE_TO_WATCH, detector, correlator, responder)

    log_dir = os.path.dirname(config.LOG_FILE_TO_WATCH) or "."
    observer.schedule(event_handler, path=log_dir, recursive=False)

    observer.start()

    # Managed modules
    nids = None
    hp = None

    def start_nids():
        nonlocal nids
        if nids is not None:
            return
        nids = NetworkMonitor(correlator=correlator, responder=responder)
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
    last_mtime = 0.0

    def settings_watcher():
        nonlocal last_mtime
        while not stop_event.is_set():
            try:
                mtime = os.path.getmtime(RUNTIME_SETTINGS_FILE) if os.path.exists(RUNTIME_SETTINGS_FILE) else 0.0
                if mtime != last_mtime:
                    last_mtime = mtime
                    _apply_runtime_settings()

                    if getattr(config, "NIDS_ENABLED", False):
                        start_nids()
                    else:
                        stop_nids()

                    if getattr(config, "HONEYPOT_ENABLED", False):
                        start_honeypot()
                    else:
                        stop_honeypot()
            except Exception:
                pass
            time.sleep(1.0)

    threading.Thread(target=settings_watcher, daemon=True).start()

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

if __name__ == "__main__":
    main()