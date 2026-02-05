import time, os
from watchdog.observers.polling import PollingObserver as Observer
from config import config
from src.detector import ThreatDetector
from src.correlator import AlertCorrelator
from src.response import IncidentResponder
from src.handler import LogHandler

def setup_environment():
    """Create necessary directories and files."""
    # Create logs and data directories if they don't exist
    os.makedirs(os.path.dirname(config.LOG_FILE_TO_WATCH), exist_ok=True)
    os.makedirs(os.path.dirname(config.OUTPUT_ALERT_FILE), exist_ok=True)

    # Create dummy log file for testing if not present
    if not os.path.exists(config.LOG_FILE_TO_WATCH):
        print(f"[+] Init: Creating dummy log file at {config.LOG_FILE_TO_WATCH}")
        with open(config.LOG_FILE_TO_WATCH, 'w') as f:
            f.write("--- Log Monitor Started ---\n")

def main():
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

    # Set up observer
    observer = Observer()    
    event_handler = LogHandler(config.LOG_FILE_TO_WATCH, detector, correlator, responder)

    log_dir = config.LOG_FILE_TO_WATCH.rsplit('/', 1)[0] or '.'
    observer.schedule(event_handler, path=log_dir, recursive=False)

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[+] Monitoring SIEM Agent stopped.")

    observer.join()

if __name__ == "__main__":
    main()