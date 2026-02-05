from watchdog.events import FileSystemEventHandler
import json
from config import config
from src.elk_forwarder import ELKForwarder
from src.response import IncidentResponder
from src.correlator import AlertCorrelator

class LogHandler(FileSystemEventHandler):
    """
    File system event handler for real-time log monitoring.
    Integrates detection, correlation, response.
    """
    def __init__(self, file_path, detector, correlator=None, responder=None):
        self.file_path = file_path
        self.detector = detector

        # Use instances provided by main(); fall back to defaults if not provided.
        self.correlator = correlator or AlertCorrelator(config.CORRELATION_WINDOW_MINUTES)
        self.responder = responder or IncidentResponder()

        self.file_handle = open(file_path, 'r')
        self.file_handle.seek(0, 2)  # Start from end
        self.elk = ELKForwarder()

    def on_modified(self, event):
        """
        Processes new log lines on file modification.
        """
        if event.src_path.endswith("auth.log"):
            new_lines = self.file_handle.readlines()
            for line in new_lines:
                if not line.strip(): continue
                
                alert = self.detector.analyze(line)
                if alert:
                    alert = self.correlator.correlate(alert)
                    alert = self.responder.handle_incident(alert)
                    self.elk.send_alert(alert)
                    self._handle_alert(alert)

    def _handle_alert(self, alert):
        """
        Handles final alert: Console print and JSON append.
        """
        print(f"\n[!] THREAT DETECTED: {alert['alert_name']} [{alert['severity']}]")
        print(f" MITRE ID: {alert['mitre_attck_id']}")
        if "ml_anomaly_score" in alert:
            print(f" ML Anomaly Score: {alert['ml_anomaly_score']:.2f}")
        if "correlated_events" in alert:
            print(" Correlated Events:")
            for event in alert["correlated_events"]:
                print(f"  - {event}")
        else:
            print(f" Log: {alert['raw_log']}")
        print(f" Mitigation: {alert.get('mitigation', 'None')}")

        with open(config.OUTPUT_ALERT_FILE, 'a') as f:
            f.write(json.dumps(alert) + "\n")