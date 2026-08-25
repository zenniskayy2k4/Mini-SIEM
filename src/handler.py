from watchdog.events import FileSystemEventHandler
import json
from config import config
from src.elk_forwarder import ELKForwarder
from src.response import IncidentResponder
from src.correlator import AlertCorrelator
from src.alert_pipeline import handle_detection_exception, persist_and_enrich
import os

class LogHandler(FileSystemEventHandler):
    """
    File system event handler for real-time log monitoring.
    Integrates detection, correlation, response.
    """
    def __init__(
        self, file_path, detector, correlator=None, responder=None,
        geoip_service=None, abuseipdb_service=None, virustotal_service=None,
    ):
        self.file_path = file_path
        self.detector = detector
        self.geoip_service = geoip_service
        self.abuseipdb_service = abuseipdb_service
        self.virustotal_service = virustotal_service

        # Use instances provided by main(); fall back to defaults if not provided.
        self.correlator = correlator or AlertCorrelator(config.CORRELATION_WINDOW_MINUTES)
        self.responder = responder or IncidentResponder()

        self.file_handle = open(file_path, 'r', encoding="utf-8", errors="ignore")
        self.file_handle.seek(0, 2)  # Start from end
        self.elk = ELKForwarder()

    def on_modified(self, event):
        """
        Processes new log lines on file modification.
        """
        # Only react to the exact watched file (works cross-platform)
        src = os.path.normcase(os.path.abspath(event.src_path))
        watched = os.path.normcase(os.path.abspath(self.file_path))
        if src != watched:
            return

        new_lines = self.file_handle.readlines()
        for line in new_lines:
            if not line.strip():
                continue

            alert = self.detector.analyze(line)
            if alert:
                self._process_alert(alert)

    def _process_alert(self, alert):
        if handle_detection_exception(alert):
            return
        alert = self.correlator.correlate(alert)
        if handle_detection_exception(alert):
            return
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
        actions = alert.get("response_actions") or []
        action = actions[-1] if actions else None
        print(f" Response Action: {action or 'None'}")

        persist_and_enrich(
            alert, getattr(self.detector, "ai_analyst", None), self.geoip_service,
            self.abuseipdb_service, self.virustotal_service,
        )


class WindowsEventHandler(LogHandler):
    """Tail normalized Windows JSONL without replaying historical telemetry."""

    def on_modified(self, event):
        src = os.path.normcase(os.path.abspath(event.src_path))
        watched = os.path.normcase(os.path.abspath(self.file_path))
        if src != watched:
            return
        for line in self.file_handle.readlines():
            try:
                windows_event = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert = self.detector.analyze_windows_event(windows_event)
            if alert:
                self._process_alert(alert)
