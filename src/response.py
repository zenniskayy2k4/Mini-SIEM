import json, os
from config import config

class IncidentResponder:
    """
    Handles incident response workflow: Analyze, Respond, Log.
    Follows NIST framework: Detection (already done), Analysis (severity check), Response (mitigation suggestions).
    """
    def __init__(self):
        pass

    def handle_incident(self, alert):
        """
        Processes alert for response: Logs, notifies, suggests mitigation.
        Returns updated alert with response actions.
        """
        if alert["severity"] in ["HIGH", "CRITICAL"]:
            # Analysis: Add notes
            alert["analysis"] = "Incident analyzed: Potential escalation detected."

            # Response: Simulate mitigation
            mitigation = self._generate_mitigation(alert)
            alert["mitigation"] = mitigation
            alert["mitigation_command"] = mitigation  # ensure UI + logs consistent

            # Notify and log
            self._notify(alert)
            self._log_response(alert)

        return alert

    def _generate_mitigation(self, alert):
        """
        Generates response suggestions based on alert type.
        """
        ip = alert.get("ip_address", "Unknown")
        name = alert.get("alert_name", "")

        if "Brute Force" in name or "Honeypot" in name or "Port Scanning" in name:
            return f"iptables -A INPUT -s {ip} -j DROP"
        elif "Sudo" in name:
            return "Manual Investigation (review sudoers, lock the offending user account)"
        return "Manual Investigation"

    def _notify(self, alert):
        """
        Simulates notification (print to console; extend to email/Slack).
        """
        print(f"\n[INCIDENT RESPONSE] Notification: {alert['alert_name']} - Severity: {alert['severity']}")
        print(f"Mitigation: {alert.get('mitigation', 'None')}")

    def _log_response(self, alert):
        """
        Logs response to file.
        """
        os.makedirs(os.path.dirname(config.RESPONSE_LOG_FILE), exist_ok=True)
        
        mitigation = alert.get('mitigation_command', 'Manual Investigation Required')
        
        with open(config.RESPONSE_LOG_FILE, 'a') as f:
            log_entry = {
                "timestamp": alert["timestamp"],
                "trigger": alert["alert_name"],
                "mitigation": mitigation
            }
            f.write(json.dumps(log_entry) + "\n")
            
        print(f"   [>>>] AUTO-RESPONSE ACTION: {mitigation}")