from collections import defaultdict
from datetime import datetime, timedelta, timezone
from config import config

class AlertCorrelator:
    """
    Correlates alerts by IP and time window to detect multi-event campaigns.
    """
    def __init__(self, window_minutes):
        self.window_minutes = window_minutes
        self.alert_buffers = defaultdict(list)

    def correlate(self, alert):
        """
        Adds alert to buffer, cleans old ones, and checks for escalation.
        Returns correlated alert if threshold met, else original.
        """
        if not alert.get("ip_address") or alert["ip_address"] == "N/A":
            return alert
        
        ip = alert["ip_address"]
        current_time = datetime.fromisoformat(alert["timestamp"].rstrip("Z"))

        # Clean buffer
        cutoff = current_time - timedelta(minutes=self.window_minutes)
        self.alert_buffers[ip] = [a for a in self.alert_buffers[ip] if 
                                  datetime.fromisoformat(a["timestamp"].rstrip("Z")) >= cutoff]

        # Add alert
        self.alert_buffers[ip].append(alert)

        # Escalate if >3 events
        if len(self.alert_buffers[ip]) >= 3 and "Brute Force" in alert["alert_name"]:
            correlated_alert = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "alert_name": "Correlated Brute Force Campaign",
                "severity": "CRITICAL",
                "mitre_attck_id": "T1110 (Campaign)",
                "description": f"Attack Campaign: {len(self.alert_buffers[ip])} attempts from {ip} in {self.window_minutes} mins.",
                "correlated_events": [a["raw_log"] for a in self.alert_buffers[ip]],
                "status": "ESCALATED",
                "ip_address": ip,
                "mitigation_command": f"iptables -A INPUT -s {ip} -j DROP",
            }
            
            # Clear buffer after escalation
            self.alert_buffers[ip] = []
            
            return correlated_alert
        return alert