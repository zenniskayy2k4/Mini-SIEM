import os

# --- PATH CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Log file input
LOG_FILE_TO_WATCH = os.path.join(BASE_DIR, 'logs', 'auth.log')
RESPONSE_LOG_FILE = os.path.join(BASE_DIR, 'data', 'incident_responses.log')

# Alert output file
OUTPUT_ALERT_FILE = os.path.join(BASE_DIR, 'data', 'siem_alerts.json')
RESPONSE_LOG_FILE = os.path.join(BASE_DIR, 'data', 'incident_responses.log')

# --- ENGINE SETTINGS ---
CORRELATION_WINDOW_MINUTES = 5
ANOMALY_THRESHOLD = 3.0       
ML_ANOMALY_THRESHOLD = -0.6   

# --- DASHBOARD SETTINGS ---
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000

# ML Model Paths
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'iso_forest.pkl')
SCALER_PATH = os.path.join(BASE_DIR, 'models', 'scaler.pkl')
# ELK Configuration
ELK_ENABLED = True # Set False nếu không chạy ELK
ELK_URL = "http://localhost:9200/siem-logs/_doc"

# --- SIGNATURES ---
SIGNATURES = [
    {
        "name": "SSH Brute Force Attempt",
        "pattern": r"Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        "severity": "HIGH",
        "mitre_id": "T1110.001",
        "description": "Multiple failed login attempts detected via SSH.",
        "extract_ip": True
    },
    {
        "name": "Sudo Privilege Escalation",
        "pattern": r"COMMAND=.*/usr/bin/su|COMMAND=.*/usr/bin/sudo",
        "severity": "MEDIUM",
        "mitre_id": "T1548.003",
        "description": "User attempted to execute a command with elevated privileges.",
        "extract_ip": False
    },
    {
        "name": "New User Creation",
        "pattern": r"new user: name=(\w+)",
        "severity": "INFO",
        "mitre_id": "T1136.001",
        "description": "A new local user account was created.",
        "extract_ip": False
    }
]