import os

# --- PATH CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Log file input
LOG_FILE_TO_WATCH = os.path.join(BASE_DIR, 'logs', 'auth.log')

# Alert output file
OUTPUT_ALERT_FILE = os.path.join(BASE_DIR, 'data', 'siem_alerts.json')
SQLITE_ALERT_DB = os.path.join(BASE_DIR, 'data', 'mini_siem.db')
RESPONSE_LOG_FILE = os.path.join(BASE_DIR, 'data', 'incident_responses.log')
SQLITE_READ_ENABLED = os.getenv("SQLITE_READ_ENABLED", "true").lower() in {"1", "true", "yes"}
JSON_READ_FALLBACK_ENABLED = os.getenv("JSON_READ_FALLBACK_ENABLED", "true").lower() in {"1", "true", "yes"}
JSON_DUAL_WRITE_ENABLED = os.getenv("JSON_DUAL_WRITE_ENABLED", "true").lower() in {"1", "true", "yes"}

# --- ENGINE SETTINGS ---
CORRELATION_WINDOW_MINUTES = 5
ANOMALY_THRESHOLD = 3.0
ML_ANOMALY_THRESHOLD = -0.6
SSH_BRUTE_FORCE_THRESHOLD = 5
SSH_BRUTE_FORCE_WINDOW_SECONDS = 60

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
        "severity": "LOW",
        "mitre_id": "T1136.001",
        "description": "A new local user account was created.",
        "extract_ip": False
    }
]

# --- NIDS SETTINGS ---
NIDS_ENABLED = True
# On Windows, iface name depends on Npcap; leave None to auto-pick
NIDS_INTERFACE = None
NIDS_BPF_FILTER = "tcp or arp"

NIDS_WINDOW_SECONDS = 5
NIDS_SYN_THRESHOLD = 20

NIDS_ARP_WINDOW_SECONDS = 30
NIDS_ARP_CHANGES_THRESHOLD = 3

# --- HONEYPOT SETTINGS ---
HONEYPOT_ENABLED = True
HONEYPOT_BIND_IP = "0.0.0.0"
HONEYPOT_PORT = 2222

# --- GRAPH SETTINGS (Dashboard Context) ---
GRAPH_MAX_ALERTS = 500
GRAPH_AUTO_REFRESH = True
GRAPH_REFRESH_MS = 10000
GRAPH_INCLUDE_SOURCES = True
GRAPH_INCLUDE_CAMPAIGNS = True
