import os

# --- PATH CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BASE_DIR, "config", "rules")
SIGMA_RULES_DIR = os.path.join(BASE_DIR, "config", "sigma")
SIGMA_RULE_STATE_FILE = os.path.join(BASE_DIR, "data", "sigma_rule_states.json")

# Log file input
LOG_FILE_TO_WATCH = os.path.join(BASE_DIR, 'logs', 'auth.log')

# Alert output file
OUTPUT_ALERT_FILE = os.path.join(BASE_DIR, 'data', 'siem_alerts.json')
SQLITE_ALERT_DB = os.path.join(BASE_DIR, 'data', 'mini_siem.db')
RESPONSE_LOG_FILE = os.path.join(BASE_DIR, 'data', 'incident_responses.log')
ANALYST_AUDIT_FILE = os.path.join(BASE_DIR, 'data', 'analyst_audit.jsonl')
AGENT_HEARTBEAT_FILE = os.path.join(BASE_DIR, 'data', 'agent_heartbeat.json')
ALERT_ARCHIVE_DIR = os.path.join(BASE_DIR, 'data', 'archive')
SQLITE_BACKUP_DIR = os.path.join(BASE_DIR, 'data', 'backups')
ALERT_RETENTION_DAYS = max(1, int(os.getenv("ALERT_RETENTION_DAYS", "90")))
LOG_ROTATE_MAX_BYTES = max(1024, int(os.getenv("LOG_ROTATE_MAX_BYTES", str(10 * 1024 * 1024))))
LOG_ROTATE_BACKUPS = max(1, int(os.getenv("LOG_ROTATE_BACKUPS", "5")))
SQLITE_READ_ENABLED = os.getenv("SQLITE_READ_ENABLED", "true").lower() in {"1", "true", "yes"}
JSON_READ_FALLBACK_ENABLED = os.getenv("JSON_READ_FALLBACK_ENABLED", "true").lower() in {"1", "true", "yes"}
JSON_DUAL_WRITE_ENABLED = os.getenv("JSON_DUAL_WRITE_ENABLED", "true").lower() in {"1", "true", "yes"}
RESPONSE_MODE = os.getenv("RESPONSE_MODE", "simulation").lower()
RESPONSE_TARGET_OS = os.getenv("RESPONSE_TARGET_OS", "linux").lower()
RESPONSE_APPROVAL_TIMEOUT_SECONDS = max(1, int(os.getenv("RESPONSE_APPROVAL_TIMEOUT_SECONDS", "900")))
RESPONSE_PROTECTED_TARGETS = {
    value.strip().lower()
    for value in os.getenv(
        "RESPONSE_PROTECTED_TARGETS",
        "localhost,127.0.0.1,::1,host.docker.internal,root,administrator,1,/,/etc,/usr,/bin,/sbin",
    ).split(",")
    if value.strip()
}
NOTIFICATION_WEBHOOK_URL = os.getenv("NOTIFICATION_WEBHOOK_URL", "").strip()
NOTIFICATION_WEBHOOK_FORMAT = os.getenv("NOTIFICATION_WEBHOOK_FORMAT", "generic").lower()
NOTIFICATION_TIMEOUT_SECONDS = max(1, int(os.getenv("NOTIFICATION_TIMEOUT_SECONDS", "3")))
NOTIFICATION_MAX_ATTEMPTS = min(3, max(1, int(os.getenv("NOTIFICATION_MAX_ATTEMPTS", "2"))))
NOTIFICATION_LOG_FILE = os.path.join(BASE_DIR, "data", "notification_audit.log")
WINDOWS_EVENT_FILE = os.getenv(
    "WINDOWS_EVENT_FILE", os.path.join(BASE_DIR, "data", "windows_events.jsonl")
)
WINDOWS_COLLECTOR_SECRET = os.getenv("WINDOWS_COLLECTOR_SECRET", "").strip()
DASHBOARD_USERS_FILE = os.path.join(BASE_DIR, "data", "dashboard_users.json")
DASHBOARD_SESSION_KEY_FILE = os.path.join(BASE_DIR, "data", "dashboard_session.key")
DASHBOARD_COOKIE_SECURE = os.getenv("DASHBOARD_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}

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
        "id": "DET-SSH-001",
        "title": "SSH Brute Force Attempt",
        "enabled": True,
        "severity": "HIGH",
        "source_type": "HIDS_LOG",
        "mitre": {"tactic": "Credential Access", "technique": "T1110.001"},
        "match": {
            "regex": r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        },
        "threshold": {
            "count": "SSH_BRUTE_FORCE_THRESHOLD",
            "window_seconds": "SSH_BRUTE_FORCE_WINDOW_SECONDS",
        },
        "description": "Repeated failed SSH logins from one source.",
        "extract_ip": True,
    },
    {
        "id": "DET-LNX-001",
        "title": "Sudo Privilege Escalation",
        "enabled": True,
        "severity": "MEDIUM",
        "source_type": "HIDS_LOG",
        "mitre": {"tactic": "Privilege Escalation", "technique": "T1548.003"},
        "match": {"contains_any": ["COMMAND=/usr/bin/su", "COMMAND=/usr/bin/sudo"]},
        "description": "User attempted to execute a command with elevated privileges.",
        "extract_ip": False
    },
    {
        "id": "DET-LNX-002",
        "title": "New User Creation",
        "enabled": True,
        "severity": "LOW",
        "source_type": "HIDS_LOG",
        "mitre": {"tactic": "Persistence", "technique": "T1136.001"},
        "match": {"contains": "new user: name="},
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
