"""
Alert Correlator:
  1. Generic campaign detection — any alert type, not just "Brute Force"
  2. Multi-stage attack chain detection — recognises MITRE tactic progressions
  3. Cross-source correlation — same IP seen in HIDS + NIDS + HONEYPOT
  4. Per-category configurable thresholds
  5. Sliding-window cleanup per IP (no memory leak on long uptime)
  6. Deduplicated escalation — prevents spam from same campaign re-triggering
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional
import logging
import threading

from src.alert_schema import build_alert

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MITRE Tactic categorisation
# Maps alert_name substrings → MITRE tactic tier (for chain detection)
# ---------------------------------------------------------------------------
TACTIC_MAP: dict[str, str] = {
    # Reconnaissance
    "Port Scanning":      "RECON",
    "Network Scan":       "RECON",
    "ARP Spoof":          "RECON",

    # Initial Access / Discovery via honeypot
    "Honeypot":           "INITIAL_ACCESS",

    # Credential Access
    "Brute Force":        "CRED_ACCESS",
    "Failed password":    "CRED_ACCESS",
    "Invalid user":       "CRED_ACCESS",
    "LSASS":              "CRED_ACCESS",

    # Privilege Escalation
    "Sudo":               "PRIV_ESC",
    "Privilege Escal":    "PRIV_ESC",

    # Execution / Anomaly
    "AI Anomaly":         "EXECUTION",
    "Semantic Anomaly":   "EXECUTION",
    "Structural Anomaly": "EXECUTION",
    "PowerShell":         "EXECUTION",
    "LOLBin":             "EXECUTION",
    "Office Child":       "EXECUTION",
}

# Ordered stages for kill-chain progression check
KILL_CHAIN_ORDER = ["RECON", "INITIAL_ACCESS", "CRED_ACCESS", "PRIV_ESC", "EXECUTION"]

# ---------------------------------------------------------------------------
# Campaign thresholds  (alert_category → min_events_to_escalate)
# ---------------------------------------------------------------------------
CAMPAIGN_THRESHOLDS: dict[str, int] = {
    "CRED_ACCESS":    3,   # 3 brute-force events → campaign
    "RECON":          5,   # 5 scans → campaign
    "EXECUTION":      2,   # 2 AI anomalies → campaign
    "HONEYPOT":       1,   # any honeypot hit = instant campaign (high fidelity)
    "PRIV_ESC":       2,
    "DEFAULT":        4,
}

# ---------------------------------------------------------------------------
# Cross-source bonus: if IP seen in N distinct sources → multiply severity
# ---------------------------------------------------------------------------
SOURCE_PRIORITY = {"HONEYPOT": 3, "NIDS": 2, "WINDOWS_EVENT": 2, "HIDS_LOG": 1}
CORRELATION_RULES = {
    "DET-CORR-001": {
        "id": "DET-CORR-001",
        "title": "Cross-Sensor Correlated Threat",
        "severity": "CRITICAL",
        "source_type": "CORRELATION",
        "rule_source": "native",
        "mitre": {"tactic": "Multiple", "technique": "T1078"},
    },
}


def _classify_alert(alert_name: str) -> str:
    """Return tactic category string for an alert name."""
    for keyword, tactic in TACTIC_MAP.items():
        if keyword.lower() in alert_name.lower():
            return tactic
    return "DEFAULT"


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts[:-1] + "+00:00" if ts.endswith("Z") else ts)


# ---------------------------------------------------------------------------
# AlertCorrelator
# ---------------------------------------------------------------------------
class AlertCorrelator:
    """
    Correlates alerts by IP and time window to detect:
      - Volume-based campaigns (many events of the same type from one IP)
      - Multi-stage attack chains (RECON → CRED_ACCESS → PRIV_ESC)
      - Cross-source events (same IP triggering HIDS + NIDS + HONEYPOT)
    """

    def __init__(self, window_minutes: int = 5):
        self.window_minutes = window_minutes

        # ip → list of recent alert dicts (sliding window)
        self._buffers: defaultdict[str, list] = defaultdict(list)

        # ip → set of source_types seen (cross-source tracking)
        self._sources_seen: defaultdict[str, set] = defaultdict(set)

        # ip → set of tactic categories seen (kill-chain tracking)
        self._tactics_seen: defaultdict[str, list] = defaultdict(list)

        # Prevent duplicate escalation: (ip, campaign_type) → last_escalation_ts
        self._escalated: dict[tuple, datetime] = {}
        self._active_alerts: dict[tuple, dict] = {}
        self._lock = threading.Lock()

        # Escalation cooldown (avoid spamming same campaign alert)
        self._escalation_cooldown_minutes = window_minutes

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def correlate(self, alert: dict) -> dict:
        with self._lock:
            return self._correlate(alert)

    def _correlate(self, alert: dict) -> dict:
        """
        Process one alert through the correlation engine.
        Returns either the original alert (no correlation yet) or a new
        escalated campaign/chain alert dict.
        """
        ip = alert.get("ip_address", "")
        if not ip or ip == "N/A":
            return alert   # Cannot correlate without a source IP

        current_time = _parse_ts(alert["timestamp"])
        self._evict_old(ip, current_time)

        # Register event
        for index, existing in enumerate(self._buffers[ip]):
            if existing.get("alert_id") == alert.get("alert_id"):
                self._buffers[ip][index] = alert
                break
        else:
            self._buffers[ip].append(alert)
        self._sources_seen[ip].add(alert.get("source_type", "UNKNOWN"))
        category = _classify_alert(alert.get("alert_name", ""))
        self._tactics_seen[ip].append(category)

        # --- Check 1: Multi-stage kill chain ---
        chain_alert = self._check_kill_chain(ip, current_time)
        if chain_alert:
            return chain_alert

        # --- Check 2: Cross-source (same IP, multiple sensors) ---
        cross_alert = self._check_cross_source(ip, current_time)
        if cross_alert:
            return cross_alert

        # --- Check 3: Volume-based campaign ---
        campaign_alert = self._check_campaign(ip, current_time, category)
        if campaign_alert:
            return campaign_alert

        return alert

    # ------------------------------------------------------------------
    # Check 1: Kill-chain progression
    # ------------------------------------------------------------------
    def _check_kill_chain(self, ip: str, now: datetime) -> Optional[dict]:
        """
        Detect ordered progression through MITRE tactic stages.
        E.g. RECON → CRED_ACCESS → PRIV_ESC within the window.
        """
        seen_tactics = set(self._tactics_seen[ip])
        matched_stages = [s for s in KILL_CHAIN_ORDER if s in seen_tactics]

        # Need at least 3 distinct stages to be meaningful
        if len(matched_stages) < 3:
            return None

        escalation_key = (ip, "KILL_CHAIN")
        active = self._active_alert(escalation_key, now, self._buffers[ip])
        if active:
            return active

        chain_str = " → ".join(matched_stages)
        logger.info(f"[Correlator] Kill chain detected: {ip}  {chain_str}")

        result = build_alert(
            alert_name="Multi-Stage Attack Chain Detected",
            severity="CRITICAL",
            source_type="CORRELATION",
            mitre_attck_id="TA0001→TA0006→TA0004 (Kill Chain)",
            description=(
                f"Attack chain from {ip}: {chain_str}  "
                f"({len(self._buffers[ip])} total events in {self.window_minutes} min)"
            ),
            raw_log=None,
            ip_address=ip,
            event_count=len(self._buffers[ip]),
            correlation_key=f"KILL_CHAIN|{ip}",
            correlated_events=[a.get("raw_log") for a in self._buffers[ip]],
            sources=sorted(self._sources_seen[ip]),
            chain_stages=matched_stages,
            trigger_event_count=len(self._buffers[ip]),
        )
        self._register_escalation(escalation_key, now, result)
        return result

    # ------------------------------------------------------------------
    # Check 2: Cross-source correlation
    # ------------------------------------------------------------------
    def _check_cross_source(self, ip: str, now: datetime) -> Optional[dict]:
        """
        If the same IP appears in 2+ distinct sensor sources (e.g. HIDS_LOG +
        NIDS), that's a high-fidelity indicator of a real attack.
        """
        sources = self._sources_seen[ip]
        if len(sources) < 2:
            return None

        # Weight sources by priority
        total_weight = sum(SOURCE_PRIORITY.get(s, 1) for s in sources)
        if total_weight < 4:   # e.g. HIDS(1) + NIDS(2) = 3 → not yet
            return None

        escalation_key = (ip, "CROSS_SOURCE")
        active = self._active_alert(escalation_key, now, self._buffers[ip])
        if active:
            active["sources"] = sorted(sources)
            return active

        logger.info(
            "[Correlator] Cross-source alert: %s  sources=%s", ip, sorted(sources)
        )

        rule = CORRELATION_RULES["DET-CORR-001"]
        result = build_alert(
            rule_id=rule["id"],
            alert_name=rule["title"],
            severity=rule["severity"],
            source_type=rule["source_type"],
            mitre_attck_id=f"{rule['mitre']['technique']} (Multi-vector)",
            description=(
                f"IP {ip} detected across multiple sensors: {', '.join(sorted(sources))}. "
                f"High-fidelity indicator of targeted attack."
            ),
            raw_log=None,
            ip_address=ip,
            event_count=len(self._buffers[ip]),
            correlation_key=f"CROSS_SOURCE|{ip}",
            correlated_events=[a.get("raw_log") for a in self._buffers[ip]],
            sources=sorted(sources),
            trigger_event_count=len(self._buffers[ip]),
        )
        self._register_escalation(escalation_key, now, result)
        return result

    # ------------------------------------------------------------------
    # Check 3: Volume-based campaign
    # ------------------------------------------------------------------
    def _check_campaign(self, ip: str, now: datetime, category: str) -> Optional[dict]:
        """
        If more than N events of the same category arrive from one IP within the
        window, escalate to a Campaign alert. Threshold varies by category.
        """
        threshold = CAMPAIGN_THRESHOLDS.get(category, CAMPAIGN_THRESHOLDS["DEFAULT"])

        # Count matching-category events in the current buffer
        same_cat = [
            a for a in self._buffers[ip]
            if _classify_alert(a.get("alert_name", "")) == category
        ]

        # Special case: single honeypot hit is always a campaign
        if category == "INITIAL_ACCESS" and len(same_cat) >= 1:
            threshold = 1

        if len(same_cat) < threshold:
            return None

        escalation_key = (ip, f"CAMPAIGN_{category}")
        active = self._active_alert(escalation_key, now, same_cat)
        if active:
            active["description"] = (
                f"Campaign from {ip}: {active['event_count']} {category} events "
                f"in {self.window_minutes} min window."
            )
            return active

        campaign_name = {
            "CRED_ACCESS":   "Brute Force Campaign",
            "RECON":         "Reconnaissance Campaign",
            "EXECUTION":     "Suspicious Execution Campaign",
            "INITIAL_ACCESS":"Honeypot Interaction Logged",
            "PRIV_ESC":      "Privilege Escalation Pattern",
        }.get(category, f"{category} Campaign")

        mitre_ids = {
            "CRED_ACCESS":   "T1110 (Brute Force Campaign)",
            "RECON":         "T1046 (Network Scan Campaign)",
            "INITIAL_ACCESS":"T1046 (Honeypot)",
            "PRIV_ESC":      "T1548 (Privilege Escalation Pattern)",
            "EXECUTION":     "T1204 (Suspicious Execution)",
        }.get(category, "T1078")

        severity = "CRITICAL" if category in ("INITIAL_ACCESS", "PRIV_ESC") else "HIGH"

        logger.info(f"[Correlator] Campaign: {campaign_name}  ip={ip}  events={len(same_cat)}")

        result = build_alert(
            alert_name=campaign_name,
            severity=severity,
            source_type="CORRELATION",
            mitre_attck_id=mitre_ids,
            description=(
                f"Campaign from {ip}: {len(same_cat)} {category} events "
                f"in {self.window_minutes} min window."
            ),
            raw_log=None,
            ip_address=ip,
            event_count=len(same_cat),
            first_seen=same_cat[0]["timestamp"],
            last_seen=same_cat[-1]["timestamp"],
            correlation_key=f"CAMPAIGN_{category}|{ip}",
            correlated_events=[a.get("raw_log") for a in same_cat],
            trigger_event_count=len(same_cat),
        )
        result["deduplicated_events"] = 0
        self._register_escalation(escalation_key, now, result)
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _evict_old(self, ip: str, now: datetime) -> None:
        """Remove events outside the sliding window."""
        cutoff = now - timedelta(minutes=self.window_minutes)
        self._buffers[ip] = [
            a for a in self._buffers[ip]
            if _parse_ts(a["timestamp"]) >= cutoff
        ]
        self._sources_seen[ip] = {a.get("source_type", "UNKNOWN") for a in self._buffers[ip]}
        self._tactics_seen[ip] = [
            _classify_alert(a.get("alert_name", "")) for a in self._buffers[ip]
        ]

    def _is_in_cooldown(self, key: tuple, now: datetime) -> bool:
        last = self._escalated.get(key)
        if last is None:
            return False
        return (now - last) < timedelta(minutes=self._escalation_cooldown_minutes)

    def _active_alert(self, key: tuple, now: datetime, events: list[dict]) -> Optional[dict]:
        if not self._is_in_cooldown(key, now):
            self._active_alerts.pop(key, None)
            return None
        alert = self._active_alerts.get(key)
        if not alert:
            return None

        alert["event_count"] = sum(max(1, int(event.get("event_count") or 1)) for event in events)
        alert["last_seen"] = max(event["last_seen"] for event in events)
        alert["correlated_events"] = [event.get("raw_log") for event in events]
        alert["deduplicated_events"] = max(
            0, alert["event_count"] - alert.get("trigger_event_count", alert["event_count"])
        )
        return alert

    def _register_escalation(self, key: tuple, now: datetime, alert: dict) -> None:
        self._escalated[key] = now
        self._active_alerts[key] = alert
