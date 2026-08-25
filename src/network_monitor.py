import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

from config import config
from src.elk_forwarder import ELKForwarder
from src.alert_pipeline import (
    handle_alert_suppression, handle_detection_exception, persist_and_enrich,
)
from src.alert_schema import build_alert

# Import scapy lazily to avoid import-time issues when not enabled
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP

NIDS_RULES = {
    "DET-NET-001": {
        "id": "DET-NET-001",
        "title": "Network Port Scanning (SYN flood heuristic)",
        "severity": "HIGH",
        "source_type": "NIDS",
        "rule_source": "native",
        "mitre": {"tactic": "Reconnaissance", "technique": "T1046"},
    },
    "DET-NET-002": {
        "id": "DET-NET-002",
        "title": "ARP Spoofing Suspected (MAC flapping)",
        "severity": "CRITICAL",
        "source_type": "NIDS",
        "rule_source": "native",
        "mitre": {"tactic": "Credential Access", "technique": "T1557.002"},
    },
}


class NetworkMonitor:
    """
    NIDS sensor:
      - SYN scan heuristic (many SYN within a time window)
      - ARP spoof heuristic (MAC changes for same IP)
    Emits alerts using the same JSON-lines file as HIDS.
    """
    def __init__(
        self, correlator=None, responder=None, ai_analyst=None,
        geoip_service=None, abuseipdb_service=None, virustotal_service=None,
        emitter=None, clock=None,
    ):
        self.correlator = correlator
        self.responder = responder
        self.ai_analyst = ai_analyst
        self.geoip_service = geoip_service
        self.abuseipdb_service = abuseipdb_service
        self.virustotal_service = virustotal_service
        self._emitter = emitter
        self._clock = clock or time.time
        self.elk = None if emitter else ELKForwarder()

        self._lock = threading.Lock()

        # SYN tracking: ip -> deque[timestamps]
        self._syn_times = defaultdict(deque)

        # ARP tracking: psrc_ip -> (last_hwsrc, last_seen_ts, change_count_window)
        self._arp_last_mac = {}
        self._arp_changes = defaultdict(deque)  # ip -> deque[timestamps]

        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def _emit(self, alert: dict) -> None:
        if self._emitter is not None:
            self._emitter(alert)
            return
        if handle_detection_exception(alert):
            return
        if handle_alert_suppression(alert):
            return
        # Optional: reuse responder/correlator pipeline if injected from main
        if self.correlator:
            alert = self.correlator.correlate(alert)
            if handle_detection_exception(alert):
                return
            if handle_alert_suppression(alert):
                return
        if self.responder:
            alert = self.responder.handle_incident(alert)

        self.elk.send_alert(alert)
        persist_and_enrich(
            alert, self.ai_analyst, self.geoip_service, self.abuseipdb_service,
            self.virustotal_service,
        )

        print(f"\n[!] NETWORK ALERT: {alert['alert_name']} [{alert['severity']}] src={alert.get('ip_address')}")

    def _process_syn(self, src_ip: str, dst_port: int | None):
        now = self._clock()
        window = getattr(config, "NIDS_WINDOW_SECONDS", 5)
        threshold = getattr(config, "NIDS_SYN_THRESHOLD", 20)

        with self._lock:
            dq = self._syn_times[src_ip]
            dq.append(now)
            cutoff = now - window
            while dq and dq[0] < cutoff:
                dq.popleft()

            count = len(dq)

        if count >= threshold:
            rule = NIDS_RULES["DET-NET-001"]
            alert = build_alert(
                rule_id=rule["id"],
                alert_name=rule["title"],
                severity=rule["severity"],
                source_type=rule["source_type"],
                mitre_attck_id=rule["mitre"]["technique"],
                description=f"High volume of TCP SYNs detected: {count}/{window}s (possible port scan).",
                raw_log=f"NETWORK_TRAFFIC src={src_ip} proto=TCP flags=SYN dport={dst_port} count={count}/{window}s",
                ip_address=src_ip,
                event_count=count,
                window_seconds=window,
                correlation_key=f"Network Port Scanning|{src_ip}",
                timestamp=datetime.fromtimestamp(now, timezone.utc),
            )
            # Reset to reduce alert spam
            with self._lock:
                self._syn_times[src_ip].clear()
            self._emit(alert)

    def _process_arp_reply(self, psrc_ip: str, hwsrc: str):
        now = self._clock()
        window = getattr(config, "NIDS_ARP_WINDOW_SECONDS", 30)
        changes_threshold = getattr(config, "NIDS_ARP_CHANGES_THRESHOLD", 3)

        with self._lock:
            last = self._arp_last_mac.get(psrc_ip)
            if last is None:
                self._arp_last_mac[psrc_ip] = (hwsrc, now)
                return

            last_mac, _last_seen = last
            if last_mac.lower() != (hwsrc or "").lower():
                self._arp_last_mac[psrc_ip] = (hwsrc, now)
                dq = self._arp_changes[psrc_ip]
                dq.append(now)
                cutoff = now - window
                while dq and dq[0] < cutoff:
                    dq.popleft()

                if len(dq) >= changes_threshold:
                    rule = NIDS_RULES["DET-NET-002"]
                    alert = build_alert(
                        rule_id=rule["id"],
                        alert_name=rule["title"],
                        severity=rule["severity"],
                        source_type=rule["source_type"],
                        mitre_attck_id=rule["mitre"]["technique"],
                        description=f"Multiple MAC changes for IP {psrc_ip} within {window}s. Possible ARP cache poisoning.",
                        raw_log=f"NETWORK_TRAFFIC proto=ARP op=reply psrc={psrc_ip} hwsrc={hwsrc}",
                        ip_address=psrc_ip,
                        event_count=len(dq),
                        window_seconds=window,
                        correlation_key=f"ARP Spoofing Suspected|{psrc_ip}",
                        timestamp=datetime.fromtimestamp(now, timezone.utc),
                    )
                    dq.clear()
                    self._emit(alert)

    def _packet_callback(self, pkt):
        # SYN detection
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            # SYN set, ACK not set
            is_syn = (flags & 0x02) != 0 and (flags & 0x10) == 0
            if is_syn:
                src_ip = pkt[IP].src
                dport = int(pkt[TCP].dport) if pkt[TCP].dport is not None else None
                self._process_syn(src_ip, dport)

        # ARP spoof heuristic (reply)
        if pkt.haslayer(ARP) and int(pkt[ARP].op) == 2:
            psrc = str(pkt[ARP].psrc or "").strip()
            hwsrc = str(pkt[ARP].hwsrc or "").strip()
            if psrc and hwsrc:
                self._process_arp_reply(psrc, hwsrc)

    def start(self):
        """
        Blocking sniffer loop (run in a daemon thread from main.py).
        Requires admin/root + pcap driver on Windows.
        """
        from scapy.all import sniff

        bpf = getattr(config, "NIDS_BPF_FILTER", "tcp or arp")
        iface = getattr(config, "NIDS_INTERFACE", None)

        print(f"[*] NIDS started. iface={iface or 'default'} filter={bpf!r}")
        try:
            sniff(
                prn=self._packet_callback,
                store=0,
                filter=bpf,
                iface=iface,
                stop_filter=lambda _p: self._stop.is_set(),
            )
        except Exception as e:
            print(f"[!] NIDS error (need Admin/Root + Npcap on Windows?): {e}")
