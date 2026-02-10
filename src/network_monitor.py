import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

from config import config
from src.elk_forwarder import ELKForwarder
from src.alert_store import append_alert

# Import scapy lazily to avoid import-time issues when not enabled
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP

class NetworkMonitor:
    """
    NIDS sensor:
      - SYN scan heuristic (many SYN within a time window)
      - ARP spoof heuristic (MAC changes for same IP)
    Emits alerts using the same JSON-lines file as HIDS.
    """
    def __init__(self, correlator=None, responder=None):
        self.correlator = correlator
        self.responder = responder
        self.elk = ELKForwarder()

        self._lock = threading.Lock()

        # SYN tracking: ip -> deque[timestamps]
        self._syn_times = defaultdict(deque)

        # ARP tracking: psrc_ip -> (last_hwsrc, last_seen_ts, change_count_window)
        self._arp_last_mac = {}
        self._arp_changes = defaultdict(deque)  # ip -> deque[timestamps]

        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def _utc_now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _emit(self, alert: dict) -> None:
        alert["source_type"] = "NETWORK_SENSOR"

        # Optional: reuse responder/correlator pipeline if injected from main
        if self.correlator:
            alert = self.correlator.correlate(alert)
        if self.responder:
            alert = self.responder.handle_incident(alert)

        self.elk.send_alert(alert)
        append_alert(alert)

        print(f"\n[!] NETWORK ALERT: {alert['alert_name']} [{alert['severity']}] src={alert.get('ip_address')}")

    def _process_syn(self, src_ip: str, dst_port: int | None):
        now = time.time()
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
            alert = {
                "timestamp": self._utc_now_iso(),
                "alert_name": "Network Port Scanning (SYN flood heuristic)",
                "severity": "HIGH",
                "mitre_attck_id": "T1046",
                "description": f"High volume of TCP SYNs detected: {count}/{window}s (possible port scan).",
                "raw_log": f"NETWORK_TRAFFIC src={src_ip} proto=TCP flags=SYN dport={dst_port} count={count}/{window}s",
                "ip_address": src_ip,
                "mitigation_command": f"iptables -A INPUT -s {src_ip} -j DROP",
            }
            # Reset to reduce alert spam
            with self._lock:
                self._syn_times[src_ip].clear()
            self._emit(alert)

    def _process_arp_reply(self, psrc_ip: str, hwsrc: str):
        now = time.time()
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
                    alert = {
                        "timestamp": self._utc_now_iso(),
                        "alert_name": "ARP Spoofing Suspected (MAC flapping)",
                        "severity": "CRITICAL",
                        "mitre_attck_id": "T1557.002",
                        "description": f"Multiple MAC changes for IP {psrc_ip} within {window}s. Possible ARP cache poisoning.",
                        "raw_log": f"NETWORK_TRAFFIC proto=ARP op=reply psrc={psrc_ip} hwsrc={hwsrc}",
                        "ip_address": psrc_ip,
                        "mitigation_command": "Manual Investigation Required",
                    }
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