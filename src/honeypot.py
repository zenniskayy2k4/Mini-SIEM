import socket
import threading

from src.alert_store import upsert_alert
from src.alert_schema import build_alert
from src.elk_forwarder import ELKForwarder
from config import config

class MiniHoneypot:
    def __init__(self, port: int = 2222, bind_ip: str = "0.0.0.0"):
        self.port = port
        self.bind_ip = bind_ip
        self.elk = ELKForwarder()
        self._stop = threading.Event()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_ip, self.port))
        self._sock.listen(50)
        self._sock.settimeout(1.0)  # allow stop()

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass

    def handle_client(self, client_socket: socket.socket, addr):
        ip, src_port = addr[0], addr[1]

        alert = build_alert(
            alert_name="Honeypot Connection",
            severity="CRITICAL",
            source_type="HONEYPOT",
            mitre_attck_id="T1046",
            description=f"Connection to internal honeypot on port {self.port}. High-fidelity suspicious event.",
            raw_log=f"HONEYPOT src={ip}:{src_port} dport={self.port}",
            ip_address=ip,
            correlation_key=f"Honeypot Connection|{ip}",
            mitigation_command=f"iptables -A INPUT -s {ip} -j DROP",
        )

        try:
            self.elk.send_alert(alert)
            upsert_alert(alert)

            client_socket.sendall(b"Welcome\nLogin: ")
            _ = client_socket.recv(1024)
            client_socket.sendall(b"Access Denied.\n")
        except Exception:
            pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def start(self):
        print(f"[*] Honeypot active on {self.bind_ip}:{self.port}")
        while not self._stop.is_set():
            try:
                client, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
