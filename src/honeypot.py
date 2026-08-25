import socket
import threading

from src.alert_pipeline import handle_detection_exception, persist_and_enrich
from src.alert_schema import build_alert
from src.elk_forwarder import ELKForwarder
from config import config

class MiniHoneypot:
    def __init__(
        self, port: int = 2222, bind_ip: str = "0.0.0.0",
        ai_analyst=None, responder=None, geoip_service=None,
        abuseipdb_service=None, virustotal_service=None,
    ):
        self.port = port
        self.bind_ip = bind_ip
        self.ai_analyst = ai_analyst
        self.responder = responder
        self.geoip_service = geoip_service
        self.abuseipdb_service = abuseipdb_service
        self.virustotal_service = virustotal_service
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
        )
        if handle_detection_exception(alert):
            client_socket.close()
            return
        if self.responder:
            alert = self.responder.handle_incident(alert)

        try:
            self.elk.send_alert(alert)
            persist_and_enrich(
                alert, self.ai_analyst, self.geoip_service, self.abuseipdb_service,
                self.virustotal_service,
            )

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
