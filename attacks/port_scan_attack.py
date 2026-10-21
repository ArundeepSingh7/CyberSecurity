"""
For educational use against your own local test environment only.
Port scan simulation using plain Python sockets — no external tool needed.
"""
import json
import socket
import threading
import time
import urllib.request
from attacks.attack_base import BaseAttack

# Common ports to probe (plus a few that will be closed)
_SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
               3306, 3389, 5000, 5432, 8080, 8443, 9200, 27017]


# Inheritance
class PortScanAttack(BaseAttack):
    """Simulates a port scan by probing common ports with short-timeout sockets."""

    def __init__(self, target: str = "127.0.0.1", port: int = 5000, duration: int = 10) -> None:
        """Initialise port scanner."""
        super().__init__(target=target, port=port, duration=duration)

    def _report_probe(self, port: int) -> None:
        """Non-blocking telemetry fallback for environments without Npcap driver."""
        def _post():
            try:
                payload = json.dumps({"dst_port": port, "fwd_pkts": 1, "syn": 1, "duration_us": 500.0, "pkt_len": 40, "attack_type": "PortScan"}).encode("utf-8")
                req = urllib.request.Request("http://127.0.0.1:8000/live/ingest", data=payload, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=0.2)
            except Exception:
                pass
        threading.Thread(target=_post, daemon=True).start()

    # Polymorphism
    def run(self) -> None:
        """Scan ports in a loop for `duration` seconds, printing each result."""
        print(f"[PortScan] Starting scan on {self.target} for {self.duration}s")
        print(f"[PortScan] Probing {len(_SCAN_PORTS)} ports: {_SCAN_PORTS}")
        start = time.time()
        iteration = 0
        while time.time() - start < self.duration:
            iteration += 1
            print(f"\n[PortScan] Sweep #{iteration}")
            for p in _SCAN_PORTS:
                status = "CLOSED"
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.15)
                        result = s.connect_ex((self.target, p))
                        status = "OPEN" if result == 0 else "CLOSED"
                except OSError:
                    pass
                print(f"  Port {p:5d}: {status}")
                self._report_probe(p)
            # short pause between sweeps
            time.sleep(0.5)
        print(f"\n[PortScan] Attack finished after {self.duration}s.")
