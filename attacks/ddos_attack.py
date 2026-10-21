"""
For educational use against your own local test environment only.
DDoS simulation: rapidly sends requests from multiple simulated source IPs
to overwhelm the target with distributed-looking traffic.
"""
import time
import random
import threading
import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests as req
from attacks.attack_base import BaseAttack


# Inheritance
class DDoSAttack(BaseAttack):
    """Simulates a DDoS by flooding endpoints with concurrent requests from many simulated sources."""

    def __init__(
        self,
        target: str = "127.0.0.1",
        port: int = 5000,
        duration: int = 10,
        total_requests: int = 300,
        workers: int = 30,
    ) -> None:
        """Initialise DDoS attack parameters."""
        super().__init__(target=target, port=port, duration=duration)
        self.total_requests = total_requests
        self.workers = workers
        # Simulated source IPs for distributed appearance
        self._sim_ips = [f"10.0.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(20)]

    def _report_telemetry(self, src_ip: str, dst_port: int, fwd_pkts: int) -> None:
        """Send flow telemetry to IDS backend."""
        def _post():
            try:
                payload = json.dumps({
                    "dst_port": dst_port,
                    "src_ip": src_ip,
                    "src_port": random.randint(40000, 65000),
                    "fwd_pkts": fwd_pkts,
                    "bwd_pkts": 1,
                    "syn": 1,
                    "ack": 0,
                    "pkt_len": 60,
                    "duration_us": 50.0,  # Very short duration = high rate = DDoS pattern
                    "attack_type": "DDoS",
                }).encode("utf-8")
                r = urllib.request.Request(
                    "http://127.0.0.1:8000/live/ingest",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                urllib.request.urlopen(r, timeout=0.5)
            except Exception:
                pass
        threading.Thread(target=_post, daemon=True).start()

    # Polymorphism
    def run(self) -> None:
        """Send concurrent requests from simulated distributed sources."""
        endpoints = ["/", "/api/items", "/slow"]
        print(f"[DDoS] Starting distributed flood to {self.target}:{self.port}")
        print(f"[DDoS] {self.total_requests} requests, {self.workers} threads, {len(self._sim_ips)} simulated IPs")
        start = time.time()
        completed = 0
        errors = 0
        deadline = start + self.duration

        def _send(_: int) -> bool:
            try:
                endpoint = random.choice(endpoints)
                url = f"http://{self.target}:{self.port}{endpoint}"
                r = req.get(url, timeout=3)
                return r.status_code < 500
            except Exception:
                return False

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            batch_size = min(self.total_requests, 60)
            while time.time() < deadline:
                futures = {pool.submit(_send, i): i for i in range(batch_size)}
                for fut in as_completed(futures):
                    sim_ip = random.choice(self._sim_ips)
                    # High fwd_pkts + very short duration = high Flow Packets/s which triggers DoS/DDoS detection
                    self._report_telemetry(sim_ip, 5000, fwd_pkts=random.randint(80, 200))
                    if fut.result():
                        completed += 1
                    else:
                        errors += 1
                elapsed = time.time() - start
                rps = completed / max(elapsed, 0.001)
                print(f"[DDoS] {completed} OK / {errors} ERR — {rps:.1f} req/s from {len(self._sim_ips)} IPs")
                if time.time() >= deadline:
                    break
                time.sleep(0.05)

        print(f"\n[DDoS] Attack finished. Total: {completed} OK, {errors} ERR.")
