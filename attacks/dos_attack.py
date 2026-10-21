"""
For educational use against your own local test environment only.
DoS simulation: sends rapid GET requests to /slow using a thread pool.
Rate is deliberately modest (200 requests over ~10 s) to avoid hanging the laptop.
"""
import time
import json
import random
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests as req
from attacks.attack_base import BaseAttack


# Inheritance
class DoSAttack(BaseAttack):
    """Simulates a DoS by flooding the /slow endpoint with concurrent requests."""

    def __init__(
        self,
        target: str = "127.0.0.1",
        port: int = 5000,
        duration: int = 10,
        total_requests: int = 200,
        workers: int = 20,
    ) -> None:
        """Initialise DoS attack parameters."""
        super().__init__(target=target, port=port, duration=duration)
        self.total_requests = total_requests
        self.workers = workers

    def _report_telemetry(self) -> None:
        """Send flow telemetry to IDS backend with DoS patterns."""
        def _post():
            try:
                # DoS pattern: very high fwd_pkts, very short duration = extremely high Flow Packets/s
                payload = json.dumps({
                    "dst_port": self.port,
                    "src_ip": "127.0.0.1",
                    "src_port": random.randint(40000, 65000),
                    "fwd_pkts": random.randint(100, 300),
                    "bwd_pkts": random.randint(0, 2),
                    "syn": 1,
                    "ack": 0,
                    "pkt_len": 60,
                    "duration_us": random.uniform(50, 200),  # Very short = high rate
                    "attack_type": "DoS",
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
        """Send concurrent GET /slow requests and print live progress."""
        url = f"http://{self.target}:{self.port}/slow"
        print(f"[DoS] Starting flood to {url}")
        print(f"[DoS] {self.total_requests} requests, {self.workers} threads, {self.duration}s window")
        start = time.time()
        completed = 0
        errors = 0
        deadline = start + self.duration

        def _send(_: int) -> bool:
            try:
                r = req.get(url, timeout=3)
                return r.status_code < 500
            except Exception:
                return False

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            batch_size = min(self.total_requests, 50)
            while time.time() < deadline:
                futures = {pool.submit(_send, i): i for i in range(batch_size)}
                for fut in as_completed(futures):
                    self._report_telemetry()
                    if fut.result():
                        completed += 1
                    else:
                        errors += 1
                elapsed = time.time() - start
                rps = completed / max(elapsed, 0.001)
                print(f"[DoS] {completed} OK / {errors} ERR — {rps:.1f} req/s")
                if time.time() >= deadline:
                    break
                time.sleep(0.1)

        print(f"\n[DoS] Attack finished. Total: {completed} OK, {errors} ERR.")
