"""
For educational use against your own local test environment only.
Bot simulation: mimics C2 beaconing behaviour — periodic callbacks,
data exfiltration patterns, and covert channel communication.
"""
import time
import random
import threading
import json
import urllib.request
import requests as req
from attacks.attack_base import BaseAttack


# Inheritance
class BotAttack(BaseAttack):
    """Simulates bot/C2 beaconing: periodic callbacks with jitter mimicking malware communication."""

    def __init__(self, target: str = "127.0.0.1", port: int = 5000, duration: int = 10) -> None:
        """Initialise bot simulator."""
        super().__init__(target=target, port=port, duration=duration)
        self._beacon_interval = 0.8  # seconds between beacons
        self._jitter = 0.3  # random jitter factor

    def _report_telemetry(self, beacon_type: str) -> None:
        """Send flow telemetry to IDS backend with bot/C2 patterns."""
        def _post():
            try:
                # Bot patterns: regular intervals, specific packet sizes, unusual ports
                c2_ports = [443, 8443, 4444, 8080, 9090]
                payload = json.dumps({
                    "dst_port": random.choice(c2_ports),
                    "src_ip": "127.0.0.1",
                    "src_port": random.randint(49152, 65535),
                    "fwd_pkts": random.randint(2, 8),
                    "bwd_pkts": random.randint(1, 4),
                    "syn": 1,
                    "ack": 1,
                    "pkt_len": random.randint(64, 256),  # Small, periodic packets
                    "duration_us": random.uniform(10000, 100000),  # Moderate duration
                    "attack_type": "Bot",
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
        """Simulate C2 beaconing, data exfiltration, and command polling."""
        base_url = f"http://{self.target}:{self.port}"
        print(f"[Bot] Starting C2 beaconing simulation to {base_url}")
        print(f"[Bot] Beacon interval: {self._beacon_interval}s ± {self._jitter}s jitter")
        start = time.time()
        deadline = start + self.duration
        beacon_count = 0

        phases = ["beacon", "poll_commands", "exfiltrate", "heartbeat"]

        while time.time() < deadline:
            phase = random.choice(phases)
            beacon_count += 1

            try:
                if phase == "beacon":
                    # C2 beacon — check-in with controller
                    r = req.get(f"{base_url}/", timeout=3, headers={
                        "User-Agent": f"Mozilla/5.0 (Bot-{random.randint(1,100)})",
                        "X-Bot-ID": f"bot-{random.randint(1000,9999)}",
                    })
                    status = f"HTTP {r.status_code}"
                    self._report_telemetry("beacon")

                elif phase == "poll_commands":
                    # Command polling — check for new instructions
                    r = req.get(f"{base_url}/api/items", timeout=3, headers={
                        "X-Command-Poll": "true",
                    })
                    status = f"HTTP {r.status_code} ({len(r.content)} bytes)"
                    self._report_telemetry("command_poll")

                elif phase == "exfiltrate":
                    # Data exfiltration — send fake stolen data
                    fake_data = {"data": "".join(random.choices("abcdefghijklmnop0123456789", k=random.randint(50, 200)))}
                    r = req.post(
                        f"{base_url}/login",
                        json=fake_data,
                        timeout=3,
                        headers={"X-Exfil": "true"},
                    )
                    status = f"HTTP {r.status_code} (exfil {len(json.dumps(fake_data))} bytes)"
                    self._report_telemetry("exfiltrate")

                else:  # heartbeat
                    r = req.get(f"{base_url}/", timeout=3)
                    status = f"HTTP {r.status_code}"
                    self._report_telemetry("heartbeat")

                print(f"  [Beacon #{beacon_count:3d}] {phase}: {status}")

            except Exception as exc:
                print(f"  [Beacon #{beacon_count:3d}] {phase} ERROR: {exc}")

            # Jittered sleep mimicking real bot behaviour
            sleep_time = self._beacon_interval + random.uniform(-self._jitter, self._jitter)
            time.sleep(max(0.1, sleep_time))

        print(f"\n[Bot] Beaconing finished after {self.duration}s. {beacon_count} beacons sent.")
