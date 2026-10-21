"""
Local IP reputation scoring — fully offline, no external threat feed.
Reputation score rises each time an IP triggers an alert, decays over time.

Optional hook: set ABUSEIPDB_KEY env var for external lookups (no-op if unset).
"""
import os
import time
import threading
from collections import defaultdict

_DECAY_HALF_LIFE_SECONDS = 300.0  # score halves every 5 minutes
_lock = threading.Lock()

# ip -> {"score": float, "last_seen": float, "count": int}
_reputation: dict[str, dict] = defaultdict(lambda: {"score": 0.0, "last_seen": time.time(), "count": 0})


def _decayed_score(ip: str) -> float:
    """Return current reputation score after exponential time decay."""
    entry = _reputation[ip]
    elapsed = time.time() - entry["last_seen"]
    decay = 0.5 ** (elapsed / _DECAY_HALF_LIFE_SECONDS)
    return entry["score"] * decay


def record_alert(ip: str, severity: str) -> None:
    """Increment reputation score for an IP based on alert severity."""
    increment = {"HIGH": 10.0, "MEDIUM": 5.0, "LOW": 2.0}.get(severity, 2.0)
    with _lock:
        current = _decayed_score(ip)
        _reputation[ip]["score"] = min(100.0, current + increment)
        _reputation[ip]["last_seen"] = time.time()
        _reputation[ip]["count"] += 1


def get_score(ip: str) -> float:
    """Return current reputation score (0–100) for the given IP."""
    with _lock:
        return round(_decayed_score(ip), 2)


def top_ips(n: int = 10) -> list[dict]:
    """Return top-n IPs by current reputation score."""
    with _lock:
        scored = [
            {"ip": ip, "score": round(_decayed_score(ip), 2), "count": data["count"]}
            for ip, data in _reputation.items()
        ]
    return sorted(scored, key=lambda x: x["score"], reverse=True)[:n]


# ---------------------------------------------------------------------------
# Optional external reputation hook — no-op unless ABUSEIPDB_KEY is set.
# ---------------------------------------------------------------------------
def check_external_reputation(ip: str) -> dict:
    """
    Optional: query AbuseIPDB if API key is set via ABUSEIPDB_KEY env var.
    Returns empty dict if key is not configured.
    """
    api_key = os.environ.get("ABUSEIPDB_KEY", "")
    if not api_key:
        return {}
    try:
        import requests  # type: ignore[import]
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json().get("data", {})
    except Exception:
        pass
    return {}
