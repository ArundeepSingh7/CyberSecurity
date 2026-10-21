"""
For educational use against your own local test environment only.
TEST TARGET APP — deliberately simple, no real user data, no real auth.
Run: python -m target_app.app   (separate terminal, port 5000)
"""
import json
import threading
import time
import urllib.request
from flask import Flask, jsonify, request

app = Flask(__name__)

# Hardcoded demo credentials — this is intentionally weak for demonstration
_DEMO_USER = "admin"
_DEMO_PASS = "password123"

# Request counter for visibility
_request_count = {"total": 0, "by_type": {}}
_lock = threading.Lock()


def _count_request(endpoint: str) -> None:
    """Track request counts for monitoring."""
    with _lock:
        _request_count["total"] += 1
        _request_count["by_type"][endpoint] = _request_count["by_type"].get(endpoint, 0) + 1


def _send_telemetry(payload: dict) -> None:
    """Non-blocking flow telemetry to Cyber IDS backend when running."""
    def _worker():
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:8000/live/ingest",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=0.5)
        except Exception:
            pass  # silent if IDS backend is not active
    threading.Thread(target=_worker, daemon=True).start()


@app.route("/")
def index():
    """Simple landing page — target for traffic generation."""
    _count_request("/")
    _send_telemetry({"dst_port": 5000, "fwd_pkts": 1, "syn": 1, "duration_us": 1000.0, "pkt_len": 120})
    count = _request_count["total"]
    return f"""
    <html>
    <head><title>Cyber IDS Test Target</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #e0e0e0;
               display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .container {{ text-align: center; padding: 2rem; background: #16213e; border-radius: 12px;
                     border: 1px solid #0f3460; max-width: 600px; }}
        h1 {{ color: #4361ee; }}
        .counter {{ font-size: 2rem; color: #f97316; margin: 1rem 0; }}
        .warning {{ color: #ef4444; font-size: 0.9rem; }}
        .status {{ color: #22c55e; }}
    </style>
    </head>
    <body>
        <div class="container">
            <h1>Cyber IDS Test Target</h1>
            <p class="status">Server is running and accepting connections</p>
            <div class="counter">Total Requests: {count}</div>
            <p>This is a local test application for the Cyber IDS system.</p>
            <p>Available endpoints: <code>/</code> <code>/api/items</code> <code>/login</code> <code>/slow</code> <code>/status</code></p>
            <p class="warning">FOR LOCAL EDUCATIONAL USE ONLY — Do not expose externally.</p>
        </div>
    </body>
    </html>
    """


@app.route("/api/items")
def api_items():
    """Fake API endpoint — target for web traffic / scan patterns."""
    _count_request("/api/items")
    _send_telemetry({"dst_port": 5000, "fwd_pkts": 2, "syn": 1, "duration_us": 2000.0, "pkt_len": 80})
    items = [{"id": i, "name": f"item_{i}"} for i in range(5)]
    return jsonify({"items": items, "total": len(items)})


@app.route("/login", methods=["POST"])
def login():
    """Fake login — returns 401 on failure (BruteForce target)."""
    _count_request("/login")
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    _send_telemetry({"dst_port": 22, "fwd_pkts": 15, "syn": 1, "duration_us": 5000.0, "pkt_len": 120})
    if username == _DEMO_USER and password == _DEMO_PASS:
        return jsonify({"status": "ok", "message": "Login successful"}), 200
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/slow")
def slow():
    """Deliberately slow endpoint — DoS target (0.5 s sleep)."""
    _count_request("/slow")
    _send_telemetry({"dst_port": 5000, "fwd_pkts": 100, "syn": 1, "duration_us": 100.0, "pkt_len": 60})
    time.sleep(0.5)
    return jsonify({"status": "ok", "message": "Slow response"})


@app.route("/status")
def status():
    """Return current request counts for monitoring."""
    return jsonify({
        "status": "ok",
        "request_count": _request_count,
    })


if __name__ == "__main__":
    print("=" * 60)
    print("  Cyber IDS TEST TARGET APP")
    print("  Listening on http://127.0.0.1:5000")
    print("  Endpoints: / /api/items /login /slow /status")
    print("  FOR LOCAL EDUCATIONAL USE ONLY")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False)
