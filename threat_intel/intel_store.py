"""
SQLite-backed alert store for persistent threat intelligence.
Schema: alerts(id, timestamp, source_ip, attack_type, severity,
               final_score, mitre_id, reasons)
"""
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import config
from threat_intel import ip_reputation

_DB_PATH = config.INTEL_DB_PATH


def _connect() -> sqlite3.Connection:
    """Open a thread-safe SQLite connection."""
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the alerts table if it does not exist."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL    NOT NULL,
                source_ip   TEXT    NOT NULL,
                attack_type TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                final_score REAL    NOT NULL,
                mitre_id    TEXT    NOT NULL DEFAULT '',
                reasons     TEXT    NOT NULL DEFAULT '[]'
            )
            """
        )
        conn.commit()


# Initialise on import
init_db()


# Encapsulation
def record(alert: Any, source_ip: str, mitre_id: str = "") -> None:
    """Persist one alert and update IP reputation."""
    ip_reputation.record_alert(source_ip, alert.severity)
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO alerts (timestamp, source_ip, attack_type, severity,
                                final_score, mitre_id, reasons)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                source_ip,
                alert.attack_type,
                alert.severity,
                alert.final_score,
                mitre_id,
                json.dumps(alert.reasons),
            ),
        )
        conn.commit()


def query_summary() -> dict[str, Any]:
    """Return aggregated statistics for the threat intelligence view."""
    with _connect() as conn:
        # Count by attack_type
        type_rows = conn.execute(
            "SELECT attack_type, COUNT(*) AS cnt FROM alerts GROUP BY attack_type ORDER BY cnt DESC"
        ).fetchall()

        # Count by mitre_id
        mitre_rows = conn.execute(
            "SELECT mitre_id, attack_type, COUNT(*) AS cnt FROM alerts"
            " WHERE mitre_id != '' GROUP BY mitre_id ORDER BY cnt DESC"
        ).fetchall()

        # Alerts over time (last 100, descending)
        recent_rows = conn.execute(
            "SELECT timestamp, attack_type, severity FROM alerts ORDER BY id DESC LIMIT 100"
        ).fetchall()

    return {
        "type_counts": {r["attack_type"]: r["cnt"] for r in type_rows},
        "mitre_counts": [
            {"mitre_id": r["mitre_id"], "attack_type": r["attack_type"], "count": r["cnt"]}
            for r in mitre_rows
        ],
        "recent": [
            {"timestamp": r["timestamp"], "attack_type": r["attack_type"], "severity": r["severity"]}
            for r in recent_rows
        ],
        "top_ips": ip_reputation.top_ips(10),
    }


def query_ip_history(ip: str) -> list[dict[str, Any]]:
    """Return alert history for a specific source IP."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE source_ip = ? ORDER BY id DESC LIMIT 200",
            (ip,),
        ).fetchall()
    return [dict(r) for r in rows]
