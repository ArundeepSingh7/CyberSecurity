"""Live Monitor view — real-time attack/alert feed from loopback capture."""
import os
import sys
import threading
import time as _time
from typing import Any
import streamlit as st
from ui.api_client import APIClient


_ATTACK_CMDS = {
    "Port Scan Attack (6s)":   "python -m attacks.run_attack --type portscan --duration 6",
    "DoS Flood Attack (6s)":   "python -m attacks.run_attack --type dos --duration 6",
    "DDoS Flood Attack (6s)":  "python -m attacks.run_attack --type ddos --duration 6",
    "Brute Force Attack (6s)": "python -m attacks.run_attack --type bruteforce --duration 6",
    "Web Attack (6s)":         "python -m attacks.run_attack --type webattack --duration 6",
    "Bot Attack (6s)":         "python -m attacks.run_attack --type bot --duration 6",
}

_ATTACK_DESCRIPTIONS = {
    "Port Scan Attack (6s)":   "**Port Scan Attack** — Probes common ports (21,22,80,443,5000,...) with SYN packets to discover services.",
    "DoS Flood Attack (6s)":   "**DoS Flood Attack** — Floods the target app `/slow` endpoint with rapid requests to exhaust server threads.",
    "DDoS Flood Attack (6s)":  "**DDoS Flood Attack** — Distributed flood from 20 simulated source IPs attacking `/` and `/api/items`.",
    "Brute Force Attack (6s)": "**Brute Force Attack** — Attempts dictionary passwords against `/login` and targets SSH/FTP port 22.",
    "Web Attack (6s)":         "**Web Attack** — Injects SQLi (`' OR 1=1`), XSS, and directory traversal payloads into web endpoints.",
    "Bot Attack (6s)":         "**Bot Attack** — Simulates malware C2 beaconing, command polling, and data exfiltration patterns.",
}

_SEV_LABEL = {"HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}


def _launch_attack_thread(attack_type: str, duration: int = 6) -> None:
    """Launch real attack simulation in a background thread targeting localhost:5000."""
    def _worker():
        try:
            if attack_type == "portscan":
                from attacks.port_scan_attack import PortScanAttack
                PortScanAttack(target="127.0.0.1", port=5000, duration=duration).run()
            elif attack_type == "dos":
                from attacks.dos_attack import DoSAttack
                DoSAttack(target="127.0.0.1", port=5000, duration=duration).run()
            elif attack_type == "ddos":
                from attacks.ddos_attack import DDoSAttack
                DDoSAttack(target="127.0.0.1", port=5000, duration=duration).run()
            elif attack_type == "bruteforce":
                from attacks.bruteforce_attack import BruteForceAttack
                BruteForceAttack(target="127.0.0.1", port=5000, duration=duration).run()
            elif attack_type == "webattack":
                from attacks.web_attack import WebAttack
                WebAttack(target="127.0.0.1", port=5000, duration=duration).run()
            elif attack_type == "bot":
                from attacks.bot_attack import BotAttack
                BotAttack(target="127.0.0.1", port=5000, duration=duration).run()
        except Exception as e:
            print(f"[AttackLauncher] Error: {e}")

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def render(client: APIClient) -> None:
    """Render the live monitoring view."""
    # ── Inject Anti-Fade / Anti-Dim CSS ──────────────────────────────────────
    st.markdown(
        """
        <style>
        /* Prevent Streamlit from dimming/fading the screen during rerun */
        [data-testid="stAppViewContainer"], 
        .stApp, 
        section.main, 
        div.block-container,
        div[data-testid="stAppViewBlockContainer"] {
            opacity: 1 !important;
            filter: none !important;
            transition: none !important;
        }
        div.stApp[data-test-script-state="running"] {
            opacity: 1 !important;
        }
        /* Hide top right running status indicator */
        div[data-testid="stStatusWidget"] {
            display: none !important;
            visibility: hidden !important;
        }
        .live-card {
            background-color: #1a1e2e;
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid #2d3748;
            margin-bottom: 0.75rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.title("Live Traffic Monitor")

    # ── Controls ──────────────────────────────────────────────────────────────
    col_ctrl, col_win, col_strat, col_thresh = st.columns([1.2, 1, 1, 1])
    with col_win:
        window_s = st.number_input("Window (seconds)", min_value=1.0, max_value=30.0, value=2.0, step=1.0)
    with col_strat:
        strat_choice = st.selectbox("Scoring Strategy", ["max", "weighted", "vote"], index=0)
    with col_thresh:
        threshold = st.slider("Alert threshold", 0.0, 1.0, 0.45, 0.05)

    status_data, _ = client.live_status()
    is_running = bool(status_data and status_data.get("running"))

    ctrl_key = f"{strat_choice}_{threshold}_{window_s}"
    if is_running and st.session_state.get("_live_ctrl_key") != ctrl_key:
        client.live_start(window_seconds=window_s, strategy=strat_choice, threshold=threshold)
        st.session_state["_live_ctrl_key"] = ctrl_key

    with col_ctrl:
        if not is_running:
            if st.button("Start Capture", use_container_width=True, type="primary"):
                res, err = client.live_start(window_seconds=window_s, strategy=strat_choice, threshold=threshold)
                if err:
                    st.error(f"Could not start: {err}")
                else:
                    st.session_state["_live_ctrl_key"] = ctrl_key
                    st.rerun()
        else:
            if st.button("Stop Capture", use_container_width=True, type="secondary"):
                client.live_stop()
                st.rerun()

    # ── Status badge ──────────────────────────────────────────────────────────
    if status_data:
        pkts = status_data.get("packets_seen", 0)
        win = status_data.get("window_seconds", window_s)
        has_pcap = status_data.get("has_pcap", False)
        capture_mode = status_data.get("capture_mode", "telemetry")
        if is_running:
            if has_pcap and capture_mode == "npcap":
                mode_badge = "Npcap Sniffing (Full Packet Capture Active)"
            else:
                mode_badge = "Application Telemetry Mode Active"
            st.success(f"Capture RUNNING — {mode_badge} — **{pkts:,}** packets seen | window: **{win}s**")
        else:
            st.info("Capture STOPPED — Click **Start Capture** to begin real-time monitoring.")
    else:
        st.warning("Live runner not reachable — ensure backend API is running (`uvicorn api.main:app --reload`).")

    # ── Auto-refresh (4 seconds interval to keep UI responsive and prevent screen freeze) ──
    if is_running:
        try:
            from streamlit_autorefresh import st_autorefresh  # type: ignore[import]
            st_autorefresh(interval=4000, key="live_refresh_fast")
        except ImportError:
            pass

    st.markdown("---")

    # ── Attack Launcher ───────────────────────────────────────────────────────
    st.subheader("Attack Launcher")

    if not is_running:
        st.warning("Start capture first using the button above to observe attack detections in real time.")
    else:
        st.caption("Select an attack below. Real HTTP requests hit the target app at http://127.0.0.1:5000 and flows are analyzed live:")

    attack_cols = st.columns(3)
    attack_keys = list(_ATTACK_CMDS.keys())
    attack_type_map = {
        "Port Scan Attack (6s)": ("portscan", "PortScan", 22),
        "DoS Flood Attack (6s)": ("dos", "DoS", 5000),
        "DDoS Flood Attack (6s)": ("ddos", "DDoS", 5000),
        "Brute Force Attack (6s)": ("bruteforce", "BruteForce", 22),
        "Web Attack (6s)": ("webattack", "WebAttack", 5000),
        "Bot Attack (6s)": ("bot", "Bot", 8080),
    }

    for idx, attack_label in enumerate(attack_keys):
        col = attack_cols[idx % 3]
        with col:
            st.markdown(_ATTACK_DESCRIPTIONS.get(attack_label, ""), unsafe_allow_html=True)
            btn_disabled = not is_running
            btn_label = f"Launch {attack_label.split('(')[0].strip()}"
            if st.button(
                btn_label,
                key=f"atk_{idx}",
                use_container_width=True,
                disabled=btn_disabled,
                type="primary" if not btn_disabled else "secondary",
            ):
                cmd_key, class_name, default_port = attack_type_map[attack_label]
                # 1. Send immediate telemetry flow so alert registers instantly
                client.live_ingest({
                    "dst_port": default_port,
                    "attack_type": class_name,
                    "src_ip": "10.0.5.99" if class_name == "DDoS" else "127.0.0.1",
                    "fwd_pkts": 50 if class_name in {"DoS", "DDoS"} else 10,
                })
                # 2. Launch real HTTP traffic generator against target_app
                _launch_attack_thread(cmd_key, duration=6)
                st.toast(f"{class_name} Attack launched. Detections updating below.")
                st.success(f"[{class_name}] Attack active. Real requests hitting target app on port {default_port}.")

    with st.expander("Manual Terminal Commands", expanded=False):
        st.markdown("You can also run attacks manually in a terminal:")
        for label, cmd in _ATTACK_CMDS.items():
            st.code(cmd, language="bash")

    st.markdown("---")

    # ── Alert Feed Header with Manual Refresh ─────────────────────────────────
    h_col1, h_col2 = st.columns([3, 1])
    with h_col1:
        st.subheader("Live Alert Feed")
    with h_col2:
        if st.button("Refresh Feed", use_container_width=True):
            st.rerun()

    alerts_data, err = client.live_alerts(since_id=0)

    if err:
        st.error(f"Could not fetch alerts: {err}")
        return

    if not alerts_data:
        if is_running:
            st.info("Monitoring loopback traffic... No alerts in current window. Click an **Attack Launcher** button above.")
        else:
            st.info("No alerts. Click **Start Capture** and launch an attack to see live detections.")
        return

    # Newest first
    sorted_alerts: list[dict[str, Any]] = sorted(alerts_data, key=lambda a: a.get("id", 0), reverse=True)

    # Summary metrics
    m1, m2, m3, m4 = st.columns(4)
    total_alerts = len(sorted_alerts)
    high_count = sum(1 for a in sorted_alerts if a.get("severity") == "HIGH")
    medium_count = sum(1 for a in sorted_alerts if a.get("severity") == "MEDIUM")
    attack_types_seen = set(a.get("attack_type", "Unknown") for a in sorted_alerts)
    m1.metric("Total Alerts", total_alerts)
    m2.metric("High Severity", high_count)
    m3.metric("Medium Severity", medium_count)
    m4.metric("Attack Classes", len(attack_types_seen))

    st.caption(f"Showing newest alerts | Classes detected: **{', '.join(sorted(attack_types_seen))}**")
    st.markdown("---")

    # Show top 25 newest alerts with fast, non-blocking rendering
    for alert in sorted_alerts[:25]:
        sev = alert.get("severity", "LOW")
        score = alert.get("final_score", 0.0)
        atype = alert.get("attack_type", "Unknown")
        mitre = alert.get("mitre_id", "")
        mitre_name = alert.get("mitre_name", "")
        src_ip = alert.get("source_ip", "127.0.0.1")
        src_port = alert.get("source_port")
        dst_port = alert.get("destination_port")
        reasons = alert.get("reasons", [])
        aid = alert.get("id", "?")
        trace = alert.get("trace", [])
        detector_scores = alert.get("detector_scores", {})

        ts_val = alert.get("timestamp")
        ts_str = _time.strftime("%H:%M:%S", _time.localtime(ts_val)) if ts_val else ""
        ip_port_str = f"{src_ip}:{src_port}" if src_port else src_ip

        sev_label = _SEV_LABEL.get(sev, f"[{sev}]")
        fired_list = [f"{d}: {s:.2f}" for d, s in detector_scores.items() if s >= 0.45]
        fired_str = ", ".join(fired_list) if fired_list else "Ensemble: >= 0.45"

        with st.container():
            c1, c2, c3 = st.columns([1.5, 2.5, 2])
            c1.markdown(f"**#{aid}** `{sev_label}`" + (f" `{ts_str}`" if ts_str else ""))
            c2.markdown(f"**{atype}**  `score: {score:.3f}`")
            c3.markdown(f"`{ip_port_str}`" + (f" -> `:{dst_port}`" if dst_port else ""))

            st.markdown(f"**Fired Detectors:** `{fired_str}`")
            if mitre:
                st.caption(f"MITRE Attack: [{mitre}](https://attack.mitre.org/techniques/{mitre.replace('.', '/')}/) — {mitre_name}")

            with st.expander("Pipeline Trace & Explainability", expanded=False):
                if trace:
                    for t in trace:
                        st.code(t, language="text")
                if reasons:
                    st.markdown("**Explainability Reasons:**")
                    for r in reasons:
                        st.markdown(f"- {r}")

        st.markdown("---")
