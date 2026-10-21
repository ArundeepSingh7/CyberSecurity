"""Threat Intelligence view — IP reputation, MITRE mapping, alert timeline, and actionable intelligence."""
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from ui.api_client import APIClient


# ── Comprehensive threat intelligence knowledge base ──────────────────────────
_THREAT_PROFILES = {
    "DoS": {
        "description": "Denial of Service attack detected — high-volume traffic designed to exhaust server resources and prevent legitimate users from accessing services.",
        "risk_level": "HIGH",
        "impact": [
            "Service unavailability for legitimate users",
            "Server CPU/memory exhaustion",
            "Potential cascading failures in dependent services",
            "Revenue loss during downtime",
        ],
        "indicators": [
            "Extremely high packet rate (>5000 pkts/s)",
            "Single source flooding a single endpoint",
            "Small packet sizes with minimal payloads",
            "TCP SYN flood or HTTP request flood pattern",
        ],
        "mitre_id": "T1498",
        "mitre_tactic": "Impact",
        "recommendations": [
            "**Immediate**: Enable rate limiting on the affected endpoint (e.g., 100 req/s per IP)",
            "**Firewall**: Block the source IP at the network perimeter firewall",
            "**Monitor**: Set up alerts for traffic exceeding 1000 req/s baseline",
            "**Infrastructure**: Deploy a CDN/DDoS protection service (Cloudflare, AWS Shield)",
            "**Resilience**: Implement circuit breakers and auto-scaling policies",
            "**Policy**: Create an incident response runbook for volumetric attacks",
        ],
        "cve_references": [
            "CVE-2019-9512 (HTTP/2 Ping Flood)",
            "CVE-2019-9514 (HTTP/2 Reset Flood)",
        ],
    },
    "DDoS": {
        "description": "Distributed Denial of Service attack detected — coordinated flood from multiple source IPs designed to overwhelm infrastructure capacity.",
        "risk_level": "CRITICAL",
        "impact": [
            "Complete service outage across all endpoints",
            "Network bandwidth saturation",
            "Upstream provider congestion",
            "Extended recovery time due to distributed nature",
        ],
        "indicators": [
            "Traffic from multiple distinct source IPs simultaneously",
            "Abnormally high aggregate traffic volume",
            "Requests spread across multiple endpoints",
            "Geographic distribution of source addresses",
        ],
        "mitre_id": "T1498",
        "mitre_tactic": "Impact",
        "recommendations": [
            "**Immediate**: Activate DDoS mitigation service / scrubbing center",
            "**Firewall**: Implement geo-blocking for non-expected regions",
            "**Analysis**: Identify botnet C2 patterns in source IPs",
            "**Infrastructure**: Enable auto-scaling and CDN-based absorption",
            "**Forensics**: Collect traffic samples for botnet fingerprinting",
            "**Coordination**: Contact ISP for upstream filtering assistance",
            "**Policy**: Notify stakeholders and activate business continuity plan",
        ],
        "cve_references": [
            "CVE-2023-44487 (HTTP/2 Rapid Reset - zero-day DDoS)",
            "CVE-2018-6389 (WordPress DoS via load-scripts.php)",
        ],
    },
    "PortScan": {
        "description": "Network reconnaissance detected — systematic probing of ports to discover running services, often a precursor to exploitation.",
        "risk_level": "MEDIUM",
        "impact": [
            "Exposure of running services and their versions",
            "Attack surface mapping for future exploitation",
            "Information leakage about network topology",
            "Potential prelude to a targeted attack",
        ],
        "indicators": [
            "Low forward packet count per connection (1-2 packets)",
            "SYN flags without completed handshakes (SYN scan)",
            "Sequential or common-port probing patterns",
            "Rapid connection attempts across many ports",
        ],
        "mitre_id": "T1046",
        "mitre_tactic": "Discovery",
        "recommendations": [
            "**Immediate**: Review and close unnecessary open ports",
            "**Firewall**: Enable port scan detection rules (e.g., >10 ports in 60s = block)",
            "**Monitor**: Log all connection attempts to unused ports as indicators",
            "**Hardening**: Disable service banners and version disclosure",
            "**Network**: Implement network segmentation to limit lateral movement",
            "**Policy**: Investigate the source IP for prior malicious activity",
        ],
        "cve_references": [
            "CWE-200 (Information Exposure)",
        ],
    },
    "BruteForce": {
        "description": "Credential stuffing / brute force attack detected — repeated authentication attempts to gain unauthorized access to accounts.",
        "risk_level": "HIGH",
        "impact": [
            "Account compromise if weak passwords exist",
            "Account lockout causing legitimate user denial of service",
            "Credential theft leading to data breach",
            "Lateral movement using compromised credentials",
        ],
        "indicators": [
            "High volume of authentication requests to SSH/FTP ports (22, 21)",
            "Many forward packets per flow (>10) targeting auth services",
            "Sequential password attempts from same source",
            "Failed login response codes (401/403) followed by retries",
        ],
        "mitre_id": "T1110",
        "mitre_tactic": "Credential Access",
        "recommendations": [
            "**Immediate**: Enable account lockout after 5 failed attempts",
            "**Firewall**: Block the source IP and add to deny list",
            "**Authentication**: Enforce multi-factor authentication (MFA)",
            "**Monitor**: Set up alerts for >3 failed logins per minute per IP",
            "**Password Policy**: Enforce minimum 12-char passwords with complexity",
            "**Defense**: Deploy fail2ban or similar intrusion prevention",
            "**Policy**: Review all accounts for password reuse from known breaches",
        ],
        "cve_references": [
            "CWE-307 (Improper Restriction of Excessive Authentication Attempts)",
            "CVE-2021-22205 (GitLab RCE via auth bypass)",
        ],
    },
    "WebAttack": {
        "description": "Web application attack detected — SQL injection, cross-site scripting (XSS), or path traversal attempts targeting application vulnerabilities.",
        "risk_level": "CRITICAL",
        "impact": [
            "Database compromise via SQL injection",
            "User session hijacking via XSS",
            "Sensitive file access via path traversal",
            "Remote code execution in severe cases",
        ],
        "indicators": [
            "HTTP requests with SQL syntax in parameters",
            "JavaScript/HTML injection in query strings",
            "Directory traversal sequences (../) in URLs",
            "Unusual parameter lengths or encoded payloads",
        ],
        "mitre_id": "T1190",
        "mitre_tactic": "Initial Access",
        "recommendations": [
            "**Immediate**: Deploy a Web Application Firewall (WAF) with OWASP CRS",
            "**Code**: Implement parameterized queries for all database operations",
            "**Sanitization**: Apply input validation and output encoding on all user inputs",
            "**Monitor**: Enable detailed request logging for forensic analysis",
            "**Scan**: Run DAST/SAST security scans against the application",
            "**Patch**: Review and update all web frameworks and dependencies",
            "**Headers**: Implement CSP, X-Frame-Options, and X-XSS-Protection headers",
        ],
        "cve_references": [
            "CWE-89 (SQL Injection)",
            "CWE-79 (Cross-Site Scripting)",
            "CWE-22 (Path Traversal)",
            "CVE-2021-44228 (Log4Shell)",
        ],
    },
    "Bot": {
        "description": "Bot / Command-and-Control (C2) beaconing detected — periodic network callbacks consistent with malware communication patterns.",
        "risk_level": "CRITICAL",
        "impact": [
            "Active malware infection on the host",
            "Data exfiltration to attacker-controlled servers",
            "Remote command execution capability",
            "Potential ransomware deployment or espionage",
        ],
        "indicators": [
            "Regular interval callbacks with slight jitter",
            "Communication to unusual ports (4444, 8443, 9090)",
            "Small, consistent packet sizes typical of beaconing",
            "Encrypted or encoded payloads in outbound traffic",
        ],
        "mitre_id": "T1071",
        "mitre_tactic": "Command and Control",
        "recommendations": [
            "**Immediate**: Isolate the affected host from the network",
            "**Forensics**: Capture full packet trace of C2 communication",
            "**Firewall**: Block outbound connections to identified C2 IPs/domains",
            "**EDR**: Run endpoint detection scan to identify the malware",
            "**Network**: Implement DNS sinkholing for known C2 domains",
            "**Incident**: Activate incident response plan — potential data breach",
            "**Reporting**: Share C2 indicators with CERT and threat intel communities",
        ],
        "cve_references": [
            "MITRE Attack T1571 (Non-Standard Port)",
            "MITRE Attack T1573 (Encrypted Channel)",
        ],
    },
    "Anomaly": {
        "description": "Anomalous network behavior detected — traffic patterns that deviate from established baselines but don't match a known attack signature.",
        "risk_level": "MEDIUM",
        "impact": [
            "Potential zero-day or novel attack vector",
            "Misconfigured application generating unusual traffic",
            "Insider threat or policy violation",
        ],
        "indicators": [
            "Scores above threshold across multiple ML detectors",
            "No matching rule-based signature",
            "Unusual combination of flow features",
        ],
        "mitre_id": "T1040",
        "mitre_tactic": "Discovery / Collection",
        "recommendations": [
            "**Investigate**: Review the flow details and packet capture",
            "**Baseline**: Compare against normal traffic patterns",
            "**Monitor**: Continue monitoring for escalation",
            "**Log**: Document the anomaly for pattern tracking",
        ],
        "cve_references": [],
    },
}


def render(client: APIClient) -> None:
    """Render threat intelligence dashboard."""
    st.title("Threat Intelligence Center")

    summary, err = client.intel_summary()
    if err:
        st.error(f"Could not load intelligence data: {err}")
        return
    if not summary:
        st.info("No threat intelligence recorded yet. Run a live capture and launch attacks to populate intelligence data.")
        return

    # ── Overview metrics ──────────────────────────────────────────────────────
    type_counts = summary.get("type_counts", {})
    total_alerts = sum(type_counts.values())
    unique_types = len(type_counts)
    top_ips = summary.get("top_ips", [])

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Alerts", total_alerts)
    m2.metric("Attack Types", unique_types)
    m3.metric("Unique IPs", len(top_ips))
    highest_risk = max(
        (_THREAT_PROFILES.get(t, {}).get("risk_level", "LOW") for t in type_counts.keys()),
        key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x, 0),
        default="NONE"
    ) if type_counts else "NONE"
    m4.metric("Highest Risk", highest_risk)

    st.markdown("---")

    # ── Active Threat Profiles with Recommendations ───────────────────────────
    st.subheader("Active Threat Profiles & Recommendations")

    if type_counts:
        for attack_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            profile = _THREAT_PROFILES.get(attack_type)
            if not profile:
                continue

            with st.expander(
                f"[{profile['risk_level']}] **{attack_type}** — {count} alerts | MITRE: {profile['mitre_id']}",
                expanded=(profile["risk_level"] in ("CRITICAL", "HIGH")),
            ):
                st.markdown(f"**{profile['description']}**")
                st.markdown(f"**MITRE Attack Tactic:** {profile['mitre_tactic']}")

                col_impact, col_ioc = st.columns(2)
                with col_impact:
                    st.markdown("##### Potential Impact")
                    for impact in profile["impact"]:
                        st.markdown(f"- {impact}")

                with col_ioc:
                    st.markdown("##### Indicators of Compromise")
                    for indicator in profile["indicators"]:
                        st.markdown(f"- {indicator}")

                st.markdown("##### Recommended Actions")
                for rec in profile["recommendations"]:
                    st.markdown(f"  {rec}")

                if profile.get("cve_references"):
                    st.markdown("##### Related References")
                    for ref in profile["cve_references"]:
                        st.markdown(f"- `{ref}`")
    else:
        st.info("No active threats detected yet.")

    st.markdown("---")

    # ── Top source IPs ────────────────────────────────────────────────────────
    st.subheader("Top Source IPs by Reputation Score")
    if top_ips:
        ip_df = pd.DataFrame(top_ips)
        fig_ip = px.bar(
            ip_df,
            x="ip",
            y="score",
            color="score",
            color_continuous_scale="RdYlGn_r",
            labels={"ip": "Source IP", "score": "Reputation Score"},
            title="IP Reputation Scores (higher = more suspicious)",
        )
        fig_ip.update_layout(
            plot_bgcolor="#0e1117",
            paper_bgcolor="#0e1117",
            font_color="#fafafa",
            showlegend=False,
        )
        st.plotly_chart(fig_ip, use_container_width=True)

        # IP risk assessment table
        st.markdown("##### IP Risk Assessment")
        for ip_entry in top_ips:
            ip = ip_entry.get("ip", "")
            score = ip_entry.get("score", 0)
            count = ip_entry.get("count", 0)
            if score >= 50:
                risk = "**HIGH RISK** — Recommend immediate blocking"
            elif score >= 25:
                risk = "**MEDIUM RISK** — Monitor closely and consider blocking"
            elif score >= 10:
                risk = "**LOW RISK** — Continue monitoring"
            else:
                risk = "**MINIMAL** — Normal activity"
            st.markdown(f"- `{ip}` — Score: {score:.1f} | {count} alerts | {risk}")
    else:
        st.info("No IP reputation data yet.")

    st.markdown("---")

    # ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────
    st.subheader("MITRE Attack Coverage Map")
    mitre_counts = summary.get("mitre_counts", [])
    if mitre_counts:
        mitre_df = pd.DataFrame(mitre_counts)
        fig_mitre = px.bar(
            mitre_df,
            x="mitre_id",
            y="count",
            color="attack_type",
            labels={"mitre_id": "MITRE Technique", "count": "Alert Count"},
            title="Alert Distribution by MITRE Attack Technique",
            text="count",
            color_discrete_sequence=px.colors.qualitative.Set2,
        )
        fig_mitre.update_layout(
            plot_bgcolor="#0e1117",
            paper_bgcolor="#0e1117",
            font_color="#fafafa",
        )
        st.plotly_chart(fig_mitre, use_container_width=True)

        # MITRE technique details
        st.markdown("##### Technique Details")
        for row in mitre_counts:
            tid = row.get("mitre_id", "")
            atype = row.get("attack_type", "")
            profile = _THREAT_PROFILES.get(atype, {})
            if tid:
                st.markdown(
                    f"- [{tid}](https://attack.mitre.org/techniques/{tid.replace('.', '/')}/) — "
                    f"**{atype}** ({profile.get('mitre_tactic', 'Unknown')}) — "
                    f"{row.get('count', 0)} detections"
                )
    else:
        st.info("No MITRE data yet.")

    st.markdown("---")

    # ── Alert timeline ────────────────────────────────────────────────────────
    st.subheader("Alert Timeline")
    recent = summary.get("recent", [])
    if recent:
        timeline_df = pd.DataFrame(recent)
        timeline_df["datetime"] = pd.to_datetime(timeline_df["timestamp"], unit="s")
        fig_time = px.scatter(
            timeline_df,
            x="datetime",
            y="attack_type",
            color="severity",
            color_discrete_map={"HIGH": "#ef4444", "MEDIUM": "#f97316", "LOW": "#eab308"},
            title="Alert Timeline (last 100 alerts)",
            labels={"datetime": "Time", "attack_type": "Attack Type"},
            size_max=12,
        )
        fig_time.update_traces(marker=dict(size=10))
        fig_time.update_layout(
            plot_bgcolor="#0e1117",
            paper_bgcolor="#0e1117",
            font_color="#fafafa",
        )
        st.plotly_chart(fig_time, use_container_width=True)

        # Attack distribution pie chart
        if type_counts:
            col_pie, col_table = st.columns(2)
            with col_pie:
                fig_pie = px.pie(
                    names=list(type_counts.keys()),
                    values=list(type_counts.values()),
                    title="Attack Type Distribution",
                    color_discrete_sequence=px.colors.qualitative.Set2,
                )
                fig_pie.update_layout(
                    plot_bgcolor="#0e1117",
                    paper_bgcolor="#0e1117",
                    font_color="#fafafa",
                )
                st.plotly_chart(fig_pie, use_container_width=True)

            with col_table:
                st.markdown("##### Attack Summary")
                summary_rows = []
                for atype, cnt in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                    profile = _THREAT_PROFILES.get(atype, {})
                    summary_rows.append({
                        "Attack Type": atype,
                        "Count": cnt,
                        "Risk Level": profile.get("risk_level", "Unknown"),
                        "MITRE ID": profile.get("mitre_id", "N/A"),
                        "Tactic": profile.get("mitre_tactic", "N/A"),
                    })
                st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No timeline data yet.")

    st.markdown("---")

    # ── IP drill-down ─────────────────────────────────────────────────────────
    st.subheader("IP Address Investigation")
    ip_input = st.text_input("Enter source IP to investigate", value="127.0.0.1")
    if st.button("Investigate IP"):
        history, h_err = client.intel_ip(ip_input)
        if h_err:
            st.error(f"Error: {h_err}")
        elif not history:
            st.info(f"No recorded alerts for {ip_input}.")
        else:
            history_df = pd.DataFrame(history)
            if "timestamp" in history_df.columns:
                history_df["datetime"] = pd.to_datetime(history_df["timestamp"], unit="s")

            st.markdown(f"##### Alert History for `{ip_input}` ({len(history)} records)")

            # Summary for this IP
            if "attack_type" in history_df.columns:
                ip_type_counts = history_df["attack_type"].value_counts().to_dict()
                for atype, cnt in ip_type_counts.items():
                    profile = _THREAT_PROFILES.get(atype, {})
                    if profile:
                        st.warning(f"**{atype}** — {cnt} occurrences | {profile.get('description', '')[:100]}...")

            st.dataframe(history_df, use_container_width=True, hide_index=True)
