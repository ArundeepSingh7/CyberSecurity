import pandas as pd
import plotly.express as px
import streamlit as st
from ui.api_client import APIClient


def render(client: APIClient) -> None:
    """Render the main Security Operations Center dashboard."""
    st.title("SOC Threat Overview")

    analysis_res = st.session_state.get("latest_analysis")
    alerts, err = client.get_alerts(limit=500)

    if err and not analysis_res:
        st.error(f"Cannot connect to Threat Intelligence API: {err}")
        return

    active_alerts = analysis_res.get("alerts", []) if analysis_res else (alerts or [])
    total_flows = analysis_res.get("total_flows", len(active_alerts)) if analysis_res else len(active_alerts)
    alert_count = len(active_alerts)
    attack_ratio = (alert_count / total_flows * 100.0) if total_flows > 0 else 0.0
    high_sev_count = sum(1 for a in active_alerts if a.get("severity") == "HIGH")

    # KPI Metrics Row
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Flows Analyzed", f"{total_flows:,}")
    c2.metric("Threat Alerts", f"{alert_count:,}", delta=f"{attack_ratio:.1f}% rate", delta_color="inverse")
    c3.metric("Attack Ratio", f"{attack_ratio:.1f}%")
    c4.metric("High Severity Alerts", f"{high_sev_count:,}", delta_color="inverse")

    st.markdown("---")

    if not active_alerts:
        st.info("No active alerts recorded yet. Head over to **Analyze Flows** to inspect traffic or simulate live network packets.")
        return

    df_alerts = pd.DataFrame(active_alerts)

    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.subheader("Attacks by Classification")
        if "attack_type" in df_alerts.columns and not df_alerts.empty:
            type_counts = df_alerts["attack_type"].value_counts().reset_index()
            type_counts.columns = ["Attack Type", "Count"]
            fig_pie = px.pie(
                type_counts,
                names="Attack Type",
                values="Count",
                color_discrete_sequence=px.colors.qualitative.Bold,
                hole=0.4,
            )
            fig_pie.update_layout(margin=dict(t=20, b=20, l=20, r=20))
            st.plotly_chart(fig_pie, use_container_width=True)

    with col_chart2:
        st.subheader("Alert Severity Distribution")
        if "severity" in df_alerts.columns and not df_alerts.empty:
            sev_counts = df_alerts["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            color_map = {"HIGH": "#e63946", "MEDIUM": "#f4a261", "LOW": "#2a9d8f"}
            fig_bar = px.bar(
                sev_counts,
                x="Severity",
                y="Count",
                color="Severity",
                color_discrete_map=color_map,
            )
            fig_bar.update_layout(showlegend=False, margin=dict(t=20, b=20, l=20, r=20))
            st.plotly_chart(fig_bar, use_container_width=True)

    st.subheader("Recent Security Events")
    preview_cols = [c for c in ["index", "attack_type", "final_score", "severity"] if c in df_alerts.columns]
    st.dataframe(df_alerts[preview_cols].tail(10), use_container_width=True)
