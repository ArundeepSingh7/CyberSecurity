import streamlit as st
from ui.api_client import APIClient


def render(client: APIClient) -> None:
    """Render alert investigation view with SHAP and rule explanations."""
    st.title("Threat Alert Investigation")

    analysis_res = st.session_state.get("latest_analysis")
    alerts = analysis_res.get("alerts", []) if analysis_res else []

    if not alerts:
        fetched, err = client.get_alerts(limit=100)
        if not err and fetched:
            alerts = fetched

    if not alerts:
        st.info("No threat alerts available to inspect. Run an analysis in the **Analyze Flows** view first.")
        return

    alert_options = [
        f"Alert #{a.get('index', i)} | {a.get('attack_type', 'Unknown')} | Severity: {a.get('severity', 'LOW')} | Score: {a.get('final_score', 0.0):.2f}"
        for i, a in enumerate(alerts)
    ]

    selected_label = st.selectbox("Select Security Alert to Investigate", alert_options, index=0)
    selected_idx = alert_options.index(selected_label)
    alert = alerts[selected_idx]

    st.markdown("---")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Flow Index", f"#{alert.get('index', selected_idx)}")
    c2.metric("Classified Type", alert.get("attack_type", "Unknown"))
    c3.metric("Threat Confidence", f"{alert.get('final_score', 0.0):.2%}")

    sev = alert.get("severity", "LOW")
    sev_color = "red" if sev == "HIGH" else ("orange" if sev == "MEDIUM" else "green")
    c4.markdown(f"**Severity Level**\n\n:{sev_color}[{sev}]")

    st.subheader("Detection Reasoning & Explainability")
    reasons = alert.get("reasons", [])
    if reasons:
        st.write("Contributing heuristic rules and feature SHAP attributions:")
        for r in reasons:
            st.markdown(f"- **{r}**")
    else:
        st.write("No specific feature attribution triggered or capped for batch speed.")

    with st.expander("Raw Alert Payload"):
        st.json(alert)
