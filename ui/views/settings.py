import streamlit as st
from ui.api_client import APIClient


def render(client: APIClient) -> None:
    """Render system settings and backend API health diagnostics."""
    st.title("System Configuration & Diagnostics")

    st.subheader("API Service Status")
    health, err = client.get_health()

    if err:
        st.error(f"Backend API is unreachable: {err}")
        st.write("Ensure the FastAPI server is running with: `uvicorn api.main:app --reload`")
    else:
        st.success("Connected to Threat Intelligence API successfully.")
        c1, c2 = st.columns(2)
        c1.metric("API Status", health.get("status", "unknown").upper())
        c2.metric("Trained Model Loaded", "YES" if health.get("model_loaded") else "NO")

    st.markdown("---")
    st.subheader("Engine Detection Parameters")

    with st.form("settings_form"):
        new_strategy = st.selectbox(
            "Default Scoring Strategy",
            ["weighted", "max", "vote"],
            help="Weighted: combines RF (0.4), XGB (0.4), and rules (0.2). Max: highest detector score. Vote: ensemble consensus.",
        )
        new_threshold = st.slider(
            "Default Alert Sensitivity Threshold",
            min_value=0.1,
            max_value=0.9,
            value=0.5,
            step=0.05,
            help="Traffic scoring equal to or above this threshold triggers an alert.",
        )
        submitted = st.form_submit_button("Save Configuration", use_container_width=True)

        if submitted:
            res, update_err = client.update_config(strategy=new_strategy, threshold=new_threshold)
            if update_err:
                st.error(f"Failed to update settings: {update_err}")
            else:
                st.success("Engine settings updated successfully.")
