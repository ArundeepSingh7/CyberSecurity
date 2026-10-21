import io
from pathlib import Path
import numpy as np
import pandas as pd
import streamlit as st
from ui.api_client import APIClient


def render(client: APIClient) -> None:
    """Render traffic analysis and flow simulation view."""
    st.title("Network Flow Analysis")

    # Configuration Controls
    col_strat, col_thresh = st.columns(2)
    with col_strat:
        strategies, s_err = client.get_strategies()
        strategy_options = strategies or ["weighted", "max", "vote"]
        selected_strategy = st.selectbox("Scoring Strategy", strategy_options, index=0)

    with col_thresh:
        selected_threshold = st.slider(
            "Alert Sensitivity Threshold",
            min_value=0.0,
            max_value=1.0,
            value=0.50,
            step=0.05,
        )

    st.markdown("---")

    col_upload, col_sim = st.columns([2, 1])
    file_to_send: bytes | None = None
    filename: str = "flows.csv"

    with col_upload:
        st.subheader("Upload Flow Data (CSV)")
        uploaded_file = st.file_uploader("Upload Network Flow CSV", type=["csv"])
        if uploaded_file is not None:
            file_to_send = uploaded_file.getvalue()
            filename = uploaded_file.name

    with col_sim:
        st.subheader("Live Traffic Simulation")
        st.write("Stream synthetic flows into the detection engine.")
        if st.button("Simulate 50 Live Flows", use_container_width=True):
            demo_path = Path("data/sample/demo_flows.csv")
            if demo_path.exists():
                demo_df = pd.read_csv(demo_path)
                sample_chunk = demo_df.sample(n=min(50, len(demo_df)))
            else:
                sample_data = {
                    "Destination Port": np.random.choice([21, 22, 80, 443, 8080], 50),
                    "Flow Duration": np.random.exponential(10000, 50),
                    "Total Fwd Packets": np.random.randint(1, 30, 50),
                    "Total Backward Packets": np.random.randint(1, 30, 50),
                    "Flow Bytes/s": np.random.exponential(5000, 50),
                    "Flow Packets/s": np.random.exponential(500, 50),
                    "SYN Flag Count": np.random.choice([0, 1], 50, p=[0.7, 0.3]),
                    "ACK Flag Count": np.random.choice([0, 1], 50, p=[0.3, 0.7]),
                    "Packet Length Mean": np.random.normal(500, 150, 50),
                    "Average Packet Size": np.random.normal(520, 150, 50),
                    "Init_Win_bytes_forward": np.random.choice([8192, 14600, 29200], 50),
                }
                sample_chunk = pd.DataFrame(sample_data)

            buf = io.StringIO()
            sample_chunk.to_csv(buf, index=False)
            file_to_send = buf.getvalue().encode("utf-8")
            filename = "simulated_flows.csv"
            st.success("Sample packet chunk generated.")

    if file_to_send is not None:
        with st.spinner("Analyzing network packets..."):
            res, err = client.analyze_csv(
                file_bytes=file_to_send,
                filename=filename,
                strategy=selected_strategy,
                threshold=selected_threshold,
            )

        if err:
            st.error(f"Analysis failed: {err}")
        elif res:
            st.session_state["latest_analysis"] = res
            st.success(
                f"Analysis Complete! Examined **{res['total_flows']}** flows. Generated **{res['alert_count']}** alerts."
            )

            alerts = res.get("alerts", [])
            if alerts:
                df_res = pd.DataFrame(alerts)
                cols_to_show = ["index", "attack_type", "final_score", "severity"]
                st.dataframe(df_res[cols_to_show], use_container_width=True)
            else:
                st.info("No suspicious anomalies detected in this traffic batch.")
