import pandas as pd
import plotly.express as px
import plotly.figure_factory as ff
import streamlit as st
from ui.api_client import APIClient


def render(client: APIClient) -> None:
    """Render model performance comparison and evaluation metrics."""
    st.title("Model Performance & Benchmarks")

    metrics, err = client.get_metrics()
    if err:
        st.error(f"Could not load performance metrics: {err}")
        st.info("Train the models first by executing: `python -m src.training.train`")
        return

    if not metrics:
        st.warning("No metrics data returned from server.")
        return

    rf_data = metrics.get("RandomForest", {})
    xgb_data = metrics.get("XGBoost", {})

    st.subheader("Model Comparison Matrix")
    comparison = {
        "Metric": [
            "Binary Accuracy",
            "Precision",
            "Recall",
            "F1-Score",
            "ROC-AUC",
            "False Positive Rate",
            "Multi-class Accuracy",
            "Macro F1",
        ],
        "Random Forest": [
            f"{rf_data.get('binary', {}).get('accuracy', 0.0):.4f}",
            f"{rf_data.get('binary', {}).get('precision', 0.0):.4f}",
            f"{rf_data.get('binary', {}).get('recall', 0.0):.4f}",
            f"{rf_data.get('binary', {}).get('f1', 0.0):.4f}",
            f"{rf_data.get('binary', {}).get('roc_auc', 0.0):.4f}",
            f"{rf_data.get('binary', {}).get('false_positive_rate', 0.0):.4f}",
            f"{rf_data.get('multiclass', {}).get('accuracy', 0.0):.4f}",
            f"{rf_data.get('multiclass', {}).get('macro_f1', 0.0):.4f}",
        ],
        "XGBoost": [
            f"{xgb_data.get('binary', {}).get('accuracy', 0.0):.4f}",
            f"{xgb_data.get('binary', {}).get('precision', 0.0):.4f}",
            f"{xgb_data.get('binary', {}).get('recall', 0.0):.4f}",
            f"{xgb_data.get('binary', {}).get('f1', 0.0):.4f}",
            f"{xgb_data.get('binary', {}).get('roc_auc', 0.0):.4f}",
            f"{xgb_data.get('binary', {}).get('false_positive_rate', 0.0):.4f}",
            f"{xgb_data.get('multiclass', {}).get('accuracy', 0.0):.4f}",
            f"{xgb_data.get('multiclass', {}).get('macro_f1', 0.0):.4f}",
        ],
    }
    st.table(pd.DataFrame(comparison))

    tab_rf, tab_xgb = st.tabs(["Random Forest Details", "XGBoost Details"])

    for model_name, mdata, tab in [
        ("Random Forest", rf_data, tab_rf),
        ("XGBoost", xgb_data, tab_xgb),
    ]:
        with tab:
            st.markdown(f"### {model_name} Evaluation")
            col1, col2 = st.columns(2)
            col1.metric("ROC-AUC", f"{mdata.get('binary', {}).get('roc_auc', 0.0):.4f}")
            col2.metric("False Positive Rate (FPR)", f"{mdata.get('binary', {}).get('false_positive_rate', 0.0):.4%}")

            # Confusion Matrix Heatmap
            cm = mdata.get("multiclass", {}).get("confusion_matrix")
            labels = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Bot"]
            if cm:
                st.subheader("Confusion Matrix")
                fig_cm = px.imshow(
                    cm,
                    x=labels[: len(cm)],
                    y=labels[: len(cm)],
                    labels=dict(x="Predicted Class", y="True Class", color="Count"),
                    color_continuous_scale="Blues",
                    text_auto=True,
                )
                fig_cm.update_layout(margin=dict(t=20, b=20, l=20, r=20))
                st.plotly_chart(fig_cm, use_container_width=True)

            # Feature Importance Bar Chart
            top_feats = mdata.get("top_features", [])
            if top_feats:
                st.subheader("Top 15 Feature Importances")
                df_feat = pd.DataFrame(top_feats)
                fig_feat = px.bar(
                    df_feat.sort_values("importance", ascending=True),
                    x="importance",
                    y="feature",
                    orientation="h",
                    color="importance",
                    color_continuous_scale="Viridis",
                )
                fig_feat.update_layout(
                    xaxis_title="Importance Score",
                    yaxis_title="Feature",
                    margin=dict(t=20, b=20, l=20, r=20),
                )
                st.plotly_chart(fig_feat, use_container_width=True)
