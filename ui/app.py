import sys
from pathlib import Path

# Ensure project root is in sys.path so 'ui' package is discoverable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
from ui.api_client import APIClient
from ui.views import alert_details, analyze, dashboard, live_monitor, performance, settings, threat_intel

st.set_page_config(
    page_title="Cyber IDS - Threat Intelligence System",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark modern styling accents
st.markdown(
    """
    <style>
    /* Completely disable Streamlit running/fading/dimming effect */
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
    /* Hide top right running man / status indicator widget */
    div[data-testid="stStatusWidget"] {
        display: none !important;
        visibility: hidden !important;
    }
    .main-header {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
    }
    .metric-card {
        background-color: #1e1e24;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #4361ee;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

client = APIClient()


@st.cache_data(ttl=3)
def _cached_health():
    return client.get_health()


with st.sidebar:
    st.image(
        "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=400&q=80",
        caption="AI-Powered Threat Engine",
    )
    st.title("Cyber IDS")
    st.caption("AI-Powered Intrusion Detection System")

    nav_choice = st.radio(
        "Navigation",
        [
            "Dashboard",
            "Analyze Flows",
            "Alert Details",
            "Model Performance",
            "Live Monitor",
            "Threat Intelligence",
            "Settings",
        ],
        index=0,
    )

    st.markdown("---")
    health, _ = _cached_health()
    if health and health.get("status") == "ok":
        st.success("API Connected")
        if health.get("model_loaded"):
            st.caption("Models: Loaded")
        else:
            st.caption("Models: Not Loaded")
    else:
        st.error("API Offline")

# Routing to views
if nav_choice == "Dashboard":
    dashboard.render(client)
elif nav_choice == "Analyze Flows":
    analyze.render(client)
elif nav_choice == "Alert Details":
    alert_details.render(client)
elif nav_choice == "Model Performance":
    performance.render(client)
elif nav_choice == "Live Monitor":
    live_monitor.render(client)
elif nav_choice == "Threat Intelligence":
    threat_intel.render(client)
elif nav_choice == "Settings":
    settings.render(client)

