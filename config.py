from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_RAW_DATA_DIR = Path(r"C:\Users\arund\Downloads\MachineLearningCSV\MachineLearningCVE")
RAW_DATA_DIR = DEFAULT_RAW_DATA_DIR if DEFAULT_RAW_DATA_DIR.exists() else (DATA_DIR / "raw")
SAMPLE_DATA_DIR = DATA_DIR / "sample"
MODELS_DIR = PROJECT_ROOT / "models"

DEMO_FLOWS_PATH = SAMPLE_DATA_DIR / "demo_flows.csv"
METRICS_PATH = MODELS_DIR / "metrics.json"
ENGINE_PATH = MODELS_DIR / "engine.joblib"
PIPELINE_PATH = MODELS_DIR / "pipeline.joblib"

# Attack classes
ATTACK_CLASSES = [
    "BENIGN",
    "DoS",
    "DDoS",
    "PortScan",
    "BruteForce",
    "WebAttack",
    "Bot",
]

DROPPED_CLASSES = ["Infiltration", "Heartbleed"]

# Sampling and split
MAX_SAMPLES_PER_CLASS = 40000
RANDOM_SEED = 42
TEST_SPLIT_SIZE = 0.2

# Key features
KEY_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count",
    "Packet Length Mean",
    "Average Packet Size",
    "Init_Win_bytes_forward",
]

# Rule thresholds
DOS_FLOW_PACKETS_THRESHOLD = 5000.0
PORT_SCAN_MAX_FWD_PACKETS = 2
PORT_SCAN_MIN_SYN_FLAGS = 1
BRUTE_FORCE_PORTS = {21, 22}
BRUTE_FORCE_MIN_FWD_PACKETS = 10

# Threat engine settings
DEFAULT_THRESHOLD = 0.5
DEFAULT_WEIGHTS = {
    "RandomForest": 0.4,
    "XGBoost": 0.4,
    "DoSDetector": 0.2 / 3,
    "PortScanDetector": 0.2 / 3,
    "BruteForceDetector": 0.2 / 3,
}
DEFAULT_STRATEGY = "weighted"
SEVERITY_HIGH_THRESHOLD = 0.8
SEVERITY_MEDIUM_THRESHOLD = 0.6

# Live capture / target app settings
TARGET_HOST = "127.0.0.1"          # MUST remain localhost for safety
TARGET_APP_PORT = 5000
LIVE_WINDOW_SECONDS = 2            # packet aggregation window
LIVE_MAX_ALERTS_MEMORY = 200       # rolling in-memory deque size
# Windows loopback interface name for Scapy (requires Npcap)
LOOPBACK_IFACE = "\\Device\\NPF_Loopback"

# Threat intelligence SQLite store
INTEL_DB_PATH = PROJECT_ROOT / "threat_intel.db"
