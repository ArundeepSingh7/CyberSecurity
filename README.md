# cyber_ids: AI-Powered Cyberattack Detection & Threat Intelligence

`cyber_ids` is a modular, production-ready Intrusion Detection & Threat Intelligence System built using clean Object-Oriented Programming (OOP) principles, machine learning (Random Forest, XGBoost), SHAP explainability, and specialized rule-based detectors.

---

## 1. Quick Start & Run Commands

Execute all commands from the project root:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Place CICIDS2017 dataset CSVs in data/raw/
# Download the 8 CSV files ("MachineLearningCVE") from the UNB CIC "IDS 2017" official dataset page or Kaggle:
# https://www.unb.ca/cic/datasets/ids-2017.html
# Place all CSVs directly into data/raw/

# 3. Train models and generate demo artifacts
python -m src.training.train

# 4. Start the FastAPI backend
uvicorn api.main:app --reload

# 5. Launch the Streamlit dashboard UI (in a separate terminal)
streamlit run ui/app.py

# 6. Run unit tests
pytest -q
```

---

## 2. System Architecture

- **Data Pipeline**: Cleans headers, handles infinities/NaNs, removes duplicates, and standardizes multi-class labels into 7 core categories (`BENIGN`, `DoS`, `DDoS`, `PortScan`, `BruteForce`, `WebAttack`, `Bot`).
- **Feature Pipeline (`FeaturePipeline`)**: Encapsulates median imputation and standard scaling, preserving feature schemas.
- **Threat Engine (`ThreatEngine`)**: Composes multiple detectors (`RandomForestDetector`, `XGBoostDetector`, `DoSDetector`, `PortScanDetector`, `BruteForceDetector`) and dynamically aggregates their scores using runtime-swappable strategies (`WeightedAverage`, `MaxScore`, `MajorityVote`).
- **Explainability**: Leverages TreeExplainer / SHAP values with feature importance fallback to provide human-readable justification for alerts.
- **FastAPI Backend**: Serves REST endpoints for flow analysis, alerts, runtime strategy configuration, and model evaluation metrics.
- **Streamlit Frontend**: Decoupled interface communicating strictly through HTTP REST requests to provide interactive KPI dashboards, live traffic simulation, alert investigation, and model performance comparisons.

---

## 3. Object-Oriented Principles Implemented

| OOP Concept | Core Implementation |
|---|---|
| **Abstraction** | `BaseDetector(ABC)` template method pattern (`fit`, `score`, `attack_type`, `predict`, `explain`) and `ScoringStrategy(ABC)` |
| **Encapsulation** | `FeaturePipeline` (`_pipeline`, `_columns`, `_fitted`), read-only detector properties (`name`, `is_fitted`) |
| **Inheritance** | Multi-level inheritance: `BaseDetector -> RuleBasedDetector -> DoSDetector / PortScanDetector / BruteForceDetector` and `BaseDetector -> RandomForestDetector / XGBoostDetector` |
| **Polymorphism** | `ThreatEngine` uniformly evaluates heterogeneous detectors via common `score()`, `attack_type()`, and `explain()` interfaces; swappable `ScoringStrategy` algorithms |
| **Composition** | `ThreatEngine` HAS-A `FeaturePipeline`, HAS-A `list[BaseDetector]`, and HAS-A `ScoringStrategy` |
| **Factory** | `DetectorFactory.create(key)` and `DetectorFactory.create_many(keys)` with strategy helpers |

---

## 4. Live Testing Demo — "I did X, it alerted Y"

> **Safety**: All attack scripts hardcode `target = "127.0.0.1"` and refuse to run against any non-localhost target. For educational/demonstration use only against your own local environment.

### Prerequisites

- **Windows**: Install [Npcap](https://npcap.com) (required by Scapy for loopback capture). Run terminals as **Administrator**.
- **Linux/Mac**: Run with `sudo` for raw socket access.

### Step-by-step Demo

```bash
# Terminal 1 — Train models (one-time, already done if you ran step 3 above)
python -m src.training.train

# Terminal 2 — FastAPI backend (must be Administrator on Windows for capture)
uvicorn api.main:app --reload

# Terminal 3 — Toy target app (the thing you will "attack")
python -m target_app.app
# → Listening on http://127.0.0.1:5000

# Terminal 4 — Streamlit dashboard
streamlit run ui/app.py
# → Open "Live Monitor" in sidebar → click "Start Live Capture"

# Terminal 5 — Launch an attack (pick one, or run all three in sequence)
python -m attacks.run_attack --type portscan  --duration 10
python -m attacks.run_attack --type dos       --duration 10
python -m attacks.run_attack --type bruteforce --duration 10
```

Watch alerts appear on the **Live Monitor** page within 2–4 seconds of each attack.
Switch to **Threat Intelligence** to see MITRE Attack technique mapping and IP reputation scores.

### 5. How to Verify an Attack Really Reached the Model

1. Run attack simulation:
   ```bash
   python -m attacks.run_attack --type dos --duration 10
   ```
2. Watch the uvicorn terminal logs -- you should see the 5 trace lines printing during the attack window:
   - `[capture] N packets captured in window` (raw packet count)
   - `[aggregate] M flows built` (output of flow aggregator)
   - `[pipeline] batch shape: (M, F)` (features transformed by trained FeaturePipeline)
   - `[engine] scores: {detector_name: [scores]}` (evaluated by trained ThreatEngine)
   - `[alert] K alerts generated (threshold=T, strategy=S)`
3. On the Live Monitor page, open the "Pipeline trace" expander on the new alert row and confirm `detector_scores` shows non-zero values from `RandomForest` and `XGBoost` specifically (not just the rule detector) -- this confirms that the trained machine learning models evaluated the live flow features directly.

---

### New Folder Structure (live testing additions)

```
live/                       # Packet capture & live analysis loop
  flow_aggregator.py        # Packet -> flow feature aggregation (CICFlowMeter approximation)
  stream_runner.py          # Background thread: capture -> engine -> alerts
target_app/                 # Toy Flask app to attack (localhost only)
  app.py                    # Endpoints: /, /api/items, /login, /slow
attacks/                    # Simulated attack scripts
  attack_base.py            # BaseAttack(ABC) with _check_target() safety guard
  port_scan_attack.py       # Probes common ports via plain sockets
  dos_attack.py             # Floods /slow via thread pool (modest rate)
  bruteforce_attack.py      # Tries 15-password wordlist against /login
  run_attack.py             # CLI: python -m attacks.run_attack --type dos
threat_intel/               # Persistence & enrichment
  mitre_map.py              # Static MITRE Attack lookup (offline)
  ip_reputation.py          # Local score per source IP with time decay
  intel_store.py            # SQLite alerts table (threat_intel.db)
ui/views/
  live_monitor.py           # Start/Stop + real-time alert feed
  threat_intel.py           # IP reputation, MITRE chart, alert timeline
```

