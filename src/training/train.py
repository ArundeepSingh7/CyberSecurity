import argparse
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import config
from src.core.exceptions import DataLoadError
from src.data.loader import load_raw_dataset
from src.detectors.ml_detectors import RandomForestDetector, XGBoostDetector
from src.detectors.rule_detectors import BruteForceDetector, DoSDetector, PortScanDetector
from src.engine.threat_engine import ThreatEngine
from src.features.pipeline import FeaturePipeline
from src.training.evaluate import evaluate_model, save_metrics


# Abstraction
def generate_synthetic_dataset(num_samples: int = 4000) -> pd.DataFrame:
    """Generate synthetic network flow dataset matching CICIDS2017 schema."""
    np.random.seed(config.RANDOM_SEED)
    classes = config.ATTACK_CLASSES
    records: list[dict[str, float | str]] = []

    for i in range(num_samples):
        cls_name = classes[i % len(classes)]
        is_attack = 0 if cls_name == "BENIGN" else 1

        dest_port = 80.0
        fwd_pkts = float(np.random.randint(1, 20))
        bwd_pkts = float(np.random.randint(1, 20))
        flow_duration = float(np.random.exponential(10000))
        flow_bytes_s = float(np.random.exponential(5000))
        flow_pkts_s = float(np.random.exponential(100))
        syn_flags = float(np.random.choice([0, 1], p=[0.8, 0.2]))
        ack_flags = float(np.random.choice([0, 1], p=[0.3, 0.7]))
        pkt_len_mean = float(np.random.normal(500, 150))
        avg_pkt_size = float(np.random.normal(520, 150))
        init_win_bytes = float(np.random.choice([8192, 14600, 29200, 65535]))

        if cls_name == "DoS":
            flow_pkts_s = float(np.random.uniform(6000, 15000))
            fwd_pkts = float(np.random.randint(50, 200))
        elif cls_name == "PortScan":
            fwd_pkts = 1.0
            syn_flags = 1.0
            dest_port = float(np.random.choice([21, 22, 80, 443, 8080]))
        elif cls_name == "BruteForce":
            dest_port = float(np.random.choice([21, 22]))
            fwd_pkts = float(np.random.randint(15, 60))
        elif cls_name == "DDoS":
            flow_pkts_s = float(np.random.uniform(4000, 10000))
            fwd_pkts = float(np.random.randint(30, 150))
        elif cls_name == "WebAttack":
            dest_port = float(np.random.choice([80, 443, 8080]))
            pkt_len_mean = float(np.random.uniform(1200, 2500))
        elif cls_name == "Bot":
            flow_duration = float(np.random.uniform(50000, 200000))
            fwd_pkts = float(np.random.randint(20, 80))

        row: dict[str, float | str] = {
            "Destination Port": dest_port,
            "Flow Duration": flow_duration,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Flow Bytes/s": max(0.0, flow_bytes_s),
            "Flow Packets/s": max(0.0, flow_pkts_s),
            "SYN Flag Count": syn_flags,
            "ACK Flag Count": ack_flags,
            "Packet Length Mean": max(10.0, pkt_len_mean),
            "Average Packet Size": max(10.0, avg_pkt_size),
            "Init_Win_bytes_forward": init_win_bytes,
            "Label": cls_name,
            "attack_type": cls_name,
            "is_attack": is_attack,
        }
        records.append(row)

    return pd.DataFrame(records)


def main() -> None:
    """Run end-to-end model training, evaluation, and serialization."""
    parser = argparse.ArgumentParser(description="Train cyber_ids detection models.")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=config.RAW_DATA_DIR,
        help="Path to directory containing raw CICIDS2017 CSV files.",
    )
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Train on synthetic benchmark data if raw CSVs are not present.",
    )
    args = parser.parse_args()

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    config.SAMPLE_DATA_DIR.mkdir(parents=True, exist_ok=True)

    print("=== Cyber IDS Model Training ===")
    use_synthetic = args.synthetic
    data_dir = args.data_dir

    try:
        if not use_synthetic:
            print(f"Loading raw CICIDS2017 dataset from {data_dir}...")
            df = load_raw_dataset(data_dir)
            print(f"Successfully loaded {len(df):,} samples across classes:")
            for cls_name, count in df["attack_type"].value_counts().items():
                print(f"  - {cls_name}: {count:,} samples")
        else:
            print("Generating synthetic dataset for verification/demo...")
            df = generate_synthetic_dataset()
    except DataLoadError as e:
        print(f"\n[Warning] {e}")
        print("To download the dataset, visit: https://www.unb.ca/cic/datasets/ids-2017.html")
        print(f"Placing raw CSV files into {data_dir} is required for training on real data.")
        print("Falling back to synthetic training mode to create runnable models...")
        df = generate_synthetic_dataset()

    print(f"\nTotal dataset shape: {df.shape}")

    train_df, test_df = train_test_split(
        df,
        test_size=config.TEST_SPLIT_SIZE,
        stratify=df["attack_type"],
        random_state=config.RANDOM_SEED,
    )
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    print(f"Train split: {len(train_df)}, Test split: {len(test_df)}")

    # Encapsulation
    pipeline = FeaturePipeline()
    pipeline.fit(train_df)
    pipeline.save(config.PIPELINE_PATH)
    print(f"Feature pipeline saved to {config.PIPELINE_PATH}")

    train_batch = pipeline.make_batch(train_df)
    test_batch = pipeline.make_batch(test_df)

    y_train = train_df["attack_type"].tolist()
    y_test = test_df["attack_type"].tolist()

    # Load Optuna tuned params if available
    best_params_path = config.MODELS_DIR / "best_params.json"
    rf_params = {}
    xgb_params = {}
    if best_params_path.exists():
        import json
        with open(best_params_path, "r") as f:
            saved_p = json.load(f)
        rf_params = saved_p.get("RandomForest", {})
        xgb_params = saved_p.get("XGBoost", {})
        print(f"Applying Optuna best parameters:")
        print(f"  RF: {rf_params}")
        print(f"  XGB: {xgb_params}")

    # Inheritance
    print("Training Random Forest Detector with optimal parameters...")
    rf_detector = RandomForestDetector(**rf_params)
    rf_detector.fit(train_batch, labels=y_train)

    print("Training XGBoost Detector with optimal parameters...")
    xgb_detector = XGBoostDetector(**xgb_params)
    xgb_detector.fit(train_batch, labels=y_train)

    # Evaluation
    print("Evaluating models on test batch...")
    rf_eval = evaluate_model(rf_detector, test_batch, y_test)
    xgb_eval = evaluate_model(xgb_detector, test_batch, y_test)

    metrics = {
        "RandomForest": rf_eval,
        "XGBoost": xgb_eval,
    }
    save_metrics(metrics, config.METRICS_PATH)
    print(f"Metrics saved to {config.METRICS_PATH}")
    print(f"  RF Binary Accuracy: {rf_eval['binary']['accuracy'] * 100:.2f}% | Multi-class Macro F1: {rf_eval['multiclass']['macro_f1']:.4f}")
    print(f"  XGB Binary Accuracy: {xgb_eval['binary']['accuracy'] * 100:.2f}% | Multi-class Macro F1: {xgb_eval['multiclass']['macro_f1']:.4f}")

    demo_size = min(3000, len(test_df))
    demo_df = test_df.sample(n=demo_size, random_state=config.RANDOM_SEED)
    demo_df.to_csv(config.DEMO_FLOWS_PATH, index=False)
    print(f"Saved {demo_size} representative demo flows to {config.DEMO_FLOWS_PATH}")

    # Composition
    dos_detector = DoSDetector()
    portscan_detector = PortScanDetector()
    bruteforce_detector = BruteForceDetector()

    engine = ThreatEngine(
        pipeline=pipeline,
        detectors=[
            rf_detector,
            xgb_detector,
            dos_detector,
            portscan_detector,
            bruteforce_detector,
        ],
        strategy=config.DEFAULT_STRATEGY,
        weights=config.DEFAULT_WEIGHTS,
        threshold=config.DEFAULT_THRESHOLD,
    )
    engine.save(config.ENGINE_PATH)
    print(f"ThreatEngine saved to {config.ENGINE_PATH}")

    # Run inference on unlabeled test dataset
    unlabeled_path = Path(r"C:\Users\arund\Downloads\test_cicids_unlabeled.csv")
    if not unlabeled_path.exists():
        unlabeled_path = config.DATA_DIR / "raw" / "test_cicids_unlabeled.csv"
    if unlabeled_path.exists():
        print(f"\nRunning predictions on unlabeled dataset: {unlabeled_path.name}...")
        u_raw = pd.read_csv(unlabeled_path, low_memory=False, encoding_errors="replace")
        from src.data.loader import clean_dataframe
        u_clean = clean_dataframe(u_raw)
        u_batch = pipeline.make_batch(u_clean)

        u_clean["Pred_RF_Attack"] = rf_detector.attack_type(u_batch)
        u_clean["Pred_RF_Score"] = np.round(rf_detector.score(u_batch), 4)
        u_clean["Pred_XGB_Attack"] = xgb_detector.attack_type(u_batch)
        u_clean["Pred_XGB_Score"] = np.round(xgb_detector.score(u_batch), 4)

        pred_file = config.DATA_DIR / "test_cicids_predictions.csv"
        pred_file.parent.mkdir(parents=True, exist_ok=True)
        u_clean.to_csv(pred_file, index=False)
        print(f"Saved {len(u_clean)} predictions to {pred_file}")

    print("\nTraining & evaluation completed successfully on real CICIDS dataset!")


if __name__ == "__main__":
    main()
