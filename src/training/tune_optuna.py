"""
Hyperparameter tuning with Optuna for Cyber IDS Random Forest and XGBoost detectors.
Trains on user-provided CICIDS dataset combined with sample data.
"""
import argparse
import json
from pathlib import Path
from typing import Any
import numpy as np
import optuna
import pandas as pd
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import f1_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

import config
from src.data.labels import map_label
from src.data.loader import clean_dataframe
from src.detectors.ml_detectors import RandomForestDetector, XGBoostDetector
from src.detectors.rule_detectors import BruteForceDetector, DoSDetector, PortScanDetector
from src.engine.threat_engine import ThreatEngine
from src.features.pipeline import FeaturePipeline
from src.training.evaluate import evaluate_model, save_metrics

# Suppress Optuna verbose logs (show only warnings/summary)
optuna.logging.set_verbosity(optuna.logging.WARNING)


def load_combined_training_data(user_csv_path: Path, sample_csv_path: Path) -> pd.DataFrame:
    """Load and combine user dataset with sample flows for full class coverage."""
    dfs: list[pd.DataFrame] = []

    if user_csv_path.exists():
        print(f"Loading user dataset from: {user_csv_path}")
        u_df = pd.read_csv(user_csv_path, low_memory=False, encoding_errors="replace")
        u_df = clean_dataframe(u_df)
        if "Label" in u_df.columns:
            u_df["attack_type"] = u_df["Label"].apply(map_label)
        u_df = u_df.dropna(subset=["attack_type"]).reset_index(drop=True)
        print(f"User data loaded: {len(u_df)} samples")
        dfs.append(u_df)
    else:
        print(f"Warning: {user_csv_path} not found.")

    if sample_csv_path.exists():
        print(f"Loading reference sample data from: {sample_csv_path}")
        s_df = pd.read_csv(sample_csv_path, low_memory=False, encoding_errors="replace")
        s_df = clean_dataframe(s_df)
        if "Label" in s_df.columns and "attack_type" not in s_df.columns:
            s_df["attack_type"] = s_df["Label"].apply(map_label)
        s_df = s_df.dropna(subset=["attack_type"]).reset_index(drop=True)
        print(f"Sample data loaded: {len(s_df)} samples")
        dfs.append(s_df)

    if not dfs:
        raise ValueError("No data found to train on.")

    combined = pd.concat(dfs, ignore_index=True)
    combined = combined.drop_duplicates(subset=[c for c in combined.columns if c not in {"Label", "attack_type", "is_attack"}])
    combined = combined.sample(frac=1.0, random_state=config.RANDOM_SEED).reset_index(drop=True)
    combined["is_attack"] = (combined["attack_type"] != "BENIGN").astype(int)

    print("\nCombined dataset distribution:")
    for cls_name, cnt in combined["attack_type"].value_counts().items():
        print(f"  - {cls_name}: {cnt} samples")

    return combined


def tune_random_forest(
    X_scaled: np.ndarray,
    y_encoded: np.ndarray,
    n_trials: int = 15,
) -> dict[str, Any]:
    """Tune RandomForestClassifier using Optuna and StratifiedKFold."""
    print(f"\n[Optuna] Starting Random Forest tuning ({n_trials} trials)...")

    def objective(trial: optuna.Trial) -> float:
        n_estimators = trial.suggest_int("n_estimators", 50, 250, step=25)
        max_depth = trial.suggest_int("max_depth", 5, 25)
        min_samples_split = trial.suggest_int("min_samples_split", 2, 8)
        min_samples_leaf = trial.suggest_int("min_samples_leaf", 1, 4)
        max_features = trial.suggest_categorical("max_features", ["sqrt", "log2", None])

        skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=config.RANDOM_SEED)
        f1_scores = []

        for train_idx, val_idx in skf.split(X_scaled, y_encoded):
            X_tr, X_val = X_scaled[train_idx], X_scaled[val_idx]
            y_tr, y_val = y_encoded[train_idx], y_encoded[val_idx]

            clf = RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                min_samples_split=min_samples_split,
                min_samples_leaf=min_samples_leaf,
                max_features=max_features,
                class_weight="balanced",
                n_jobs=-1,
                random_state=config.RANDOM_SEED,
            )
            clf.fit(X_tr, y_tr)
            preds = clf.predict(X_val)
            f1_scores.append(f1_score(y_val, preds, average="macro", zero_division=0))

        return float(np.mean(f1_scores))

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=n_trials)

    print(f"[Optuna] Best RF macro F1: {study.best_value:.4f}")
    print(f"[Optuna] Best RF parameters: {study.best_params}")
    return study.best_params


def tune_xgboost(
    X_scaled: np.ndarray,
    y_encoded: np.ndarray,
    num_classes: int,
    n_trials: int = 15,
) -> dict[str, Any]:
    """Tune XGBClassifier using Optuna and StratifiedKFold."""
    print(f"\n[Optuna] Starting XGBoost tuning ({n_trials} trials)...")

    def objective(trial: optuna.Trial) -> float:
        n_estimators = trial.suggest_int("n_estimators", 80, 250, step=30)
        max_depth = trial.suggest_int("max_depth", 3, 9)
        learning_rate = trial.suggest_float("learning_rate", 0.02, 0.3, log=True)
        subsample = trial.suggest_float("subsample", 0.6, 1.0)
        colsample_bytree = trial.suggest_float("colsample_bytree", 0.6, 1.0)
        min_child_weight = trial.suggest_int("min_child_weight", 1, 5)

        skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=config.RANDOM_SEED)
        f1_scores = []

        for train_idx, val_idx in skf.split(X_scaled, y_encoded):
            X_tr, X_val = X_scaled[train_idx], X_scaled[val_idx]
            y_tr, y_val = y_encoded[train_idx], y_encoded[val_idx]

            sample_weights = compute_sample_weight("balanced", y_tr)
            clf = XGBClassifier(
                objective="multi:softprob",
                num_class=num_classes,
                n_estimators=n_estimators,
                max_depth=max_depth,
                learning_rate=learning_rate,
                subsample=subsample,
                colsample_bytree=colsample_bytree,
                min_child_weight=min_child_weight,
                tree_method="hist",
                random_state=config.RANDOM_SEED,
            )
            clf.fit(X_tr, y_tr, sample_weight=sample_weights)
            preds = clf.predict(X_val)
            f1_scores.append(f1_score(y_val, preds, average="macro", zero_division=0))

        return float(np.mean(f1_scores))

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=n_trials)

    print(f"[Optuna] Best XGB macro F1: {study.best_value:.4f}")
    print(f"[Optuna] Best XGB parameters: {study.best_params}")
    return study.best_params


def run_unlabeled_predictions(
    engine: ThreatEngine,
    unlabeled_csv_path: Path,
    out_csv_path: Path,
) -> None:
    """Run trained ThreatEngine on unlabeled flows and output predictions."""
    if not unlabeled_csv_path.exists():
        print(f"No unlabeled file found at {unlabeled_csv_path}, skipping inference.")
        return

    print(f"\nRunning inference on unlabeled test dataset: {unlabeled_csv_path}...")
    unlabeled_df = pd.read_csv(unlabeled_csv_path, low_memory=False, encoding_errors="replace")
    clean_unlabeled = clean_dataframe(unlabeled_df)

    alerts = engine.analyze(clean_unlabeled, threshold=config.DEFAULT_THRESHOLD)
    print(f"Generated {len(alerts)} alerts on {len(clean_unlabeled)} unlabeled flows.")

    # Get predictions for all rows
    batch = engine._pipeline.make_batch(clean_unlabeled)
    rf_detector = [d for d in engine.detectors if d.name == "RandomForest"][0]
    xgb_detector = [d for d in engine.detectors if d.name == "XGBoost"][0]

    clean_unlabeled["Pred_RF_Score"] = np.round(rf_detector.score(batch), 4)
    clean_unlabeled["Pred_RF_Attack"] = rf_detector.attack_type(batch)
    clean_unlabeled["Pred_XGB_Score"] = np.round(xgb_detector.score(batch), 4)
    clean_unlabeled["Pred_XGB_Attack"] = xgb_detector.attack_type(batch)

    out_csv_path.parent.mkdir(parents=True, exist_ok=True)
    clean_unlabeled.to_csv(out_csv_path, index=False)
    print(f"Saved predicted labels to: {out_csv_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Optuna Hyperparameter Tuning & Model Training")
    parser.add_argument(
        "--user-data",
        type=Path,
        default=Path("data/raw/test_cicids_labeled.csv"),
        help="Path to user labeled CSV.",
    )
    parser.add_argument(
        "--sample-data",
        type=Path,
        default=config.SAMPLE_DATA_DIR / "demo_flows.csv",
        help="Path to demo/sample flows CSV.",
    )
    parser.add_argument(
        "--unlabeled-data",
        type=Path,
        default=Path("data/raw/test_cicids_unlabeled.csv"),
        help="Path to unlabeled CSV for validation.",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=15,
        help="Number of Optuna trials per model (default: 15).",
    )
    parser.add_argument(
        "--retune",
        action="store_true",
        help="Force re-running Optuna tuning trials instead of using cached best_params.json.",
    )
    args = parser.parse_args()

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  CYBER IDS - OPTUNA HYPERPARAMETER TUNING & RETRAINING")
    print("=" * 60)

    # 1. Load dataset
    df = load_combined_training_data(args.user_data, args.sample_data)

    # 2. Train-test split
    train_df, test_df = train_test_split(
        df,
        test_size=config.TEST_SPLIT_SIZE,
        stratify=df["attack_type"],
        random_state=config.RANDOM_SEED,
    )
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)
    print(f"Split completed: Train={len(train_df)}, Test={len(test_df)}")

    # 3. Fit pipeline
    pipeline = FeaturePipeline()
    pipeline.fit(train_df)
    pipeline.save(config.PIPELINE_PATH)
    print(f"Feature pipeline saved to {config.PIPELINE_PATH}")

    train_batch = pipeline.make_batch(train_df)
    test_batch = pipeline.make_batch(test_df)

    classes = config.ATTACK_CLASSES
    y_train = train_df["attack_type"].tolist()
    y_test = test_df["attack_type"].tolist()
    y_train_encoded = np.array([classes.index(str(lbl)) for lbl in y_train])

    best_params_path = config.MODELS_DIR / "best_params.json"

    # 4. Optuna Tuning (or load existing best params)
    if best_params_path.exists() and not args.retune:
        print(f"\n[Optuna] Loading existing tuned hyperparameters from {best_params_path}")
        with open(best_params_path, "r") as f:
            cached_params = json.load(f)
        best_rf_params = cached_params.get("RandomForest", {})
        best_xgb_params = cached_params.get("XGBoost", {})
        print(f"  RF params: {best_rf_params}")
        print(f"  XGB params: {best_xgb_params}")
    else:
        best_rf_params = tune_random_forest(train_batch.scaled, y_train_encoded, n_trials=args.trials)
        best_xgb_params = tune_xgboost(train_batch.scaled, y_train_encoded, num_classes=len(classes), n_trials=args.trials)
        with open(best_params_path, "w") as f:
            json.dump({"RandomForest": best_rf_params, "XGBoost": best_xgb_params}, f, indent=2)
        print(f"\nBest hyperparameters saved to {best_params_path}")

    # 5. Fit tuned detectors
    print("\nTraining final RandomForest with Optuna hyperparameters...")
    rf_detector = RandomForestDetector(**best_rf_params)
    rf_detector.fit(train_batch, labels=y_train)

    print("Training final XGBoost with Optuna hyperparameters...")
    xgb_detector = XGBoostDetector(**best_xgb_params)
    xgb_detector.fit(train_batch, labels=y_train)

    # 6. Evaluation
    print("\nEvaluating tuned models on test set...")
    rf_eval = evaluate_model(rf_detector, test_batch, y_test)
    xgb_eval = evaluate_model(xgb_detector, test_batch, y_test)

    metrics = {
        "RandomForest": rf_eval,
        "XGBoost": xgb_eval,
    }
    save_metrics(metrics, config.METRICS_PATH)
    print(f"Metrics saved to {config.METRICS_PATH}")
    print(f"  [*] RF Binary Accuracy: {rf_eval['binary']['accuracy'] * 100:.2f}% (Macro F1: {rf_eval['multiclass']['macro_f1']:.4f})")
    print(f"  [*] XGB Binary Accuracy: {xgb_eval['binary']['accuracy'] * 100:.2f}% (Macro F1: {xgb_eval['multiclass']['macro_f1']:.4f})")

    # 7. ThreatEngine Composition
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
    print(f"\nThreatEngine successfully serialized to {config.ENGINE_PATH}")

    # 8. Run inference on unlabeled dataset
    pred_out_path = Path("data/test_cicids_predictions.csv")
    run_unlabeled_predictions(engine, args.unlabeled_data, pred_out_path)

    print("\n" + "=" * 60)
    print("  ALL MODELS SUCCESSFULLY TUNED & TRAINED ON USER DATA!")
    print("=" * 60)


if __name__ == "__main__":
    main()
