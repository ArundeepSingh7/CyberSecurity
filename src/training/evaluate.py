import json
from pathlib import Path
from typing import Any
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
import config
from src.core.types import FlowBatch
from src.detectors.base import BaseDetector


# Abstraction
def evaluate_model(
    detector: BaseDetector,
    batch: FlowBatch,
    y_true: list[str],
) -> dict[str, Any]:
    """Evaluate detector on binary and multi-class metrics."""
    scores = detector.score(batch)
    preds_binary = (scores >= 0.5).astype(int)
    y_true_binary = np.array([0 if lbl == "BENIGN" else 1 for lbl in y_true])

    acc_bin = float(accuracy_score(y_true_binary, preds_binary))
    prec_bin = float(precision_score(y_true_binary, preds_binary, zero_division=0))
    rec_bin = float(recall_score(y_true_binary, preds_binary, zero_division=0))
    f1_bin = float(f1_score(y_true_binary, preds_binary, zero_division=0))

    try:
        roc_auc = float(roc_auc_score(y_true_binary, scores))
    except Exception:
        roc_auc = 1.0

    cm_bin = confusion_matrix(y_true_binary, preds_binary, labels=[0, 1])
    tn, fp, fn, tp = cm_bin.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    preds_multi = detector.attack_type(batch)
    acc_multi = float(accuracy_score(y_true, preds_multi))
    macro_f1 = float(f1_score(y_true, preds_multi, average="macro", zero_division=0))

    report = classification_report(
        y_true,
        preds_multi,
        labels=config.ATTACK_CLASSES,
        output_dict=True,
        zero_division=0,
    )
    cm_multi = confusion_matrix(
        y_true,
        preds_multi,
        labels=config.ATTACK_CLASSES,
    ).tolist()

    top_features: list[dict[str, Any]] = []
    if hasattr(detector, "_model") and hasattr(detector._model, "feature_importances_"):
        imps = detector._model.feature_importances_
        sorted_indices = np.argsort(imps)[::-1][:15]
        for idx in sorted_indices:
            feat_name = (
                batch.feature_names[idx]
                if idx < len(batch.feature_names)
                else f"Feature_{idx}"
            )
            top_features.append(
                {"feature": feat_name, "importance": round(float(imps[idx]), 5)}
            )

    return {
        "binary": {
            "accuracy": round(acc_bin, 4),
            "precision": round(prec_bin, 4),
            "recall": round(rec_bin, 4),
            "f1": round(f1_bin, 4),
            "roc_auc": round(roc_auc, 4),
            "false_positive_rate": round(fpr, 4),
        },
        "multiclass": {
            "accuracy": round(acc_multi, 4),
            "macro_f1": round(macro_f1, 4),
            "report": report,
            "confusion_matrix": cm_multi,
        },
        "top_features": top_features,
    }


# Encapsulation
def save_metrics(metrics: dict[str, Any], path: Path | str) -> None:
    """Save metrics evaluation results to JSON."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
