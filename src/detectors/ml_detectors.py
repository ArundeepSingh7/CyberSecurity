from typing import Any, Optional, Union
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier
import config
from src.core.types import FlowBatch
from src.detectors.base import BaseDetector


# Inheritance
class RandomForestDetector(BaseDetector):
    """Multi-class Random Forest threat detector."""

    def __init__(self, **params: Any) -> None:
        """Initialize Random Forest model and parameters."""
        super().__init__(name="RandomForest")
        self._classes = config.ATTACK_CLASSES
        self._feature_names: list[str] = []
        self._explainer: Optional[Any] = None
        rf_kwargs: dict[str, Any] = {
            "n_estimators": 200,
            "class_weight": "balanced",
            "n_jobs": -1,
            "random_state": config.RANDOM_SEED,
        }
        rf_kwargs.update(params)
        self._model = RandomForestClassifier(**rf_kwargs)

    # Polymorphism
    def _fit(self, batch: FlowBatch, labels: Any = None) -> None:
        """Train internal Random Forest classifier."""
        if labels is None:
            raise ValueError("Training requires class labels.")
        self._feature_names = list(batch.feature_names)
        y_encoded = np.array([self._classes.index(str(lbl)) for lbl in labels])
        self._model.fit(batch.scaled, y_encoded)

    # Polymorphism
    def _score(self, batch: FlowBatch) -> np.ndarray:
        """Return attack confidence score defined as 1 - P(BENIGN)."""
        probs = self._model.predict_proba(batch.scaled)
        benign_pos = list(self._model.classes_).index(0) if 0 in self._model.classes_ else None
        if benign_pos is None:
            return np.ones(len(batch.scaled), dtype=float)
        p_benign = probs[:, benign_pos]
        return 1.0 - p_benign

    # Polymorphism
    def _attack_type(self, batch: FlowBatch) -> list[str]:
        """Predict specific attack type via argmax over non-BENIGN classes (or BENIGN if score < 0.5)."""
        probs = self._model.predict_proba(batch.scaled)
        scores = self._score(batch)
        class_list = list(self._model.classes_)
        non_benign_indices = [idx for idx, cls_id in enumerate(class_list) if cls_id != 0]

        predictions: list[str] = []
        for i, row in enumerate(probs):
            if scores[i] < 0.35 or not non_benign_indices:
                predictions.append("BENIGN")
                continue
            best_pos = non_benign_indices[int(np.argmax(row[non_benign_indices]))]
            cls_id = class_list[best_pos]
            predictions.append(self._classes[cls_id])
        return predictions

    def explain(self, row: Union[dict[str, Any], pd.Series]) -> list[str]:
        """Return top explanatory features using SHAP or feature importances."""
        try:
            import shap

            if self._explainer is None:
                self._explainer = shap.TreeExplainer(self._model)

            row_dict = row.to_dict() if isinstance(row, pd.Series) else row
            features = [float(row_dict.get(k, 0.0)) for k in self._feature_names]
            val_arr = np.array(features).reshape(1, -1)
            shap_values = self._explainer.shap_values(val_arr)

            vals = (
                shap_values[1][0]
                if isinstance(shap_values, list) and len(shap_values) > 1
                else (shap_values[0] if len(shap_values.shape) == 2 else shap_values[0, :, 1])
            )
            top_idx = np.argsort(np.abs(vals))[-3:][::-1]
            return [
                f"{self._feature_names[i]} ({vals[i]:+.2f})"
                for i in top_idx
            ]
        except Exception:
            if hasattr(self._model, "feature_importances_") and self._feature_names:
                importances = self._model.feature_importances_
                top_idx = np.argsort(importances)[-3:][::-1]
                row_dict = row.to_dict() if isinstance(row, pd.Series) else row
                return [
                    f"{self._feature_names[i]}: {float(row_dict.get(self._feature_names[i], 0.0)):.1f}"
                    for i in top_idx
                ]
            return []


# Inheritance
class XGBoostDetector(BaseDetector):
    """Multi-class XGBoost threat detector."""

    def __init__(self, **params: Any) -> None:
        """Initialize XGBoost model and parameters."""
        super().__init__(name="XGBoost")
        self._classes = config.ATTACK_CLASSES
        self._feature_names: list[str] = []
        self._explainer: Optional[Any] = None
        xgb_kwargs: dict[str, Any] = {
            "objective": "multi:softprob",
            "num_class": len(self._classes),
            "n_estimators": 300,
            "max_depth": 8,
            "tree_method": "hist",
            "random_state": config.RANDOM_SEED,
        }
        xgb_kwargs.update(params)
        self._model = XGBClassifier(**xgb_kwargs)

    # Polymorphism
    def _fit(self, batch: FlowBatch, labels: Any = None) -> None:
        """Train internal XGBoost classifier using balanced sample weights."""
        if labels is None:
            raise ValueError("Training requires class labels.")
        self._feature_names = list(batch.feature_names)
        y_encoded = np.array([self._classes.index(str(lbl)) for lbl in labels])
        weights = compute_sample_weight("balanced", y_encoded)
        self._model.fit(batch.scaled, y_encoded, sample_weight=weights)

    # Polymorphism
    def _score(self, batch: FlowBatch) -> np.ndarray:
        """Return attack confidence score defined as 1 - P(BENIGN)."""
        probs = self._model.predict_proba(batch.scaled)
        p_benign = probs[:, 0]
        return 1.0 - p_benign

    # Polymorphism
    def _attack_type(self, batch: FlowBatch) -> list[str]:
        """Predict specific attack type via argmax over non-BENIGN classes (or BENIGN if score < 0.5)."""
        probs = self._model.predict_proba(batch.scaled)
        scores = self._score(batch)
        predictions: list[str] = []
        for i, row in enumerate(probs):
            if scores[i] < 0.35 or len(row) <= 1:
                predictions.append("BENIGN")
            else:
                non_benign_probs = row[1:]
                best_sub_idx = int(np.argmax(non_benign_probs))
                cls_id = best_sub_idx + 1
                predictions.append(self._classes[cls_id])
        return predictions

    def explain(self, row: Union[dict[str, Any], pd.Series]) -> list[str]:
        """Return top explanatory features using SHAP or feature importances."""
        try:
            import shap

            if self._explainer is None:
                self._explainer = shap.TreeExplainer(self._model)

            row_dict = row.to_dict() if isinstance(row, pd.Series) else row
            features = [float(row_dict.get(k, 0.0)) for k in self._feature_names]
            val_arr = np.array(features).reshape(1, -1)
            shap_values = self._explainer.shap_values(val_arr)

            vals = (
                shap_values[1][0]
                if isinstance(shap_values, list) and len(shap_values) > 1
                else (shap_values[0] if len(shap_values.shape) == 2 else shap_values[0, :, 1])
            )
            top_idx = np.argsort(np.abs(vals))[-3:][::-1]
            return [
                f"{self._feature_names[i]} ({vals[i]:+.2f})"
                for i in top_idx
            ]
        except Exception:
            if hasattr(self._model, "feature_importances_") and self._feature_names:
                importances = self._model.feature_importances_
                top_idx = np.argsort(importances)[-3:][::-1]
                row_dict = row.to_dict() if isinstance(row, pd.Series) else row
                return [
                    f"{self._feature_names[i]}: {float(row_dict.get(self._feature_names[i], 0.0)):.1f}"
                    for i in top_idx
                ]
            return []
