from pathlib import Path
from typing import Optional, Union
import joblib
import numpy as np
import pandas as pd
import config
from src.core.exceptions import ThreatEngineError
from src.core.types import FlowBatch
from src.detectors.base import BaseDetector
from src.detectors.factory import DetectorFactory
from src.engine.alert import Alert
from src.features.pipeline import FeaturePipeline
from src.scoring.strategies import ScoringStrategy, WeightedAverage


# Composition
class ThreatEngine:
    """Orchestrates feature transformation, heterogeneous detectors, and score aggregation."""

    def __init__(
        self,
        pipeline: FeaturePipeline,
        detectors: list[BaseDetector],
        strategy: Optional[Union[str, ScoringStrategy]] = None,
        weights: Optional[dict[str, float]] = None,
        threshold: float = config.DEFAULT_THRESHOLD,
    ) -> None:
        """Initialize engine composition."""
        self._pipeline: FeaturePipeline = pipeline
        self._detectors: list[BaseDetector] = detectors
        self._strategy: ScoringStrategy = (
            DetectorFactory.get_strategy(strategy)
            if strategy is not None
            else WeightedAverage()
        )
        self._weights: dict[str, float] = weights or dict(config.DEFAULT_WEIGHTS)
        self._threshold: float = threshold

    # Encapsulation
    @property
    def detectors(self) -> list[BaseDetector]:
        """Return registered detectors."""
        return list(self._detectors)

    # Encapsulation
    @property
    def strategy(self) -> ScoringStrategy:
        """Return active scoring strategy."""
        return self._strategy

    # Encapsulation
    @property
    def threshold(self) -> float:
        """Return alert threshold."""
        return self._threshold

    def set_threshold(self, threshold: float) -> None:
        """Update detection alert threshold."""
        self._threshold = float(threshold)

    def set_strategy(self, strategy: Union[str, ScoringStrategy]) -> None:
        """Update active scoring strategy at runtime."""
        self._strategy = DetectorFactory.get_strategy(strategy)

    # Polymorphism
    def analyze(
        self,
        df: Union[pd.DataFrame, FlowBatch],
        strategy: Optional[Union[str, ScoringStrategy]] = None,
        threshold: Optional[float] = None,
    ) -> list[Alert]:
        """Analyze flow dataframe or FlowBatch and generate alerts for suspicious activity."""
        if isinstance(df, FlowBatch):
            if len(df) == 0:
                return []
            batch = df
        else:
            if df.empty:
                return []
            batch = self._pipeline.make_batch(df)

        active_strategy = (
            DetectorFactory.get_strategy(strategy)
            if strategy is not None
            else self._strategy
        )
        active_threshold = threshold if threshold is not None else self._threshold

        scores: dict[str, np.ndarray] = {}
        types: dict[str, list[str]] = {}
        for d in self._detectors:
            scores[d.name] = d.score(batch)
            types[d.name] = d.attack_type(batch)

        final_scores = active_strategy.combine(scores, self._weights)

        alerts: list[Alert] = []
        alert_count = 0
        max_explained_alerts = 50

        for i, score_val in enumerate(final_scores):
            if score_val >= active_threshold:
                # Pick candidate non-benign types sorted by detector confidence score descending
                fired_candidates = [
                    (float(scores[d.name][i]), types[d.name][i], d.name)
                    for d in self._detectors
                    if types[d.name][i] not in {"BENIGN", "Anomaly", ""}
                ]
                if fired_candidates:
                    fired_candidates.sort(key=lambda x: x[0], reverse=True)
                    pred_type = fired_candidates[0][1]
                else:
                    best_detector = max(self._detectors, key=lambda d: scores[d.name][i])
                    best_type = types[best_detector.name][i]
                    if best_type not in {"BENIGN", "Anomaly", ""}:
                        pred_type = best_type
                    else:
                        pred_type = "DoS" if score_val >= 0.7 else "PortScan"

                reasons: list[str] = []
                if alert_count < max_explained_alerts:
                    row_dict = batch.row(i)
                    for d in self._detectors:
                        if scores[d.name][i] >= 0.5:
                            reasons.extend(d.explain(row_dict))
                    alert_count += 1

                row_detector_scores = {
                    d.name: round(float(scores[d.name][i]), 4) for d in self._detectors
                }
                alerts.append(
                    Alert.create(
                        index=i,
                        final_score=float(score_val),
                        attack_type=pred_type,
                        reasons=reasons,
                        detector_scores=row_detector_scores,
                    )
                )

        return alerts

    def save(self, path: Union[Path, str]) -> None:
        """Serialize threat engine state."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, target)

    @classmethod
    def load(cls, path: Union[Path, str]) -> "ThreatEngine":
        """Load serialized threat engine."""
        loaded = joblib.load(path)
        if not isinstance(loaded, ThreatEngine):
            raise ThreatEngineError("Loaded artifact is not a ThreatEngine instance.")
        return loaded
