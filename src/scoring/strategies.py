from abc import ABC, abstractmethod
from typing import Optional
import numpy as np


# Abstraction
class ScoringStrategy(ABC):
    """Abstract strategy for combining multi-detector score outputs."""

    # Polymorphism
    @abstractmethod
    def combine(
        self,
        scores: dict[str, np.ndarray],
        weights: Optional[dict[str, float]] = None,
    ) -> np.ndarray:
        """Combine dictionary of detector scores into a single confidence array."""


# Polymorphism
class WeightedAverage(ScoringStrategy):
    """Combines detector scores using normalized weighted averaging."""

    def combine(
        self,
        scores: dict[str, np.ndarray],
        weights: Optional[dict[str, float]] = None,
    ) -> np.ndarray:
        """Compute normalized weighted average of score arrays."""
        if not scores:
            return np.array([], dtype=float)

        w_dict = weights or {}
        active_weights = {k: float(w_dict.get(k, 1.0)) for k in scores.keys()}
        total_weight = sum(active_weights.values())
        if total_weight <= 0.0:
            total_weight = float(len(scores))
            active_weights = {k: 1.0 for k in scores.keys()}

        normalized = {k: v / total_weight for k, v in active_weights.items()}

        combined = np.zeros_like(next(iter(scores.values())), dtype=float)
        for key, arr in scores.items():
            combined += arr * normalized[key]
        return combined


# Polymorphism
class MaxScore(ScoringStrategy):
    """Combines detector scores using element-wise maximum."""

    def combine(
        self,
        scores: dict[str, np.ndarray],
        weights: Optional[dict[str, float]] = None,
    ) -> np.ndarray:
        """Compute element-wise maximum across all detector scores."""
        if not scores:
            return np.array([], dtype=float)
        return np.maximum.reduce(list(scores.values()))


# Polymorphism
class MajorityVote(ScoringStrategy):
    """Combines detector scores using majority vote fraction."""

    def combine(
        self,
        scores: dict[str, np.ndarray],
        weights: Optional[dict[str, float]] = None,
    ) -> np.ndarray:
        """Compute the fraction of detectors voting positive for attack."""
        if not scores:
            return np.array([], dtype=float)
        votes = [(s >= 0.5).astype(float) for s in scores.values()]
        return np.mean(votes, axis=0)
