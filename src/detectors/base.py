from abc import ABC, abstractmethod
from typing import Any, Union
import numpy as np
import pandas as pd
from src.core.exceptions import NotFittedError
from src.core.types import FlowBatch


# Abstraction
class BaseDetector(ABC):
    """Abstract base class for all detection mechanisms."""

    def __init__(self, name: str) -> None:
        """Initialize detector with identity."""
        self._name: str = name
        self._is_fitted: bool = False
        self._model: Any = None

    # Encapsulation
    @property
    def name(self) -> str:
        """Return the detector name."""
        return self._name

    # Encapsulation
    @property
    def is_fitted(self) -> bool:
        """Return whether detector has been fitted."""
        return self._is_fitted

    # Abstraction
    @abstractmethod
    def _fit(self, batch: FlowBatch, labels: Any = None) -> None:
        """Internal fit implementation."""

    # Abstraction
    @abstractmethod
    def _score(self, batch: FlowBatch) -> np.ndarray:
        """Internal scoring implementation returning anomaly probabilities."""

    # Abstraction
    @abstractmethod
    def _attack_type(self, batch: FlowBatch) -> list[str]:
        """Internal attack type prediction implementation."""

    def fit(self, batch: FlowBatch, labels: Any = None) -> None:
        """Template method for fitting the detector."""
        self._fit(batch, labels=labels)
        self._is_fitted = True

    def score(self, batch: FlowBatch) -> np.ndarray:
        """Template method returning clipped attack confidence scores."""
        if not self._is_fitted:
            raise NotFittedError(f"Detector {self._name} is not fitted.")
        raw_scores = self._score(batch)
        return np.clip(np.asarray(raw_scores, dtype=float), 0.0, 1.0)

    def attack_type(self, batch: FlowBatch) -> list[str]:
        """Template method returning predicted attack types."""
        if not self._is_fitted:
            raise NotFittedError(f"Detector {self._name} is not fitted.")
        return self._attack_type(batch)

    def predict(self, batch: FlowBatch, threshold: float = 0.5) -> np.ndarray:
        """Template method returning binary predictions based on threshold."""
        return (self.score(batch) >= threshold).astype(int)

    def explain(self, row: Union[dict[str, Any], pd.Series]) -> list[str]:
        """Return human-readable explanation strings for an alert."""
        return []

    def __repr__(self) -> str:
        """Return string representation of detector."""
        return f"{self.__class__.__name__}(name='{self._name}', fitted={self._is_fitted})"
