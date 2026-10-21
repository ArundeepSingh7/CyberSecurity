from typing import Union
from src.detectors.base import BaseDetector
from src.detectors.ml_detectors import RandomForestDetector, XGBoostDetector
from src.detectors.rule_detectors import BruteForceDetector, DoSDetector, PortScanDetector
from src.scoring.strategies import MajorityVote, MaxScore, ScoringStrategy, WeightedAverage


# Factory
class DetectorFactory:
    """Factory creating threat detectors and strategy instances."""

    _DETECTOR_REGISTRY = {
        "rf": RandomForestDetector,
        "xgb": XGBoostDetector,
        "dos": DoSDetector,
        "portscan": PortScanDetector,
        "bruteforce": BruteForceDetector,
    }

    _STRATEGY_REGISTRY = {
        "weighted": WeightedAverage,
        "max": MaxScore,
        "vote": MajorityVote,
    }

    @classmethod
    def create(cls, key: str) -> BaseDetector:
        """Create a single detector instance by registration key."""
        normalized = key.strip().lower()
        if normalized not in cls._DETECTOR_REGISTRY:
            valid_keys = ", ".join(cls._DETECTOR_REGISTRY.keys())
            raise ValueError(f"Unknown detector key '{key}'. Valid options: {valid_keys}")
        return cls._DETECTOR_REGISTRY[normalized]()

    @classmethod
    def create_many(cls, keys: list[str]) -> list[BaseDetector]:
        """Create multiple detector instances from a list of keys."""
        return [cls.create(k) for k in keys]

    @classmethod
    def get_strategy(cls, name: Union[str, ScoringStrategy]) -> ScoringStrategy:
        """Retrieve strategy instance by name or pass through existing instance."""
        if isinstance(name, ScoringStrategy):
            return name
        normalized = str(name).strip().lower()
        if normalized not in cls._STRATEGY_REGISTRY:
            valid_strategies = ", ".join(cls._STRATEGY_REGISTRY.keys())
            raise ValueError(f"Unknown strategy '{name}'. Valid options: {valid_strategies}")
        return cls._STRATEGY_REGISTRY[normalized]()
