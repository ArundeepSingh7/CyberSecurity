"""Scoring aggregation strategies."""
from src.scoring.strategies import (
    MajorityVote,
    MaxScore,
    ScoringStrategy,
    WeightedAverage,
)

__all__ = ["ScoringStrategy", "WeightedAverage", "MaxScore", "MajorityVote"]
