"""Unit tests for OOP detectors, scoring strategies, and ThreatEngine."""
import numpy as np
import pandas as pd
import pytest

from src.core.types import FlowBatch
from src.detectors.rule_detectors import DoSDetector, PortScanDetector, BruteForceDetector
from src.detectors.factory import DetectorFactory
from src.scoring.strategies import WeightedAverage, MaxScore, MajorityVote
from src.engine.alert import Alert


class TestScoringStrategies:
    """Tests for OOP scoring strategies polymorphism."""

    def test_weighted_average(self):
        strat = WeightedAverage()
        scores = {"d1": np.array([0.8]), "d2": np.array([0.4])}
        weights = {"d1": 0.5, "d2": 0.5}
        combined = strat.combine(scores, weights)
        assert np.isclose(combined[0], 0.6)

    def test_max_score(self):
        strat = MaxScore()
        scores = {"d1": np.array([0.2, 0.9]), "d2": np.array([0.8, 0.1])}
        combined = strat.combine(scores)
        assert np.allclose(combined, [0.8, 0.9])

    def test_majority_vote(self):
        strat = MajorityVote()
        scores = {"d1": np.array([0.6]), "d2": np.array([0.7]), "d3": np.array([0.2])}
        combined = strat.combine(scores)
        # 2 out of 3 above 0.5 -> 2/3
        assert np.isclose(combined[0], 2.0 / 3.0)


class TestRuleBasedDetectors:
    """Tests for rule-based detector inheritance and polymorphism."""

    def test_dos_detector_high_packets(self):
        detector = DoSDetector()
        df = pd.DataFrame({"Flow Packets/s": [6000.0, 100.0], "Flow Duration": [10.0, 10.0]})
        batch = FlowBatch(raw=df, scaled=np.zeros((2, 2)), feature_names=["Flow Packets/s", "Flow Duration"])
        scores = detector.score(batch)
        assert scores[0] >= 0.8
        assert scores[1] < 0.5

    def test_portscan_detector(self):
        detector = PortScanDetector()
        df = pd.DataFrame({"SYN Flag Count": [2, 0], "Total Fwd Packets": [1, 10]})
        batch = FlowBatch(raw=df, scaled=np.zeros((2, 2)), feature_names=["SYN Flag Count", "Total Fwd Packets"])
        scores = detector.score(batch)
        assert scores[0] >= 0.8
        assert scores[1] < 0.5

    def test_bruteforce_detector(self):
        detector = BruteForceDetector()
        df = pd.DataFrame({"Destination Port": [22, 80], "Total Fwd Packets": [15, 2]})
        batch = FlowBatch(raw=df, scaled=np.zeros((2, 2)), feature_names=["Destination Port", "Total Fwd Packets"])
        scores = detector.score(batch)
        assert scores[0] >= 0.8
        assert scores[1] < 0.5


class TestDetectorFactory:
    """Tests for Factory pattern."""

    def test_create_rule_detectors(self):
        d_dos = DetectorFactory.create("dos")
        assert isinstance(d_dos, DoSDetector)

        d_port = DetectorFactory.create("portscan")
        assert isinstance(d_port, PortScanDetector)

        d_brute = DetectorFactory.create("bruteforce")
        assert isinstance(d_brute, BruteForceDetector)

    def test_get_strategy(self):
        assert isinstance(DetectorFactory.get_strategy("weighted"), WeightedAverage)
        assert isinstance(DetectorFactory.get_strategy("max"), MaxScore)
        assert isinstance(DetectorFactory.get_strategy("vote"), MajorityVote)
