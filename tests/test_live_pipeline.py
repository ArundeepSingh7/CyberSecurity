"""
Unit and integration tests for the live pipeline verification.
Tests the end-to-end data path from synthetic flow batch through
the trained FeaturePipeline and ThreatEngine, verifying model scoring
and correctness checks without requiring scapy or live network capture.
"""
import pytest
import pandas as pd
from unittest.mock import MagicMock

import config
from src.features.pipeline import FeaturePipeline
from src.engine.threat_engine import ThreatEngine
from live.stream_runner import StreamRunner
from live.flow_aggregator import FlowAggregator
from api.schemas import AlertResponse, AlertSchema


def test_synthetic_dos_pipeline_and_engine_wiring():
    """Verify synthetic DoS flow batch runs through trained pipeline and ThreatEngine.
    
    Proves:
      1. pipeline.make_batch does not raise on synthetic flow data.
      2. engine.analyze(batch) returns at least one alert.
      3. The alert's detector_scores dict contains non-zero scores from
         RandomForest, XGBoost, and DoSDetector, proving both ML models
         and the rule detector executed on real batch features.
    """
    assert config.PIPELINE_PATH.exists(), "FeaturePipeline model file must exist"
    assert config.ENGINE_PATH.exists(), "ThreatEngine model file must exist"

    pipeline = FeaturePipeline.load(config.PIPELINE_PATH)
    engine = ThreatEngine.load(config.ENGINE_PATH)

    # Synthetic flow row matching high Flow Packets/s DoS attack characteristics
    dos_data = [
        {
            "Destination Port": 80.0,
            "Flow Duration": 7.0,
            "Total Fwd Packets": 3.0,
            "Total Backward Packets": 0.0,
            "Total Length of Fwd Packets": 0.0,
            "Total Length of Bwd Packets": 0.0,
            "Fwd Packet Length Max": 0.0,
            "Fwd Packet Length Min": 0.0,
            "Fwd Packet Length Mean": 0.0,
            "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": 0.0,
            "Bwd Packet Length Min": 0.0,
            "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0,
            "Flow Bytes/s": 0.0,
            "Flow Packets/s": 428571.4,
            "Flow IAT Mean": 3.5,
            "Flow IAT Std": 0.0,
            "Flow IAT Max": 7.0,
            "Flow IAT Min": 0.0,
            "Fwd IAT Total": 7.0,
            "Fwd IAT Mean": 3.5,
            "Fwd IAT Std": 0.0,
            "Fwd IAT Max": 7.0,
            "Fwd IAT Min": 0.0,
            "Bwd IAT Total": 0.0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0,
            "Fwd PSH Flags": 0.0,
            "Bwd PSH Flags": 0.0,
            "Fwd URG Flags": 0.0,
            "Bwd URG Flags": 0.0,
            "Fwd Header Length": 96.0,
            "Bwd Header Length": 0.0,
            "Fwd Packets/s": 428571.4,
            "Bwd Packets/s": 0.0,
            "Min Packet Length": 0.0,
            "Max Packet Length": 0.0,
            "Packet Length Mean": 0.0,
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,
            "FIN Flag Count": 0.0,
            "SYN Flag Count": 0.0,
            "RST Flag Count": 0.0,
            "PSH Flag Count": 0.0,
            "ACK Flag Count": 1.0,
            "URG Flag Count": 0.0,
            "CWE Flag Count": 0.0,
            "ECE Flag Count": 0.0,
            "Down/Up Ratio": 0.0,
            "Average Packet Size": 0.0,
            "Avg Fwd Segment Size": 0.0,
            "Avg Bwd Segment Size": 0.0,
            "Fwd Header Length.1": 96.0,
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": 3.0,
            "Subflow Fwd Bytes": 0.0,
            "Subflow Bwd Packets": 0.0,
            "Subflow Bwd Bytes": 0.0,
            "Init_Win_bytes_forward": 274.0,
            "Init_Win_bytes_backward": -1.0,
            "act_data_pkt_fwd": 0.0,
            "min_seg_size_forward": 32.0,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
        }
    ]
    df = pd.DataFrame(dos_data)

    # 1. pipeline.make_batch does not raise
    batch = pipeline.make_batch(df)
    assert batch is not None
    assert len(batch) == 1
    assert batch.scaled.shape[0] == 1

    # 2. engine.analyze(batch) returns at least one alert
    alerts = engine.analyze(batch)
    assert len(alerts) >= 1, "Expected at least one alert for high-rate DoS flow"

    alert = alerts[0]
    scores = alert.detector_scores

    # 3. detector_scores dict contains RandomForest, XGBoost, and DoSDetector
    assert "RandomForest" in scores, "RandomForest score must be present in detector_scores"
    assert "XGBoost" in scores, "XGBoost score must be present in detector_scores"
    assert "DoSDetector" in scores, "DoSDetector score must be present in detector_scores"

    # Verify that all three actually evaluated the data
    assert scores["RandomForest"] > 0.0, f"Expected RandomForest > 0, got {scores['RandomForest']}"
    assert scores["XGBoost"] > 0.0, f"Expected XGBoost > 0, got {scores['XGBoost']}"
    assert scores["DoSDetector"] > 0.0, f"Expected DoSDetector > 0, got {scores['DoSDetector']}"


def test_stream_runner_untrained_engine_fails_loudly():
    """StreamRunner startup must fail loudly if ML detectors are not fitted."""
    mock_pipeline = MagicMock(spec=FeaturePipeline)
    mock_engine = MagicMock(spec=ThreatEngine)

    # Create mock detectors where is_fitted is False
    rf = MagicMock()
    rf.name = "RandomForest"
    rf.is_fitted = False

    xgb = MagicMock()
    xgb.name = "XGBoost"
    xgb.is_fitted = False

    mock_engine.detectors = [rf, xgb]

    with pytest.raises(RuntimeError, match="Models not trained — run python -m src.training.train first"):
        StreamRunner(engine=mock_engine, pipeline=mock_pipeline)


def test_flow_aggregator_missing_core_features_raises_error(monkeypatch):
    """FlowAggregator.get_window_batch must raise ValueError if core features are missing."""
    from live import flow_aggregator

    mock_pipeline = MagicMock(spec=FeaturePipeline)
    mock_pipeline.columns = list(config.KEY_FEATURES)

    agg = FlowAggregator(pipeline=mock_pipeline, window_seconds=1.0)
    agg.ingest_flow(dst_port=5000, src_port=54321, src_ip="127.0.0.1")

    orig_to_row = flow_aggregator._FlowRecord.to_feature_row

    def broken_to_row(self):
        row = orig_to_row(self)
        row.pop("Flow Packets/s", None)
        return row

    monkeypatch.setattr(flow_aggregator._FlowRecord, "to_feature_row", broken_to_row)

    with pytest.raises(ValueError, match="missing core live features"):
        agg.get_window_batch()


def test_alert_response_schema_additive_fields():
    """Verify AlertResponse schema includes detector_scores and window_packet_count."""
    data = {
        "index": 0,
        "final_score": 0.95,
        "attack_type": "DoS",
        "reasons": ["High packet rate"],
        "severity": "CRITICAL",
        "detector_scores": {"RandomForest": 0.88, "XGBoost": 0.94, "DoSDetector": 1.0},
        "window_packet_count": 150,
        "source_ip": "127.0.0.1",
        "source_port": 54321,
        "destination_port": 5000,
        "trace": [
            "[capture] 150 packets captured in window",
            "[aggregate] 1 flows built",
            "[pipeline] batch shape: (1, 78)",
            "[engine] scores: {'RandomForest': [0.88], 'XGBoost': [0.94], 'DoSDetector': [1.0]}",
            "[alert] 1 alerts generated (threshold=0.50, strategy=weighted)",
        ],
    }
    schema = AlertResponse(**data)
    assert schema.detector_scores["RandomForest"] == 0.88
    assert schema.detector_scores["XGBoost"] == 0.94
    assert schema.detector_scores["DoSDetector"] == 1.0
    assert schema.window_packet_count == 150
    assert len(schema.trace) == 5
    assert schema == AlertSchema(**data)
