from typing import Any, Union
import numpy as np
import pandas as pd
import config
from src.core.types import FlowBatch
from src.detectors.base import BaseDetector


# Inheritance
class RuleBasedDetector(BaseDetector):
    """Base class for heuristic signature detectors."""

    def __init__(self, name: str) -> None:
        """Initialize rule detector as pre-fitted."""
        super().__init__(name=name)
        self._is_fitted = True

    # Polymorphism
    def _fit(self, batch: FlowBatch, labels: Any = None) -> None:
        """Rule detectors do not require training."""


# Inheritance
class DoSDetector(RuleBasedDetector):
    """Detects high volumetric flow rates indicative of DoS."""

    def __init__(self) -> None:
        """Initialize DoS detector."""
        super().__init__(name="DoSDetector")

    # Polymorphism
    def _score(self, batch: FlowBatch) -> np.ndarray:
        """Score based on packet per second threshold."""
        if "Flow Packets/s" not in batch.raw.columns:
            return np.zeros(len(batch.raw), dtype=float)
        cond = batch.raw["Flow Packets/s"] > config.DOS_FLOW_PACKETS_THRESHOLD
        return cond.astype(float).to_numpy()

    # Polymorphism
    def _attack_type(self, batch: FlowBatch) -> list[str]:
        """Return DoS attack type for triggered flows."""
        scores = self._score(batch)
        return ["DoS" if s >= 0.5 else "BENIGN" for s in scores]

    def explain(self, row: Union[dict[str, Any], pd.Series]) -> list[str]:
        """Explain high packet rate anomaly."""
        rate = float(row.get("Flow Packets/s", 0.0))
        if rate > config.DOS_FLOW_PACKETS_THRESHOLD:
            return [f"High packet rate: {rate:.1f} pkts/s exceeds threshold {config.DOS_FLOW_PACKETS_THRESHOLD}"]
        return []


# Inheritance
class PortScanDetector(RuleBasedDetector):
    """Detects reconnaissance scanning via low forward packets and SYN flags."""

    def __init__(self) -> None:
        """Initialize PortScan detector."""
        super().__init__(name="PortScanDetector")

    # Polymorphism
    def _score(self, batch: FlowBatch) -> np.ndarray:
        """Score based on SYN probes with minimal forward packets."""
        has_fwd = "Total Fwd Packets" in batch.raw.columns
        has_syn = "SYN Flag Count" in batch.raw.columns
        if not (has_fwd and has_syn):
            return np.zeros(len(batch.raw), dtype=float)
        cond = (
            (batch.raw["Total Fwd Packets"] <= config.PORT_SCAN_MAX_FWD_PACKETS)
            & (batch.raw["SYN Flag Count"] >= config.PORT_SCAN_MIN_SYN_FLAGS)
        )
        return cond.astype(float).to_numpy()

    # Polymorphism
    def _attack_type(self, batch: FlowBatch) -> list[str]:
        """Return PortScan attack type for triggered flows."""
        scores = self._score(batch)
        return ["PortScan" if s >= 0.5 else "BENIGN" for s in scores]

    def explain(self, row: Union[dict[str, Any], pd.Series]) -> list[str]:
        """Explain port scan signature."""
        fwd = float(row.get("Total Fwd Packets", 0.0))
        syn = float(row.get("SYN Flag Count", 0.0))
        if fwd <= config.PORT_SCAN_MAX_FWD_PACKETS and syn >= config.PORT_SCAN_MIN_SYN_FLAGS:
            return [f"Port scan signature: SYN flags ({int(syn)}) with low packet count ({int(fwd)})"]
        return []


# Inheritance
class BruteForceDetector(RuleBasedDetector):
    """Detects repeated authentication attempts on administrative ports."""

    def __init__(self) -> None:
        """Initialize BruteForce detector."""
        super().__init__(name="BruteForceDetector")

    # Polymorphism
    def _score(self, batch: FlowBatch) -> np.ndarray:
        """Score based on traffic targeted at SSH/FTP ports."""
        has_port = "Destination Port" in batch.raw.columns
        has_fwd = "Total Fwd Packets" in batch.raw.columns
        if not (has_port and has_fwd):
            return np.zeros(len(batch.raw), dtype=float)
        port_match = batch.raw["Destination Port"].astype(int).isin(config.BRUTE_FORCE_PORTS)
        fwd_match = batch.raw["Total Fwd Packets"] > config.BRUTE_FORCE_MIN_FWD_PACKETS
        cond = port_match & fwd_match
        return cond.astype(float).to_numpy()

    # Polymorphism
    def _attack_type(self, batch: FlowBatch) -> list[str]:
        """Return BruteForce attack type for triggered flows."""
        scores = self._score(batch)
        return ["BruteForce" if s >= 0.5 else "BENIGN" for s in scores]

    def explain(self, row: Union[dict[str, Any], pd.Series]) -> list[str]:
        """Explain brute force signature."""
        port = int(row.get("Destination Port", 0))
        fwd = float(row.get("Total Fwd Packets", 0.0))
        if port in config.BRUTE_FORCE_PORTS and fwd > config.BRUTE_FORCE_MIN_FWD_PACKETS:
            return [f"Brute force signature: Targeted service port {port} with {int(fwd)} forward packets"]
        return []
