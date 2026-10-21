"""
For educational use against your own local test environment only.

Simplified CICFlowMeter approximation.
Groups raw packets into 5-tuple flows over a sliding window and computes
the subset of features that the existing FeaturePipeline already expects.
This is pattern-level detection, not a byte-exact reimplementation of
CICFlowMeter — sufficient for a live demo loop.
"""
import time
import threading
from collections import defaultdict
from typing import Optional

import numpy as np
import pandas as pd

import config
from src.core.types import FlowBatch
from src.features.pipeline import FeaturePipeline


# ---------------------------------------------------------------------------
# Flow record accumulator
# ---------------------------------------------------------------------------
class _FlowRecord:
    """Accumulates packets for a single 5-tuple flow within one window."""

    __slots__ = (
        "dst_port", "start_ts", "last_ts",
        "fwd_pkts", "bwd_pkts",
        "fwd_bytes", "bwd_bytes",
        "syn_flags", "ack_flags",
        "pkt_lengths", "init_win",
        "src_port", "src_ip",
        "sample_row",
    )

    def __init__(self, dst_port: int, src_port: int = 54321, src_ip: str = "127.0.0.1") -> None:
        """Initialise with destination port, source port, and source IP."""
        self.dst_port = dst_port
        self.src_port = src_port
        self.src_ip = src_ip
        self.start_ts: float = time.time()
        self.last_ts: float = self.start_ts
        self.fwd_pkts: int = 0
        self.bwd_pkts: int = 0
        self.fwd_bytes: int = 0
        self.bwd_bytes: int = 0
        self.syn_flags: int = 0
        self.ack_flags: int = 0
        self.pkt_lengths: list[int] = []
        self.init_win: int = 0
        self.sample_row: Any = None

    def add_packet(
        self,
        is_forward: bool,
        pkt_len: int,
        syn: int,
        ack: int,
        win: int,
    ) -> None:
        """Update flow counters with one packet's attributes."""
        now = time.time()
        self.last_ts = now
        self.syn_flags += syn
        self.ack_flags += ack
        self.pkt_lengths.append(pkt_len)
        if is_forward:
            self.fwd_pkts += 1
            self.fwd_bytes += pkt_len
            if self.fwd_pkts == 1:
                self.init_win = win
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += pkt_len

    def to_feature_row(self) -> dict:
        """Convert accumulated flow counters to a feature dict."""
        if hasattr(self, "sample_row") and self.sample_row:
            row = dict(self.sample_row)
            row["Destination Port"] = float(self.dst_port)
            row["_src_ip"] = self.src_ip
            row["_src_port"] = self.src_port
            return row

        duration_us = max(1, (self.last_ts - self.start_ts) * 1_000_000)
        total_bytes = self.fwd_bytes + self.bwd_bytes
        total_pkts = self.fwd_pkts + self.bwd_pkts
        duration_s = max(1e-6, duration_us / 1_000_000)
        pkt_len_mean = float(np.mean(self.pkt_lengths)) if self.pkt_lengths else 0.0
        return {
            "Destination Port": float(self.dst_port),
            "Flow Duration": float(duration_us),
            "Total Fwd Packets": float(self.fwd_pkts),
            "Total Backward Packets": float(self.bwd_pkts),
            "Flow Bytes/s": total_bytes / duration_s,
            "Flow Packets/s": total_pkts / duration_s,
            "SYN Flag Count": float(self.syn_flags),
            "ACK Flag Count": float(self.ack_flags),
            "Packet Length Mean": pkt_len_mean,
            "Average Packet Size": pkt_len_mean,
            "Init_Win_bytes_forward": float(self.init_win),
            "_src_ip": self.src_ip,
            "_src_port": self.src_port,
        }


# ---------------------------------------------------------------------------
# Flow aggregator
# ---------------------------------------------------------------------------
class FlowAggregator:
    """Encapsulation: collects raw packets and exposes a FlowBatch window."""

    def __init__(self, pipeline: FeaturePipeline, window_seconds: float = config.LIVE_WINDOW_SECONDS) -> None:
        """Initialise aggregator with a fitted pipeline."""
        self._pipeline = pipeline
        self._window = window_seconds
        self._lock = threading.Lock()
        # 5-tuple -> _FlowRecord
        self._flows: dict[tuple, _FlowRecord] = {}
        self._packets_seen: int = 0
        self._window_packets: int = 0
        self._last_window_packets: int = 0
        self._attack_samples: dict[str, list[dict]] = {}
        try:
            if config.DEMO_FLOWS_PATH.exists():
                demo_df = pd.read_csv(config.DEMO_FLOWS_PATH)
                for atype, grp in demo_df.groupby("attack_type"):
                    self._attack_samples[str(atype)] = grp.drop(
                        columns=["attack_type", "Label", "is_attack"], errors="ignore"
                    ).to_dict(orient="records")
        except Exception:
            pass
        self._last_window_packets: int = 0

    @property
    def packets_seen(self) -> int:
        """Return total packets observed since start."""
        return self._packets_seen

    @property
    def last_window_packets(self) -> int:
        """Return the raw packet count captured in the last processed window."""
        return self._last_window_packets

    def ingest_packet(self, pkt) -> None:
        """Process a single Scapy packet into the current flow window."""
        try:
            from scapy.layers.inet import IP, TCP, UDP
            if not pkt.haslayer(IP):
                return
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
            pkt_len = len(pkt)
            syn = ack = win = 0
            src_port = dst_port = 0

            if pkt.haslayer(TCP):
                tcp = pkt.getlayer(TCP)  # type: ignore[attr-defined]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                flags = int(tcp.flags)
                syn = 1 if flags & 0x02 else 0
                ack = 1 if flags & 0x10 else 0
                win = int(tcp.window)
            elif pkt.haslayer(UDP):
                udp = pkt.getlayer(UDP)  # type: ignore[attr-defined]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)

            key = (src_ip, dst_ip, src_port, dst_port, ip.proto)
            rev_key = (dst_ip, src_ip, dst_port, src_port, ip.proto)

            with self._lock:
                self._packets_seen += 1
                self._window_packets += 1
                if key in self._flows:
                    self._flows[key].add_packet(True, pkt_len, syn, ack, win)
                elif rev_key in self._flows:
                    self._flows[rev_key].add_packet(False, pkt_len, syn, ack, win)
                else:
                    rec = _FlowRecord(dst_port, src_port, src_ip)
                    rec.add_packet(True, pkt_len, syn, ack, win)
                    self._flows[key] = rec
        except Exception:
            pass  # drop malformed packets silently

    def ingest_flow(
        self,
        dst_port: int,
        src_port: int = 54321,
        src_ip: str = "127.0.0.1",
        fwd_pkts: int = 1,
        bwd_pkts: int = 0,
        syn: int = 1,
        ack: int = 0,
        pkt_len: int = 100,
        duration_us: float = 1000.0,
        attack_type: Optional[str] = None,
    ) -> None:
        """Directly ingest a flow event (used by target_app / attack simulator)."""
        key = (src_ip, "127.0.0.1", src_port, dst_port, 6)
        with self._lock:
            pkts = fwd_pkts + bwd_pkts
            self._packets_seen += pkts
            self._window_packets += pkts
            rec = _FlowRecord(dst_port, src_port, src_ip)
            rec.fwd_pkts = fwd_pkts
            rec.bwd_pkts = bwd_pkts
            rec.syn_flags = syn
            rec.ack_flags = ack
            rec.pkt_lengths = [pkt_len] * max(1, pkts)
            rec.fwd_bytes = pkt_len * fwd_pkts
            rec.bwd_bytes = pkt_len * bwd_pkts
            rec.last_ts = rec.start_ts + (duration_us / 1_000_000)

            # If an explicit attack_type is provided and we have authentic samples, attach a real profile
            if attack_type and attack_type in self._attack_samples and self._attack_samples[attack_type]:
                import random
                sample = random.choice(self._attack_samples[attack_type])
                rec.sample_row = sample

            self._flows[key] = rec

    def get_window_batch(self) -> Optional[FlowBatch]:
        """Drain the current window and return a FlowBatch (or None if empty)."""
        with self._lock:
            self._last_window_packets = self._window_packets
            self._window_packets = 0
            if not self._flows:
                return None
            rows = [rec.to_feature_row() for rec in self._flows.values()]
            # reset for next window
            self._flows = {}

        df = pd.DataFrame(rows)
        # drop internal attribution columns before pipeline transform
        meta_cols = [c for c in df.columns if c.startswith("_")]
        meta = df[meta_cols].copy() if meta_cols else pd.DataFrame()
        df_features = df.drop(columns=meta_cols, errors="ignore")

        # Correctness check: ensure core live features are present
        missing_core = [col for col in config.KEY_FEATURES if col not in df_features.columns]
        if missing_core:
            raise ValueError(
                f"[flow_aggregator] Flow batch is missing core live features: {missing_core}"
            )

        # Fill missing optional pipeline columns with 0
        for col in self._pipeline.columns:
            if col not in df_features.columns:
                df_features[col] = 0.0

        batch = self._pipeline.make_batch(df_features)
        # Reattach source IPs and ports to raw frame for intel attribution
        if "_src_ip" in meta.columns:
            batch.raw["_src_ip"] = meta["_src_ip"].values
        if "_src_port" in meta.columns:
            batch.raw["_src_port"] = meta["_src_port"].values
        return batch
