"""
For educational use against your own local test environment only.

Sniffs loopback traffic, feeds packets into FlowAggregator, runs
ThreatEngine on each window, and pushes alerts to the intel store.
Started/stopped as a background thread by the FastAPI lifespan.
"""
import ctypes
import os
import platform
import threading
import time
from collections import deque
from typing import Optional

import config
from live.flow_aggregator import FlowAggregator
from src.engine.threat_engine import ThreatEngine
from src.features.pipeline import FeaturePipeline


# ---------------------------------------------------------------------------
# Npcap detection — actually check if Npcap is installed on Windows
# ---------------------------------------------------------------------------
def has_pcap() -> bool:
    """Return whether a packet capture provider (Npcap/WinPcap/libpcap) is available."""
    system = platform.system()

    if system == "Windows":
        # Check 1: Look for npcap DLL in its install directory
        npcap_dir = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "Npcap")
        if os.path.isdir(npcap_dir):
            return True

        # Check 2: Look for wpcap.dll in System32 (WinPcap compat or Npcap in WinPcap mode)
        sys32 = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32")
        if os.path.isfile(os.path.join(sys32, "wpcap.dll")):
            return True

        # Check 3: Try loading the DLL directly
        try:
            ctypes.windll.LoadLibrary("wpcap.dll")
            return True
        except OSError:
            pass

        # Check 4: Check registry for Npcap service
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap") as key:
                return True
        except (OSError, FileNotFoundError, ImportError):
            pass

        return False
    else:
        # Linux/macOS — check for libpcap
        try:
            ctypes.cdll.LoadLibrary("libpcap.so.1")
            return True
        except OSError:
            try:
                ctypes.cdll.LoadLibrary("libpcap.dylib")
                return True
            except OSError:
                return False


# ---------------------------------------------------------------------------
# Stream runner — Composition: reuses ThreatEngine and FlowAggregator
# ---------------------------------------------------------------------------
class StreamRunner:
    """Composition: live capture loop that reuses the offline ThreatEngine."""

    def __init__(
        self,
        engine: ThreatEngine,
        pipeline: FeaturePipeline,
        window_seconds: float = config.LIVE_WINDOW_SECONDS,
    ) -> None:
        """Initialise stream runner with engine and pipeline, asserting models are trained."""
        # Correctness check: assert RandomForest and XGBoost are fitted
        rf_fitted = any(getattr(d, "is_fitted", False) for d in engine.detectors if "RandomForest" in d.name)
        xgb_fitted = any(getattr(d, "is_fitted", False) for d in engine.detectors if "XGBoost" in d.name)
        if not (rf_fitted and xgb_fitted):
            raise RuntimeError("Models not trained — run python -m src.training.train first")

        self._engine = engine
        self._aggregator = FlowAggregator(pipeline, window_seconds)
        self._window = window_seconds
        self._strategy: Optional[str] = "max"
        self._threshold: Optional[float] = 0.45
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sniffer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        # Shared rolling alert deque
        self.alerts: deque = deque(maxlen=config.LIVE_MAX_ALERTS_MEMORY)
        self._alert_counter: int = 0
        self._pcap_available: Optional[bool] = None
        # Track capture mode for status reporting
        self._capture_mode: str = "unknown"

    # Encapsulation
    @property
    def is_running(self) -> bool:
        """Return whether the live loop is active."""
        return self._running

    @property
    def aggregator(self) -> FlowAggregator:
        """Return the internal FlowAggregator."""
        return self._aggregator

    @property
    def packets_seen(self) -> int:
        """Return packets observed so far."""
        return self._aggregator.packets_seen

    @property
    def window_seconds(self) -> float:
        """Return configured window duration."""
        return self._window

    @property
    def capture_mode(self) -> str:
        """Return active capture mode description."""
        return self._capture_mode

    def start(self, window_seconds: Optional[float] = None, strategy: Optional[str] = None, threshold: Optional[float] = None) -> None:
        """Start capture sniffing and analysis loop, updating runtime params dynamically."""
        if window_seconds:
            self._window = window_seconds
            self._aggregator._window = window_seconds
        if strategy is not None:
            self._strategy = strategy
        if threshold is not None:
            self._threshold = threshold

        if self._running:
            return

        # Detect Npcap once
        if self._pcap_available is None:
            self._pcap_available = has_pcap()

        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self._sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        self._sniffer_thread.start()
        print(f"[StreamRunner] Started (pcap={self._pcap_available}, window={self._window}s)")

    def stop(self) -> None:
        """Stop the capture and analysis loop."""
        self._running = False
        self._stop_event.set()
        print("[StreamRunner] Stopped")

    def _sniff_loop(self) -> None:
        """Background sniffer: feeds packets into the aggregator using Npcap if available."""
        if not self._pcap_available:
            self._capture_mode = "telemetry"
            print("[StreamRunner] Npcap available but scapy sniff skipped — using App Telemetry mode.")
            print("[StreamRunner] Attacks will inject flow data directly via /live/ingest endpoint.")
            # Keep thread alive to allow telemetry ingestion while running
            while self._running and not self._stop_event.is_set():
                self._stop_event.wait(timeout=1.0)
            return

        self._capture_mode = "npcap"
        try:
            from scapy.all import sniff, conf as scapy_conf  # type: ignore[import]

            # Try to enable Npcap in scapy
            try:
                scapy_conf.use_npcap = True
            except Exception:
                pass

            iface = config.LOOPBACK_IFACE
            print(f"[StreamRunner] Npcap detected — sniffing on {iface}")

            # sniff in short bursts so _running check works
            while self._running and not self._stop_event.is_set():
                try:
                    sniff(
                        iface=iface,
                        filter="tcp or udp",
                        prn=self._aggregator.ingest_packet,
                        store=False,
                        timeout=self._window,
                    )
                except PermissionError:
                    print("[StreamRunner] Permission denied for sniffing — falling back to telemetry mode.")
                    self._capture_mode = "telemetry"
                    self._pcap_available = False
                    while self._running and not self._stop_event.is_set():
                        self._stop_event.wait(timeout=1.0)
                    return
                except Exception as exc:
                    print(f"[StreamRunner] Sniff error: {exc} — retrying...")
                    time.sleep(1)
        except ImportError:
            print("[StreamRunner] scapy not available — using telemetry mode.")
            self._capture_mode = "telemetry"
            while self._running and not self._stop_event.is_set():
                self._stop_event.wait(timeout=1.0)

    def _analysis_loop(self) -> None:
        """Periodic analysis: every window, drain batch, log pipeline trace, and run engine."""
        # import here to avoid circular import at module load
        from threat_intel.intel_store import record as intel_record
        from threat_intel.mitre_map import get_technique

        while self._running and not self._stop_event.is_set():
            window_start = time.time()
            # Wait for the window duration (interruptible)
            self._stop_event.wait(timeout=self._window)
            if not self._running:
                break
            window_end = time.time()
            try:
                batch = self._aggregator.get_window_batch()
                if batch is None or len(batch) == 0:
                    continue

                raw_packets = self._aggregator.last_window_packets
                num_flows = len(batch)
                num_features = batch.scaled.shape[1]

                strategy = getattr(self, "_strategy", None)
                threshold = getattr(self, "_threshold", None)

                # Compute detector scores per detector for the batch
                detector_scores_summary = {
                    d.name: [round(float(s), 4) for s in d.score(batch)]
                    for d in self._engine.detectors
                }

                alert_list = self._engine.analyze(batch, strategy=strategy, threshold=threshold)

                strat_name = str(
                    strategy
                    or self._engine.strategy.__class__.__name__.lower().replace("strategy", "")
                )
                thresh_val = float(threshold if threshold is not None else self._engine.threshold)

                # Explicit traceable log path
                trace = [
                    f"[capture] {raw_packets} packets captured in window",
                    f"[aggregate] {num_flows} flows built",
                    f"[pipeline] batch shape: ({num_flows}, {num_features})",
                    f"[engine] scores: {detector_scores_summary}",
                    f"[alert] {len(alert_list)} alerts generated (threshold={thresh_val:.2f}, strategy={strat_name})",
                ]
                for line in trace:
                    print(line)

                for alert in alert_list:
                    # Source IP and port from raw frame
                    src_ip = "127.0.0.1"
                    src_port = 54321
                    dst_port = 5000
                    try:
                        src_ip = str(batch.raw.iloc[alert.index].get("_src_ip", "127.0.0.1"))
                        src_port = int(batch.raw.iloc[alert.index].get("_src_port", 54321))
                        dst_port = int(batch.raw.iloc[alert.index].get("Destination Port", 5000))
                    except Exception:
                        pass

                    mitre_id, mitre_name = get_technique(alert.attack_type)
                    self._alert_counter += 1
                    record = {
                        "id": self._alert_counter,
                        "index": alert.index,
                        "timestamp": window_end,
                        "window_start": window_start,
                        "window_end": window_end,
                        "final_score": alert.final_score,
                        "attack_type": alert.attack_type,
                        "severity": alert.severity,
                        "reasons": alert.reasons,
                        "source_ip": src_ip,
                        "source_port": src_port,
                        "destination_port": dst_port,
                        "mitre_id": mitre_id,
                        "mitre_name": mitre_name,
                        "detector_scores": alert.detector_scores,
                        "window_packet_count": raw_packets,
                        "trace": trace,
                    }
                    self.alerts.append(record)
                    intel_record(alert, src_ip, mitre_id)
            except Exception as exc:
                print(f"[StreamRunner] Analysis error: {exc}")


# Module-level singleton, initialised by FastAPI lifespan
_runner: Optional[StreamRunner] = None


def get_runner() -> Optional[StreamRunner]:
    """Return the module-level StreamRunner singleton."""
    return _runner


def init_runner(engine: ThreatEngine, pipeline: FeaturePipeline) -> StreamRunner:
    """Initialise (or replace) the singleton runner."""
    global _runner
    if _runner and _runner.is_running:
        _runner.stop()
    _runner = StreamRunner(engine, pipeline)
    return _runner
