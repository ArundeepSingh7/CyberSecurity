from contextlib import asynccontextmanager
import io
import json
from typing import Any, Optional
from fastapi import FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import config
from api.schemas import (
    AlertResponse,
    AlertSchema,
    AnalysisResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    HealthResponse,
    LiveStartRequest,
    LiveStatusResponse,
)
from src.engine.threat_engine import ThreatEngine
from src.features.pipeline import FeaturePipeline

ENGINE: Optional[ThreatEngine] = None
ALERTS_DB: list[dict[str, Any]] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load ThreatEngine and initialise StreamRunner at application startup."""
    global ENGINE
    if config.ENGINE_PATH.exists():
        try:
            ENGINE = ThreatEngine.load(config.ENGINE_PATH)
        except Exception:
            ENGINE = None
    # Initialise live stream runner (does not start sniffing until /live/start)
    if ENGINE is not None and config.PIPELINE_PATH.exists():
        try:
            from live.stream_runner import init_runner
            pipeline = FeaturePipeline.load(config.PIPELINE_PATH)
            init_runner(ENGINE, pipeline)
        except Exception as exc:
            print(f"[lifespan] StreamRunner init failed: {exc}")
    yield


app = FastAPI(
    title="Cyber IDS Threat Intelligence API",
    description="REST API for flow-level network intrusion detection and threat intelligence.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
def health_check() -> dict[str, Any]:
    """Check API operational status and model availability."""
    global ENGINE
    if ENGINE is None and config.ENGINE_PATH.exists():
        try:
            ENGINE = ThreatEngine.load(config.ENGINE_PATH)
        except Exception:
            pass
    return {
        "status": "ok",
        "model_loaded": ENGINE is not None,
    }


@app.get("/strategies", response_model=list[str])
def list_strategies() -> list[str]:
    """Return list of supported score aggregation strategies."""
    return ["weighted", "max", "vote"]


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_traffic(
    file: UploadFile = File(...),
    strategy: Optional[str] = Query(None, description="Optional strategy override"),
    threshold: Optional[float] = Query(None, description="Optional threshold override"),
) -> dict[str, Any]:
    """Analyze uploaded network flows CSV and return generated alerts."""
    global ENGINE
    if ENGINE is None:
        if config.ENGINE_PATH.exists():
            ENGINE = ThreatEngine.load(config.ENGINE_PATH)
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Models are not trained yet. Run python -m src.training.train first.",
            )

    try:
        content = await file.read()
        df = pd.read_csv(io.BytesIO(content), low_memory=False)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not parse uploaded CSV file: {str(exc)}",
        ) from exc

    if df.empty:
        return {
            "total_flows": 0,
            "alert_count": 0,
            "attack_type_counts": {},
            "alerts": [],
        }

    try:
        alerts = ENGINE.analyze(df, strategy=strategy, threshold=threshold)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error analyzing traffic flows: {str(exc)}",
        ) from exc

    alert_dicts = [a.to_dict() for a in alerts]
    ALERTS_DB.extend(alert_dicts)

    type_counts: dict[str, int] = {}
    for a in alerts:
        type_counts[a.attack_type] = type_counts.get(a.attack_type, 0) + 1

    return {
        "total_flows": len(df),
        "alert_count": len(alerts),
        "attack_type_counts": type_counts,
        "alerts": alert_dicts,
    }


@app.get("/alerts", response_model=list[AlertSchema])
def get_alerts(limit: int = Query(100, ge=1, le=1000)) -> list[dict[str, Any]]:
    """Retrieve recent alerts recorded in memory."""
    return ALERTS_DB[-limit:]


@app.get("/metrics")
def get_metrics() -> dict[str, Any]:
    """Retrieve model training evaluation metrics."""
    if not config.METRICS_PATH.exists():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model metrics are not available. Train models first.",
        )
    try:
        with open(config.METRICS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read metrics: {str(exc)}",
        ) from exc


@app.post("/config", response_model=ConfigResponse)
def update_config(req: ConfigUpdateRequest) -> dict[str, Any]:
    """Update active engine strategy or alert threshold."""
    global ENGINE
    if ENGINE is None:
        if config.ENGINE_PATH.exists():
            ENGINE = ThreatEngine.load(config.ENGINE_PATH)
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Engine is not loaded yet.",
            )

    if req.strategy is not None:
        try:
            ENGINE.set_strategy(req.strategy)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    if req.threshold is not None:
        ENGINE.set_threshold(req.threshold)

    return {
        "strategy": ENGINE.strategy.__class__.__name__.lower().replace("strategy", ""),
        "threshold": ENGINE.threshold,
        "available_strategies": ["weighted", "max", "vote"],
    }


# ============================================================
# Live capture endpoints
# ============================================================

def _get_runner():
    """Helper to retrieve the StreamRunner or raise 503."""
    global ENGINE
    from live.stream_runner import get_runner, init_runner
    runner = get_runner()
    if runner is None:
        if ENGINE is None and config.ENGINE_PATH.exists():
            try:
                ENGINE = ThreatEngine.load(config.ENGINE_PATH)
            except Exception:
                ENGINE = None
        if ENGINE is not None and config.PIPELINE_PATH.exists():
            try:
                pipeline = FeaturePipeline.load(config.PIPELINE_PATH)
                runner = init_runner(ENGINE, pipeline)
            except Exception:
                runner = None
    if runner is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Live stream runner not initialised. Train models first.",
        )
    return runner


@app.post("/live/start")
def live_start(req: LiveStartRequest) -> dict[str, Any]:
    """Start live loopback traffic capture and analysis."""
    runner = _get_runner()
    runner.start(
        window_seconds=req.window_seconds,
        strategy=req.strategy,
        threshold=req.threshold,
    )
    return {"status": "started", "window_seconds": runner.window_seconds}


@app.post("/live/stop")
def live_stop() -> dict[str, Any]:
    """Stop live capture."""
    runner = _get_runner()
    runner.stop()
    return {"status": "stopped"}


@app.get("/live/status", response_model=LiveStatusResponse)
def live_status() -> dict[str, Any]:
    """Return current live capture status."""
    runner = _get_runner()
    from live.stream_runner import has_pcap
    return {
        "running": runner.is_running,
        "window_seconds": runner.window_seconds,
        "packets_seen": runner.packets_seen,
        "has_pcap": has_pcap(),
        "capture_mode": runner.capture_mode,
    }


@app.post("/live/ingest")
def live_ingest(payload: dict[str, Any]) -> dict[str, Any]:
    """Directly ingest a flow event into the active aggregator window (telemetry fallback)."""
    runner = _get_runner()
    runner.aggregator.ingest_flow(
        dst_port=int(payload.get("dst_port", 5000)),
        src_port=int(payload.get("src_port", 54321)),
        src_ip=str(payload.get("src_ip", "127.0.0.1")),
        fwd_pkts=int(payload.get("fwd_pkts", 1)),
        bwd_pkts=int(payload.get("bwd_pkts", 0)),
        syn=int(payload.get("syn", 1)),
        ack=int(payload.get("ack", 0)),
        pkt_len=int(payload.get("pkt_len", 100)),
        duration_us=float(payload.get("duration_us", 1000.0)),
        attack_type=payload.get("attack_type"),
    )
    return {"status": "ok", "packets_seen": runner.packets_seen}


@app.get("/live/alerts", response_model=list[AlertResponse])
def live_alerts(since_id: int = Query(0, ge=0)) -> list[dict[str, Any]]:
    """Return live alerts with id > since_id (for polling)."""
    runner = _get_runner()
    return [a for a in runner.alerts if a.get("id", 0) > since_id]


# ============================================================
# Threat intelligence endpoints
# ============================================================

@app.get("/intel/summary")
def intel_summary() -> dict[str, Any]:
    """Return aggregated threat intelligence summary."""
    from threat_intel.intel_store import query_summary
    return query_summary()


@app.get("/intel/ip/{ip}")
def intel_ip(ip: str) -> list[dict[str, Any]]:
    """Return alert history for a specific source IP."""
    from threat_intel.intel_store import query_ip_history
    return query_ip_history(ip)

