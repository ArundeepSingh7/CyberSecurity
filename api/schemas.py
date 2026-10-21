from typing import Any, Optional
from pydantic import BaseModel, Field


# Encapsulation
class AlertSchema(BaseModel):
    """Schema for individual threat alert."""

    index: int
    final_score: float
    attack_type: str
    reasons: list[str]
    severity: str
    id: Optional[int] = None
    mitre_id: Optional[str] = None
    mitre_name: Optional[str] = None
    detector_scores: dict[str, float] = Field(default_factory=dict)
    window_packet_count: int = 0
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    trace: list[str] = Field(default_factory=list)


AlertResponse = AlertSchema


# Encapsulation
class AnalysisResponse(BaseModel):
    """Schema for traffic analysis endpoint response."""

    total_flows: int
    alert_count: int
    attack_type_counts: dict[str, int]
    alerts: list[AlertSchema]


# Encapsulation
class HealthResponse(BaseModel):
    """Schema for health status response."""

    status: str
    model_loaded: bool


# Encapsulation
class ConfigUpdateRequest(BaseModel):
    """Schema for updating engine runtime configuration."""

    strategy: Optional[str] = Field(None, description="Aggregation strategy: weighted, max, vote")
    threshold: Optional[float] = Field(None, ge=0.0, le=1.0, description="Alert confidence threshold")


# Encapsulation
class ConfigResponse(BaseModel):
    """Schema for active engine configuration response."""

    strategy: str
    threshold: float
    available_strategies: list[str]


# Encapsulation
class LiveStartRequest(BaseModel):
    """Schema for starting live capture."""

    window_seconds: float = Field(2.0, ge=1.0, le=60.0, description="Flow aggregation window")
    strategy: Optional[str] = Field(None, description="Scoring strategy override")
    threshold: Optional[float] = Field(None, ge=0.0, le=1.0, description="Alert threshold override")


# Encapsulation
class LiveStatusResponse(BaseModel):
    """Schema for live capture status."""

    running: bool
    window_seconds: float
    packets_seen: int
    has_pcap: bool = False
    capture_mode: str = "unknown"
