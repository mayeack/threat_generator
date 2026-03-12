from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class RunState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"


class GeneratorStatus(BaseModel):
    state: RunState = RunState.IDLE
    run_id: Optional[int] = None
    uptime_seconds: float = 0.0
    total_events: int = 0


class StatsResponse(BaseModel):
    state: RunState
    uptime_seconds: float
    total_events: int
    events_by_sourcetype: dict[str, int]
    threat_events: int
    current_eps: float


class ConfigUpdate(BaseModel):
    eps: Optional[float] = None
    threat_ratio: Optional[float] = None
    output_dir: Optional[str] = None
    diurnal: Optional[dict[str, Any]] = None
    sourcetypes: Optional[dict[str, Any]] = None


class TopologyUpdate(BaseModel):
    topology: dict[str, Any]


class CampaignInfo(BaseModel):
    id: str
    name: str
    enabled: bool
    interval_minutes: list[int]
    description: str
    mitre_techniques: list[str]
    iocs: dict[str, Any]


class CampaignToggle(BaseModel):
    enabled: bool


class SavedConfig(BaseModel):
    id: int
    name: str
    created_at: str
    is_active: bool
