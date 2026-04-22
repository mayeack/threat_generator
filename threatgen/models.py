from __future__ import annotations

import re
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


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


_HEC_URL_RE = re.compile(r"^https://[A-Za-z0-9._-]+(:\d{2,5})?(/.*)?$")
_HEC_SAFE_STR_RE = re.compile(r"^[A-Za-z0-9._:\-/]+$")
_LLM_MODEL_RE = re.compile(r"^[A-Za-z0-9._:\-/]{1,100}$")


class LLMConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    model: Optional[str] = Field(default=None, max_length=100)
    campaign_model: Optional[str] = Field(default=None, max_length=100)
    variation_pool_size: Optional[int] = Field(default=None, ge=1, le=1000)
    low_water: Optional[int] = Field(default=None, ge=1, le=1000)
    batch_size: Optional[int] = Field(default=None, ge=1, le=100)
    refresh_interval_minutes: Optional[int] = Field(default=None, ge=1, le=1440)
    request_timeout_s: Optional[float] = Field(default=None, ge=1.0, le=300.0)
    max_concurrent_requests: Optional[int] = Field(default=None, ge=1, le=20)
    max_retries: Optional[int] = Field(default=None, ge=0, le=10)
    max_tokens_variations: Optional[int] = Field(default=None, ge=256, le=32000)
    max_tokens_campaign: Optional[int] = Field(default=None, ge=256, le=32000)

    @field_validator("model", "campaign_model")
    @classmethod
    def _validate_model_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        s = v.strip()
        if not s:
            raise ValueError("model name cannot be empty")
        if not _LLM_MODEL_RE.match(s):
            raise ValueError("model may only contain letters, digits, . _ - : /")
        return s


_ANTHROPIC_KEY_RE = re.compile(r"^sk-ant-[A-Za-z0-9_\-]{20,500}$")


class LLMKeyUpdate(BaseModel):
    """Request body for storing an Anthropic API key via the UI.

    The key is validated here but is NEVER echoed back by any
    endpoint, never persisted to the DB or YAML, and is redacted from
    logs.
    """

    api_key: str = Field(..., min_length=20, max_length=500)

    @field_validator("api_key")
    @classmethod
    def _validate_key(cls, v: str) -> str:
        s = (v or "").strip()
        if not _ANTHROPIC_KEY_RE.match(s):
            raise ValueError(
                "api_key does not look like an Anthropic key (expected sk-ant-...)"
            )
        return s


_HEC_TOKEN_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class HECKeyUpdate(BaseModel):
    """Request body for storing a Splunk HEC token via the UI.

    The token is validated here but is NEVER echoed back by any
    endpoint, never persisted to the DB or YAML, and is redacted from
    logs.
    """

    token: str = Field(..., min_length=36, max_length=36)

    @field_validator("token")
    @classmethod
    def _validate_token(cls, v: str) -> str:
        s = (v or "").strip()
        if not _HEC_TOKEN_RE.match(s):
            raise ValueError(
                "token does not look like a Splunk HEC token "
                "(expected UUID: 8-4-4-4-12 hex characters)"
            )
        return s


class HECConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    url: Optional[str] = Field(default=None, max_length=512)
    verify_tls: Optional[bool] = None
    default_index: Optional[str] = Field(default=None, max_length=80)
    default_source: Optional[str] = Field(default=None, max_length=200)
    default_host: Optional[str] = Field(default=None, max_length=200)
    sourcetype_map: Optional[dict[str, str]] = None
    batch_size: Optional[int] = Field(default=None, ge=1, le=10000)
    flush_interval_s: Optional[float] = Field(default=None, ge=0.1, le=300.0)
    queue_max: Optional[int] = Field(default=None, ge=1, le=1000000)
    request_timeout_s: Optional[float] = Field(default=None, ge=1.0, le=300.0)
    max_retries: Optional[int] = Field(default=None, ge=0, le=10)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        s = v.strip()
        if not s:
            return ""
        if not _HEC_URL_RE.match(s):
            raise ValueError("url must be https:// and use a valid host")
        return s

    @field_validator("default_index", "default_source", "default_host")
    @classmethod
    def _validate_safe_str(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        s = v.strip()
        if not s:
            raise ValueError("value cannot be empty")
        if not _HEC_SAFE_STR_RE.match(s):
            raise ValueError("only letters, digits, . _ - : / are allowed")
        return s

    @field_validator("sourcetype_map")
    @classmethod
    def _validate_sourcetype_map(cls, v: Optional[dict[str, str]]) -> Optional[dict[str, str]]:
        if v is None:
            return v
        cleaned: dict[str, str] = {}
        for k, val in v.items():
            if not isinstance(k, str) or not isinstance(val, str):
                raise ValueError("sourcetype_map keys and values must be strings")
            ks, vs = k.strip(), val.strip()
            if not ks:
                continue
            if not _HEC_SAFE_STR_RE.match(ks):
                raise ValueError(f"invalid generator name: {ks!r}")
            if vs and not _HEC_SAFE_STR_RE.match(vs):
                raise ValueError(f"invalid sourcetype override: {vs!r}")
            if vs:
                cleaned[ks] = vs
        return cleaned


class HECStatsResponse(BaseModel):
    enabled: bool
    running: bool
    token_present: bool
    events_sent: int
    events_failed: int
    events_dropped: int
    batches_sent: int
    batches_failed: int
    queue_depth: int
    queue_capacity: int
    last_success_at: Optional[str] = None
    last_error_at: Optional[str] = None
    last_error: Optional[str] = None
    last_latency_ms: Optional[float] = None


class HECTestResult(BaseModel):
    ok: bool
    status_code: Optional[int] = None
    latency_ms: float
    error: Optional[str] = None
