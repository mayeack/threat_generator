from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class DiurnalConfig:
    enabled: bool = True
    peak_hours: tuple[int, int] = (8, 18)
    peak_multiplier: float = 1.5
    trough_multiplier: float = 0.3


@dataclass
class SourcetypeConfig:
    weight: int
    file: str


@dataclass
class CampaignConfig:
    enabled: bool = True
    interval_minutes: tuple[int, int] = (10, 30)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class EngineConfig:
    output_dir: str = "./logs"
    eps: float = 5.0
    threat_ratio: float = 0.08
    diurnal: DiurnalConfig = field(default_factory=DiurnalConfig)
    sourcetypes: dict[str, SourcetypeConfig] = field(default_factory=dict)
    campaigns: dict[str, CampaignConfig] = field(default_factory=dict)
    topology_data: dict[str, Any] = field(default_factory=dict)
    seed: Optional[int] = None


def parse_config(raw: dict) -> EngineConfig:
    diurnal_raw = raw.get("diurnal", {})
    diurnal = DiurnalConfig(
        enabled=diurnal_raw.get("enabled", True),
        peak_hours=tuple(diurnal_raw.get("peak_hours", [8, 18])),
        peak_multiplier=diurnal_raw.get("peak_multiplier", 1.5),
        trough_multiplier=diurnal_raw.get("trough_multiplier", 0.3),
    )

    sourcetypes: dict[str, SourcetypeConfig] = {}
    for name, st in raw.get("sourcetypes", {}).items():
        sourcetypes[name] = SourcetypeConfig(weight=st["weight"], file=st["file"])

    campaigns: dict[str, CampaignConfig] = {}
    for name, camp in raw.get("threat_campaigns", {}).items():
        interval = camp.get("interval_minutes", [10, 30])
        extra = {k: v for k, v in camp.items() if k not in ("enabled", "interval_minutes")}
        campaigns[name] = CampaignConfig(
            enabled=camp.get("enabled", True),
            interval_minutes=tuple(interval),
            extra=extra,
        )

    return EngineConfig(
        output_dir=raw.get("output_dir", "./logs"),
        eps=raw.get("eps", 5.0),
        threat_ratio=raw.get("threat_ratio", 0.08),
        diurnal=diurnal,
        sourcetypes=sourcetypes,
        campaigns=campaigns,
        topology_data=raw.get("topology", {}),
    )
