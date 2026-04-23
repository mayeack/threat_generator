from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from threatgen.engine.llm.client import LLMConfig


# Canonical Splunk sourcetypes emitted by the HEC forwarder. Keys are the
# internal ThreatGen sourcetype names used by the generators; values are the
# OOTB Splunk sourcetypes that Exposure Analytics, CIM datamodels, and every
# bundled hunt guide / dashboard / skill already target. Keeping this map
# close to the dataclass (not just the YAML) ensures that even a stored
# config in threatgen.db that predates the map still lands events under the
# canonical sourcetypes; without it, Exposure Analytics entity templates
# would need per-install customization. `_migrate_hec_sourcetype_map` in
# threatgen/database.py backfills these entries into persisted configs.
_CANONICAL_HEC_SOURCETYPE_MAP: dict[str, str] = {
    "wineventlog": "WinEventLog:Security",
    "sysmon": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "linux_secure": "linux_secure",
    "stream:dns": "stream:dns",
    "stream:http": "stream:http",
    "cisco:asa": "cisco:asa",
}


# Canonical Splunk ``source`` values emitted by the HEC forwarder. Only three
# families need source overrides: EA's Linux_sshd / WinSysmon / WinSecurity
# discovery sources include ``source=...`` terms in their OOTB search filters.
# stream:* and cisco:asa have no ``source=`` requirement, so they keep their
# legacy ``threatgen:<family>`` derivation. `_migrate_hec_source_map` in
# threatgen/database.py backfills these entries into persisted configs so
# upgrading deployments get the canonical mapping without manual edits.
_CANONICAL_HEC_SOURCE_MAP: dict[str, str] = {
    "wineventlog": "WinEventLog:Security",
    "sysmon": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "linux_secure": "/var/log/secure",
}


@dataclass
class HECConfig:
    enabled: bool = False
    url: str = ""
    verify_tls: bool = True
    default_index: str = "main"
    default_source: str = "threatgen"
    default_host: str = "threatgen"
    sourcetype_map: dict[str, str] = field(
        default_factory=lambda: dict(_CANONICAL_HEC_SOURCETYPE_MAP)
    )
    source_map: dict[str, str] = field(
        default_factory=lambda: dict(_CANONICAL_HEC_SOURCE_MAP)
    )
    batch_size: int = 100
    flush_interval_s: float = 2.0
    queue_max: int = 10000
    request_timeout_s: float = 10.0
    max_retries: int = 3


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
    llm: LLMConfig = field(default_factory=LLMConfig)
    hec: HECConfig = field(default_factory=HECConfig)
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

    llm_raw = raw.get("llm", {}) or {}
    defaults = LLMConfig()
    llm = LLMConfig(
        enabled=bool(llm_raw.get("enabled", defaults.enabled)),
        model=str(llm_raw.get("model", defaults.model)),
        campaign_model=str(llm_raw.get("campaign_model", defaults.campaign_model)),
        variation_pool_size=int(llm_raw.get("variation_pool_size", defaults.variation_pool_size)),
        low_water=int(llm_raw.get("low_water", defaults.low_water)),
        batch_size=int(llm_raw.get("batch_size", defaults.batch_size)),
        refresh_interval_minutes=int(llm_raw.get("refresh_interval_minutes", defaults.refresh_interval_minutes)),
        request_timeout_s=float(llm_raw.get("request_timeout_s", defaults.request_timeout_s)),
        max_concurrent_requests=int(llm_raw.get("max_concurrent_requests", defaults.max_concurrent_requests)),
        max_retries=int(llm_raw.get("max_retries", defaults.max_retries)),
        max_tokens_variations=int(llm_raw.get("max_tokens_variations", defaults.max_tokens_variations)),
        max_tokens_campaign=int(llm_raw.get("max_tokens_campaign", defaults.max_tokens_campaign)),
    )

    hec_raw = raw.get("hec", {}) or {}
    hec_defaults = HECConfig()
    sourcetype_map_raw = hec_raw.get("sourcetype_map", hec_defaults.sourcetype_map) or {}
    sourcetype_map = {
        str(k): str(v) for k, v in sourcetype_map_raw.items() if isinstance(k, str)
    }
    source_map_raw = hec_raw.get("source_map", hec_defaults.source_map) or {}
    source_map = {
        str(k): str(v) for k, v in source_map_raw.items() if isinstance(k, str)
    }
    hec = HECConfig(
        enabled=bool(hec_raw.get("enabled", hec_defaults.enabled)),
        url=str(hec_raw.get("url", hec_defaults.url) or ""),
        verify_tls=bool(hec_raw.get("verify_tls", hec_defaults.verify_tls)),
        default_index=str(hec_raw.get("default_index", hec_defaults.default_index)),
        default_source=str(hec_raw.get("default_source", hec_defaults.default_source)),
        default_host=str(hec_raw.get("default_host", hec_defaults.default_host)),
        sourcetype_map=sourcetype_map,
        source_map=source_map,
        batch_size=max(1, int(hec_raw.get("batch_size", hec_defaults.batch_size))),
        flush_interval_s=max(0.1, float(hec_raw.get("flush_interval_s", hec_defaults.flush_interval_s))),
        queue_max=max(1, int(hec_raw.get("queue_max", hec_defaults.queue_max))),
        request_timeout_s=max(1.0, float(hec_raw.get("request_timeout_s", hec_defaults.request_timeout_s))),
        max_retries=max(0, int(hec_raw.get("max_retries", hec_defaults.max_retries))),
    )

    return EngineConfig(
        output_dir=raw.get("output_dir", "./logs"),
        eps=raw.get("eps", 5.0),
        threat_ratio=raw.get("threat_ratio", 0.08),
        diurnal=diurnal,
        sourcetypes=sourcetypes,
        campaigns=campaigns,
        topology_data=raw.get("topology", {}),
        llm=llm,
        hec=hec,
    )
