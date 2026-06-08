from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from threatgen.engine.llm.client import LLMConfig

# Destination ids are used as keyring usernames and URL path components,
# so we restrict them to a tight alphabet (lowercase ASCII letters, digits,
# hyphen) with a bounded length to avoid traversal, injection, or
# keychain-name surprises.
_DEST_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


def is_valid_dest_id(value: str) -> bool:
    """Return True when ``value`` matches the strict destination-id shape."""
    return isinstance(value, str) and bool(_DEST_ID_RE.match(value))


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


DEFAULT_HEC_DEST_ID = "default"
DEFAULT_HEC_DEST_NAME = "Primary"


@dataclass
class HECConfig:
    # Identity. ``id`` is the stable handle used by the API, the runtime,
    # and (critically) the OS keychain user-name for the per-destination
    # token. ``name`` is the operator-facing display label.
    id: str = DEFAULT_HEC_DEST_ID
    name: str = DEFAULT_HEC_DEST_NAME
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
    # ``hec_destinations`` is the source of truth for multi-instance
    # fan-out. ``hec`` is preserved as a convenience alias to the first
    # (typically ``default``) destination so legacy single-destination
    # call sites keep working without churn.
    hec_destinations: list[HECConfig] = field(default_factory=list)
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

    hec_destinations = _parse_hec_destinations(raw)
    # Convenience alias for legacy single-destination callers. The first
    # destination wins; if none are configured we fall back to defaults.
    hec_primary = hec_destinations[0] if hec_destinations else HECConfig()

    return EngineConfig(
        output_dir=raw.get("output_dir", "./logs"),
        eps=raw.get("eps", 5.0),
        threat_ratio=raw.get("threat_ratio", 0.08),
        diurnal=diurnal,
        sourcetypes=sourcetypes,
        campaigns=campaigns,
        topology_data=raw.get("topology", {}),
        llm=llm,
        hec_destinations=hec_destinations,
        hec=hec_primary,
    )


def _parse_one_hec(raw: dict[str, Any], *, fallback_id: str, fallback_name: str) -> HECConfig:
    """Parse a single HEC destination dict into an ``HECConfig``.

    Reused by ``parse_config`` for both legacy single-destination configs
    and the new ``hec_destinations`` list so the field-level validation
    stays in one place.
    """
    defaults = HECConfig()

    raw_id = str(raw.get("id", fallback_id) or fallback_id).strip().lower()
    dest_id = raw_id if _DEST_ID_RE.match(raw_id) else fallback_id

    raw_name = raw.get("name", fallback_name)
    name = str(raw_name).strip() if raw_name is not None else fallback_name
    if not name:
        name = fallback_name

    sourcetype_map_raw = raw.get("sourcetype_map", defaults.sourcetype_map) or {}
    sourcetype_map = {
        str(k): str(v) for k, v in sourcetype_map_raw.items() if isinstance(k, str)
    }
    source_map_raw = raw.get("source_map", defaults.source_map) or {}
    source_map = {
        str(k): str(v) for k, v in source_map_raw.items() if isinstance(k, str)
    }

    return HECConfig(
        id=dest_id,
        name=name,
        enabled=bool(raw.get("enabled", defaults.enabled)),
        url=str(raw.get("url", defaults.url) or ""),
        verify_tls=bool(raw.get("verify_tls", defaults.verify_tls)),
        default_index=str(raw.get("default_index", defaults.default_index)),
        default_source=str(raw.get("default_source", defaults.default_source)),
        default_host=str(raw.get("default_host", defaults.default_host)),
        sourcetype_map=sourcetype_map,
        source_map=source_map,
        batch_size=max(1, int(raw.get("batch_size", defaults.batch_size))),
        flush_interval_s=max(0.1, float(raw.get("flush_interval_s", defaults.flush_interval_s))),
        queue_max=max(1, int(raw.get("queue_max", defaults.queue_max))),
        request_timeout_s=max(1.0, float(raw.get("request_timeout_s", defaults.request_timeout_s))),
        max_retries=max(0, int(raw.get("max_retries", defaults.max_retries))),
    )


def _parse_hec_destinations(raw: dict[str, Any]) -> list[HECConfig]:
    """Parse the top-level HEC destination list.

    Precedence:
      1. ``hec_destinations`` list (new, multi-destination shape).
      2. Legacy ``hec`` dict, wrapped as a single ``default`` destination.
      3. Empty list (caller decides whether to inject a stub).

    Destination ids are de-duplicated by suffixing ``-1``, ``-2`` ... so
    the runtime/keychain layer can safely use them as unique handles.
    """
    out: list[HECConfig] = []
    seen_ids: set[str] = set()

    destinations_raw = raw.get("hec_destinations")
    if isinstance(destinations_raw, list) and destinations_raw:
        for idx, item in enumerate(destinations_raw):
            if not isinstance(item, dict):
                continue
            fallback_id = DEFAULT_HEC_DEST_ID if idx == 0 else f"dest-{idx}"
            fallback_name = (
                DEFAULT_HEC_DEST_NAME if idx == 0 else f"Destination {idx + 1}"
            )
            cfg = _parse_one_hec(item, fallback_id=fallback_id, fallback_name=fallback_name)
            # Ensure id uniqueness within the parsed set.
            unique_id = cfg.id
            suffix = 1
            while unique_id in seen_ids:
                unique_id = f"{cfg.id}-{suffix}"
                suffix += 1
                if not _DEST_ID_RE.match(unique_id):
                    unique_id = f"dest-{idx}-{suffix}"
            if unique_id != cfg.id:
                cfg = HECConfig(**{**cfg.__dict__, "id": unique_id})
            seen_ids.add(unique_id)
            out.append(cfg)
        return out

    legacy = raw.get("hec")
    if isinstance(legacy, dict):
        out.append(
            _parse_one_hec(
                legacy,
                fallback_id=DEFAULT_HEC_DEST_ID,
                fallback_name=DEFAULT_HEC_DEST_NAME,
            )
        )

    return out
