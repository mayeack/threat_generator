from __future__ import annotations

import asyncio
import logging
import random
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from threatgen import database as db
from threatgen.database import get_active_config
from threatgen.engine.config import parse_config
from threatgen.engine.llm.cache import serialize_snapshot
from threatgen.engine.llm.client import LLMConfig
from threatgen.engine.llm.key_store import (
    ENV_KEY_NAME,
    InvalidKeyFormat,
    KeyStoreError,
    KeyStoreUnavailable,
    key_store,
)
from threatgen.engine.llm.runtime import SOURCETYPES, runtime as llm_runtime
from threatgen.engine.topology import Topology
from threatgen.models import LLMConfigUpdate, LLMKeyUpdate

logger = logging.getLogger(__name__)

router = APIRouter()

_PREVIEW_GENERATOR_CLASSES = None


def _lazy_import_generators():
    global _PREVIEW_GENERATOR_CLASSES
    if _PREVIEW_GENERATOR_CLASSES is not None:
        return _PREVIEW_GENERATOR_CLASSES
    from threatgen.engine.generators.dns import DNSGenerator
    from threatgen.engine.generators.firewall import FirewallGenerator
    from threatgen.engine.generators.http import HTTPGenerator
    from threatgen.engine.generators.linux_secure import LinuxSecureGenerator
    from threatgen.engine.generators.sysmon import SysmonGenerator
    from threatgen.engine.generators.wineventlog import WinEventLogGenerator

    _PREVIEW_GENERATOR_CLASSES = {
        "wineventlog": WinEventLogGenerator,
        "sysmon": SysmonGenerator,
        "linux_secure": LinuxSecureGenerator,
        "dns": DNSGenerator,
        "http": HTTPGenerator,
        "firewall": FirewallGenerator,
    }
    return _PREVIEW_GENERATOR_CLASSES


@router.get("/status")
async def get_llm_status() -> dict:
    snapshot = llm_runtime.cache.snapshot()
    worker = llm_runtime.worker
    planner = llm_runtime.planner
    payload = serialize_snapshot(snapshot)
    payload["worker_running"] = bool(worker and worker.running)
    payload["planner_enabled"] = bool(planner and planner.enabled)
    payload["paused"] = bool(llm_runtime.paused)
    payload["model"] = llm_runtime.cfg.model
    payload["campaign_model"] = llm_runtime.cfg.campaign_model
    return payload


def _public_llm_config(raw: dict) -> dict:
    """Return a safe-to-expose view of the LLM config. The Anthropic API key
    is NEVER included; only flags indicating whether a key is available and
    where it came from (env var vs OS keychain)."""
    defaults = LLMConfig()
    src = raw.get("llm", {}) or {}
    info = key_store.info()
    return {
        "enabled": bool(src.get("enabled", defaults.enabled)),
        "model": str(src.get("model", defaults.model)),
        "campaign_model": str(src.get("campaign_model", defaults.campaign_model)),
        "variation_pool_size": int(src.get("variation_pool_size", defaults.variation_pool_size)),
        "low_water": int(src.get("low_water", defaults.low_water)),
        "batch_size": int(src.get("batch_size", defaults.batch_size)),
        "refresh_interval_minutes": int(
            src.get("refresh_interval_minutes", defaults.refresh_interval_minutes)
        ),
        "request_timeout_s": float(src.get("request_timeout_s", defaults.request_timeout_s)),
        "max_concurrent_requests": int(
            src.get("max_concurrent_requests", defaults.max_concurrent_requests)
        ),
        "max_retries": int(src.get("max_retries", defaults.max_retries)),
        "max_tokens_variations": int(
            src.get("max_tokens_variations", defaults.max_tokens_variations)
        ),
        "max_tokens_campaign": int(src.get("max_tokens_campaign", defaults.max_tokens_campaign)),
        # Legacy alias kept for older clients; identical to key_present.
        "key_env_set": info.present,
        "key_present": info.present,
        "key_source": info.source,  # "env" | "keychain" | "none"
        "key_env_var": ENV_KEY_NAME,
    }


@router.get("/config")
async def get_llm_config() -> dict:
    raw = await get_active_config()
    return _public_llm_config(raw)


@router.put("/config")
async def update_llm_config(update: LLMConfigUpdate) -> dict:
    patch = update.model_dump(exclude_none=True)
    if not patch:
        raise HTTPException(400, "No fields to update")

    new_cfg = await db.update_active_config({"llm": patch})

    try:
        parsed = parse_config(new_cfg)
        llm_runtime.configure(parsed.llm)
        worker = llm_runtime.worker
        if worker is not None:
            if parsed.llm.enabled and not worker.running and not llm_runtime.paused:
                await worker.start()
            elif (not parsed.llm.enabled or llm_runtime.paused) and worker.running:
                await worker.stop()
    except Exception:
        logger.exception("llm_runtime_reconfigure_failed")
        raise HTTPException(500, "Failed to apply LLM configuration")

    return _public_llm_config(new_cfg)


# ---------------------------------------------------------------------------
# API-key management
#
# Simple in-process rate limiter to slow down brute-force attempts against
# the loopback interface. This is defense-in-depth; the main protection is
# that the service binds only to 127.0.0.1 and that the key is validated
# by format before ever being handed to the SDK.
# ---------------------------------------------------------------------------
_KEY_RATE_LOCK = asyncio.Lock()
_KEY_RATE_STATE: dict[str, float] = {"last_ts": 0.0, "window_start": 0.0, "count": 0}
_KEY_RATE_WINDOW_S = 60.0
_KEY_RATE_MAX = 10  # writes per minute per process


async def _rate_limit_key_writes() -> None:
    async with _KEY_RATE_LOCK:
        now = time.monotonic()
        if now - _KEY_RATE_STATE["window_start"] > _KEY_RATE_WINDOW_S:
            _KEY_RATE_STATE["window_start"] = now
            _KEY_RATE_STATE["count"] = 0
        _KEY_RATE_STATE["count"] += 1
        if _KEY_RATE_STATE["count"] > _KEY_RATE_MAX:
            raise HTTPException(429, "Too many key-management requests; slow down")
        _KEY_RATE_STATE["last_ts"] = now


async def _apply_key_change() -> None:
    """Reflect a key add/remove into the LLM runtime and worker."""
    try:
        llm_runtime.refresh_key_state()
        worker = llm_runtime.worker
        if worker is not None:
            eligible = (
                llm_runtime.cfg.enabled
                and llm_runtime.client
                and llm_runtime.client.key_present
                and not llm_runtime.paused
            )
            if eligible:
                if not worker.running:
                    await worker.start()
            else:
                if worker.running:
                    await worker.stop()
    except Exception:
        logger.exception("llm_runtime_key_apply_failed")


@router.get("/key")
async def get_llm_key_status() -> dict:
    """Reports whether a key is configured and where it came from.
    The key value itself is never returned."""
    info = key_store.info()
    return {
        "present": info.present,
        "source": info.source,  # "env" | "keychain" | "none"
        "env_var": ENV_KEY_NAME,
    }


@router.put("/key")
async def set_llm_key(body: LLMKeyUpdate) -> dict:
    """Store the Anthropic API key in the OS keychain.

    The key is:
      - validated for expected format,
      - never logged or echoed back,
      - never written to the SQLite config or YAML,
      - stored encrypted at rest by the OS keychain/secret service.
    """
    await _rate_limit_key_writes()

    try:
        key_store.set(body.api_key)
    except InvalidKeyFormat as exc:
        raise HTTPException(400, str(exc))
    except KeyStoreUnavailable as exc:
        logger.warning("llm_key_store_unavailable", extra={"error_type": type(exc).__name__})
        raise HTTPException(
            503,
            "OS secret store is unavailable on this host. "
            "Set the ANTHROPIC_API_KEY environment variable instead.",
        )
    except KeyStoreError as exc:
        raise HTTPException(400, str(exc))

    await _apply_key_change()
    # Never include the key or its hash in the response.
    info = key_store.info()
    logger.info(
        "anthropic_key_updated_via_ui",
        extra={"source": info.source, "present": info.present},
    )
    return {"present": info.present, "source": info.source, "env_var": ENV_KEY_NAME}


@router.delete("/key")
async def clear_llm_key() -> dict:
    """Remove the Anthropic API key from the OS keychain.

    Does not touch the ANTHROPIC_API_KEY environment variable; if that
    is set, the LLM subsystem will continue to use it.
    """
    await _rate_limit_key_writes()
    removed = key_store.clear()
    await _apply_key_change()
    info = key_store.info()
    logger.info(
        "anthropic_key_cleared_via_ui",
        extra={"removed": removed, "source_after": info.source},
    )
    return {
        "removed": removed,
        "present": info.present,
        "source": info.source,
        "env_var": ENV_KEY_NAME,
    }


@router.post("/pause")
async def pause_llm_worker() -> dict:
    """Stop the variation worker without persisting a config change.

    The `paused` flag lives in process memory only; a process restart
    clears it. While paused, config and key-change events will not
    auto-start the worker, so generators keep using the deterministic
    fallback path.
    """
    llm_runtime.paused = True
    worker = llm_runtime.worker
    if worker is not None and worker.running:
        await worker.stop()
    logger.info("llm_worker_paused")
    return {
        "paused": True,
        "worker_running": bool(worker and worker.running),
    }


@router.post("/resume")
async def resume_llm_worker() -> dict:
    """Clear the pause flag and restart the worker when eligible."""
    llm_runtime.paused = False
    worker = llm_runtime.worker
    started = False
    if (
        worker is not None
        and not worker.running
        and llm_runtime.cfg.enabled
        and llm_runtime.client
        and llm_runtime.client.key_present
    ):
        await worker.start()
        started = worker.running
    logger.info("llm_worker_resumed", extra={"worker_running": started})
    return {
        "paused": False,
        "worker_running": bool(worker and worker.running),
    }


@router.post("/refresh")
async def refresh_llm_cache() -> dict:
    worker = llm_runtime.worker
    if not worker:
        raise HTTPException(503, "LLM worker not initialised")
    if llm_runtime.paused:
        raise HTTPException(
            409,
            "LLM generation is paused; resume it before refreshing the pool.",
        )
    if not worker.running:
        await worker.start()
        if not worker.running:
            raise HTTPException(
                503,
                "LLM worker unavailable (check ANTHROPIC_API_KEY and config.llm.enabled)",
            )
    worker.request_refresh()
    return {"status": "refresh_requested"}


@router.get("/preview")
async def preview_cached_lines(
    sourcetype: str = Query(..., description="one of: wineventlog, sysmon, linux_secure, dns, http, firewall"),
    n: int = Query(3, ge=1, le=10),
) -> dict:
    if sourcetype not in SOURCETYPES:
        raise HTTPException(400, "unknown sourcetype")

    scenarios = await llm_runtime.cache.peek_samples(sourcetype, n)
    if not scenarios:
        return {"sourcetype": sourcetype, "count": 0, "lines": [], "reason": "cache empty"}

    raw_cfg = await get_active_config()
    cfg = parse_config(raw_cfg)
    rng = random.Random(cfg.seed)
    topology = Topology(cfg.topology_data, rng)
    topology.set_iocs({name: c.extra for name, c in cfg.campaigns.items()})

    gen_cls = _lazy_import_generators()[sourcetype]
    gen = gen_cls(topology, None)

    ts = datetime.now(timezone.utc)
    lines: list[str] = []
    for sc in scenarios:
        try:
            lines.extend(gen.render_from_scenario(sc, ts))
        except Exception:
            logger.warning("preview_render_failed", extra={"sourcetype": sourcetype}, exc_info=True)
    return {"sourcetype": sourcetype, "count": len(lines), "lines": lines}
