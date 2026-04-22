from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from fastapi import APIRouter, HTTPException

from threatgen import database as db
from threatgen.engine.config import parse_config
from threatgen.engine.hec.key_store import (
    ENV_KEY_NAME as HEC_TOKEN_ENV,
    InvalidKeyFormat,
    KeyStoreError,
    KeyStoreUnavailable,
    hec_key_store,
)
from threatgen.engine.hec.runtime import hec_runtime
from threatgen.models import (
    HECConfigUpdate,
    HECKeyUpdate,
    HECStatsResponse,
    HECTestResult,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _public_hec_config(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a safe-to-expose view of the HEC config. The token is
    NEVER included; only flags indicating whether a token is available
    and where it came from (env var vs OS keychain)."""
    hec = raw.get("hec", {}) or {}
    info = hec_key_store.info()
    return {
        "enabled": bool(hec.get("enabled", False)),
        "url": hec.get("url", ""),
        "verify_tls": bool(hec.get("verify_tls", True)),
        "default_index": hec.get("default_index", "main"),
        "default_source": hec.get("default_source", "threatgen"),
        "default_host": hec.get("default_host", "threatgen"),
        "sourcetype_map": hec.get("sourcetype_map", {}) or {},
        "batch_size": int(hec.get("batch_size", 100)),
        "flush_interval_s": float(hec.get("flush_interval_s", 2.0)),
        "queue_max": int(hec.get("queue_max", 10000)),
        "request_timeout_s": float(hec.get("request_timeout_s", 10.0)),
        "max_retries": int(hec.get("max_retries", 3)),
        # Legacy alias kept for older clients; identical to token_present.
        "token_env_set": info.present,
        "token_present": info.present,
        "token_source": info.source,  # "env" | "keychain" | "none"
        "token_env_var": HEC_TOKEN_ENV,
    }


@router.get("/config")
async def get_hec_config() -> dict[str, Any]:
    raw = await db.get_active_config()
    return _public_hec_config(raw)


@router.put("/config")
async def update_hec_config(update: HECConfigUpdate) -> dict[str, Any]:
    patch = update.model_dump(exclude_none=True)
    if not patch:
        raise HTTPException(400, "No fields to update")

    # Persist under the top-level `hec` key via deep-merge semantics.
    new_cfg = await db.update_active_config({"hec": patch})

    # Reconfigure runtime and restart if enabled.
    try:
        parsed = parse_config(new_cfg)
        hec_runtime.configure(parsed.hec)
        await hec_runtime.restart()
    except Exception:
        logger.exception("hec_runtime_reconfigure_failed")
        raise HTTPException(500, "Failed to apply HEC configuration")

    return _public_hec_config(new_cfg)


@router.post("/test", response_model=HECTestResult)
async def test_hec() -> HECTestResult:
    # Ensure runtime has the latest config before testing.
    raw = await db.get_active_config()
    try:
        parsed = parse_config(raw)
        hec_runtime.configure(parsed.hec)
    except Exception:
        logger.exception("hec_test_configure_failed")
        raise HTTPException(500, "Failed to load HEC configuration")

    if not parsed.hec.url:
        return HECTestResult(ok=False, status_code=None, latency_ms=0.0, error="url not configured")

    result = await hec_runtime.test_send()
    return HECTestResult(
        ok=result.ok,
        status_code=result.status_code,
        latency_ms=round(result.latency_ms, 1),
        error=result.error,
    )


# ---------------------------------------------------------------------------
# HEC token management
#
# Mirrors threatgen.api.llm key endpoints. Defense-in-depth:
#  * Service binds to loopback by default (see uvicorn launch).
#  * Token is validated for expected UUID shape via HECKeyUpdate.
#  * Token is never echoed or logged; only its source and presence flags
#    are surfaced to clients.
#  * Simple in-process rate limiter throttles brute-force attempts.
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


async def _apply_token_change() -> None:
    """Reflect a token add/remove into the running HEC forwarder.

    The forwarder captures the token at construction time, so we must
    restart it to pick up a new value. Restart is safe even when the
    forwarder wasn't running."""
    raw = await db.get_active_config()
    try:
        parsed = parse_config(raw)
        hec_runtime.configure(parsed.hec)
        if parsed.hec.enabled:
            await hec_runtime.restart()
        else:
            await hec_runtime.stop()
    except Exception:
        logger.exception("hec_runtime_token_apply_failed")


@router.get("/key")
async def get_hec_key_status() -> dict[str, Any]:
    """Reports whether a HEC token is configured and where it came from.
    The token value itself is never returned."""
    info = hec_key_store.info()
    return {
        "present": info.present,
        "source": info.source,  # "env" | "keychain" | "none"
        "env_var": HEC_TOKEN_ENV,
    }


@router.put("/key")
async def set_hec_key(body: HECKeyUpdate) -> dict[str, Any]:
    """Store the Splunk HEC token in the OS keychain.

    The token is:
      - validated for expected UUID format,
      - never logged or echoed back,
      - never written to the SQLite config or YAML,
      - stored encrypted at rest by the OS keychain/secret service.
    """
    await _rate_limit_key_writes()

    try:
        hec_key_store.set(body.token)
    except InvalidKeyFormat as exc:
        raise HTTPException(400, str(exc))
    except KeyStoreUnavailable as exc:
        logger.warning(
            "hec_key_store_unavailable",
            extra={"error_type": type(exc).__name__},
        )
        raise HTTPException(
            503,
            "OS secret store is unavailable on this host. "
            f"Set the {HEC_TOKEN_ENV} environment variable instead.",
        )
    except KeyStoreError as exc:
        raise HTTPException(400, str(exc))

    await _apply_token_change()
    info = hec_key_store.info()
    logger.info(
        "hec_token_updated_via_ui",
        extra={"source": info.source, "present": info.present},
    )
    return {"present": info.present, "source": info.source, "env_var": HEC_TOKEN_ENV}


@router.delete("/key")
async def clear_hec_key() -> dict[str, Any]:
    """Remove the HEC token from the OS keychain.

    Does not touch the SPLUNK_HEC_TOKEN environment variable; if that
    is set, the forwarder will continue to use it.
    """
    await _rate_limit_key_writes()
    removed = hec_key_store.clear()
    await _apply_token_change()
    info = hec_key_store.info()
    logger.info(
        "hec_token_cleared_via_ui",
        extra={"removed": removed, "source_after": info.source},
    )
    return {
        "removed": removed,
        "present": info.present,
        "source": info.source,
        "env_var": HEC_TOKEN_ENV,
    }


@router.get("/stats", response_model=HECStatsResponse)
async def hec_stats() -> HECStatsResponse:
    s = hec_runtime.stats()
    return HECStatsResponse(
        enabled=s.enabled,
        running=s.running,
        token_present=s.token_present,
        events_sent=s.events_sent,
        events_failed=s.events_failed,
        events_dropped=s.events_dropped,
        batches_sent=s.batches_sent,
        batches_failed=s.batches_failed,
        queue_depth=s.queue_depth,
        queue_capacity=s.queue_capacity,
        last_success_at=s.last_success_at,
        last_error_at=s.last_error_at,
        last_error=s.last_error,
        last_latency_ms=s.last_latency_ms,
    )
