from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, HTTPException

from threatgen import database as db
from threatgen.engine.config import (
    DEFAULT_HEC_DEST_ID,
    HECConfig,
    is_valid_dest_id,
    parse_config,
)
from threatgen.engine.hec.key_store import (
    ENV_KEY_NAME as HEC_TOKEN_ENV,
    InvalidDestinationId,
    InvalidKeyFormat,
    KeyStoreError,
    KeyStoreUnavailable,
    hec_key_store,
)
from threatgen.engine.hec.runtime import hec_runtime
from threatgen.models import (
    HECConfigUpdate,
    HECDestinationCreate,
    HECDestinationUpdate,
    HECKeyUpdate,
    HECStatsResponse,
    HECTestResult,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _public_destination(dest: dict[str, Any]) -> dict[str, Any]:
    """Return a safe-to-expose view of a single HEC destination.

    Tokens are NEVER included; we surface only ``token_present`` and
    ``token_source`` flags so the UI can render the correct badge. The
    same shape used to be returned by the legacy ``/api/hec/config``
    response, so legacy clients keep working through the shim below.
    """
    dest_id = dest.get("id") or DEFAULT_HEC_DEST_ID
    try:
        info = hec_key_store.info(dest_id)
        env_var = hec_key_store.env_var_for(dest_id)
    except InvalidDestinationId:
        info = hec_key_store.info(DEFAULT_HEC_DEST_ID)
        env_var = HEC_TOKEN_ENV

    return {
        "id": dest_id,
        "name": dest.get("name") or "",
        "enabled": bool(dest.get("enabled", False)),
        "url": dest.get("url", ""),
        "verify_tls": bool(dest.get("verify_tls", True)),
        "default_index": dest.get("default_index", "main"),
        "default_source": dest.get("default_source", "threatgen"),
        "default_host": dest.get("default_host", "threatgen"),
        "sourcetype_map": dest.get("sourcetype_map", {}) or {},
        "batch_size": int(dest.get("batch_size", 100)),
        "flush_interval_s": float(dest.get("flush_interval_s", 2.0)),
        "queue_max": int(dest.get("queue_max", 10000)),
        "request_timeout_s": float(dest.get("request_timeout_s", 10.0)),
        "max_retries": int(dest.get("max_retries", 3)),
        # Legacy alias kept for older clients; identical to token_present.
        "token_env_set": info.present,
        "token_present": info.present,
        "token_source": info.source,  # "env" | "keychain" | "none"
        "token_env_var": env_var,
    }


async def _reload_runtime() -> None:
    """Re-read the active config and reconcile the forwarder set."""
    raw = await db.get_active_config()
    try:
        parsed = parse_config(raw)
        hec_runtime.configure(parsed.hec_destinations)
        await hec_runtime.restart()
    except Exception:
        logger.exception("hec_runtime_reconfigure_failed")
        raise HTTPException(500, "Failed to apply HEC configuration")


def _require_valid_dest_id(dest_id: str) -> str:
    if not is_valid_dest_id(dest_id):
        raise HTTPException(
            400, "destination id must match [a-z0-9-]{1,40} (start with letter/digit)"
        )
    return dest_id


# ---------------------------------------------------------------------------
# Destinations collection
# ---------------------------------------------------------------------------


@router.get("/destinations")
async def list_destinations() -> dict[str, Any]:
    raw_dests = await db.list_hec_destinations()
    return {"destinations": [_public_destination(d) for d in raw_dests]}


@router.post("/destinations")
async def create_destination(body: HECDestinationCreate) -> dict[str, Any]:
    """Add a new HEC destination. The ``+`` button in the UI calls this."""
    record = body.model_dump(exclude_none=True)
    # Inject canonical maps when the operator did not provide one so the
    # new destination behaves like the seeded default. The same
    # idempotent migration runs on startup so this only matters for the
    # first-after-add lifecycle.
    record.setdefault(
        "sourcetype_map",
        {
            "wineventlog": "WinEventLog:Security",
            "sysmon": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "linux_secure": "linux_secure",
            "stream:dns": "stream:dns",
            "stream:http": "stream:http",
            "cisco:asa": "cisco:asa",
        },
    )
    record.setdefault(
        "source_map",
        {
            "wineventlog": "WinEventLog:Security",
            "sysmon": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "linux_secure": "/var/log/secure",
        },
    )
    new_record = await db.add_hec_destination(record)
    await _reload_runtime()
    return _public_destination(new_record)


@router.get("/destinations/{dest_id}")
async def get_destination(dest_id: str) -> dict[str, Any]:
    _require_valid_dest_id(dest_id)
    rec = await db.get_hec_destination(dest_id)
    if rec is None:
        raise HTTPException(404, f"destination {dest_id!r} not found")
    return _public_destination(rec)


@router.put("/destinations/{dest_id}")
async def update_destination(dest_id: str, update: HECDestinationUpdate) -> dict[str, Any]:
    _require_valid_dest_id(dest_id)
    patch = update.model_dump(exclude_none=True)
    if not patch:
        raise HTTPException(400, "No fields to update")
    rec = await db.update_hec_destination(dest_id, patch)
    if rec is None:
        raise HTTPException(404, f"destination {dest_id!r} not found")
    await _reload_runtime()
    return _public_destination(rec)


@router.delete("/destinations/{dest_id}")
async def delete_destination(dest_id: str) -> dict[str, Any]:
    _require_valid_dest_id(dest_id)
    if dest_id == DEFAULT_HEC_DEST_ID:
        # Forbid deletion of the default destination so the legacy
        # single-destination API surface always has something to talk
        # to. Operators can still disable it instead.
        raise HTTPException(400, "the default destination cannot be removed; disable it instead")
    removed = await db.delete_hec_destination(dest_id)
    if not removed:
        raise HTTPException(404, f"destination {dest_id!r} not found")
    # Best-effort token cleanup. The keychain entry is encrypted and
    # only readable by this process, but leaving an orphan would be
    # surprising to operators.
    try:
        hec_key_store.clear(dest_id)
    except Exception:
        logger.warning("hec_keyring_orphan_clear_failed", extra={"dest_id": dest_id})
    await _reload_runtime()
    return {"removed": True, "id": dest_id}


@router.post("/destinations/{dest_id}/test", response_model=HECTestResult)
async def test_destination(dest_id: str) -> HECTestResult:
    _require_valid_dest_id(dest_id)
    raw = await db.get_active_config()
    try:
        parsed = parse_config(raw)
        hec_runtime.configure(parsed.hec_destinations)
    except Exception:
        logger.exception("hec_test_configure_failed")
        raise HTTPException(500, "Failed to load HEC configuration")

    target: Optional[HECConfig] = next(
        (d for d in parsed.hec_destinations if d.id == dest_id), None
    )
    if target is None:
        raise HTTPException(404, f"destination {dest_id!r} not found")
    if not target.url:
        return HECTestResult(ok=False, status_code=None, latency_ms=0.0, error="url not configured")

    result = await hec_runtime.test_send(dest_id)
    return HECTestResult(
        ok=result.ok,
        status_code=result.status_code,
        latency_ms=round(result.latency_ms, 1),
        error=result.error,
    )


# ---------------------------------------------------------------------------
# Per-destination key management
#
# Same defense-in-depth posture as the legacy single-destination route:
#  * Service binds to loopback by default.
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
    """Reflect a token add/remove into the running HEC forwarders.

    Each forwarder captures its token at construction time, so we must
    restart the affected forwarder to pick up a new value. Restart is
    safe even when the forwarder wasn't running. We restart the entire
    runtime here for simplicity; per-destination hot-swap would be a
    future optimization."""
    raw = await db.get_active_config()
    try:
        parsed = parse_config(raw)
        hec_runtime.configure(parsed.hec_destinations)
        await hec_runtime.restart()
    except Exception:
        logger.exception("hec_runtime_token_apply_failed")


async def _ensure_destination_exists(dest_id: str) -> None:
    rec = await db.get_hec_destination(dest_id)
    if rec is None:
        raise HTTPException(404, f"destination {dest_id!r} not found")


@router.get("/destinations/{dest_id}/key")
async def get_destination_key_status(dest_id: str) -> dict[str, Any]:
    _require_valid_dest_id(dest_id)
    await _ensure_destination_exists(dest_id)
    info = hec_key_store.info(dest_id)
    return {
        "id": dest_id,
        "present": info.present,
        "source": info.source,
        "env_var": hec_key_store.env_var_for(dest_id),
    }


@router.put("/destinations/{dest_id}/key")
async def set_destination_key(dest_id: str, body: HECKeyUpdate) -> dict[str, Any]:
    _require_valid_dest_id(dest_id)
    await _ensure_destination_exists(dest_id)
    await _rate_limit_key_writes()
    try:
        hec_key_store.set(body.token, dest_id)
    except InvalidKeyFormat as exc:
        raise HTTPException(400, str(exc))
    except InvalidDestinationId as exc:
        raise HTTPException(400, str(exc))
    except KeyStoreUnavailable as exc:
        logger.warning(
            "hec_key_store_unavailable",
            extra={"error_type": type(exc).__name__, "dest_id": dest_id},
        )
        env_var = hec_key_store.env_var_for(dest_id)
        raise HTTPException(
            503,
            "OS secret store is unavailable on this host. "
            f"Set the {env_var} environment variable instead.",
        )
    except KeyStoreError as exc:
        raise HTTPException(400, str(exc))

    await _apply_token_change()
    info = hec_key_store.info(dest_id)
    logger.info(
        "hec_token_updated_via_ui",
        extra={"source": info.source, "present": info.present, "dest_id": dest_id},
    )
    return {
        "id": dest_id,
        "present": info.present,
        "source": info.source,
        "env_var": hec_key_store.env_var_for(dest_id),
    }


@router.delete("/destinations/{dest_id}/key")
async def clear_destination_key(dest_id: str) -> dict[str, Any]:
    _require_valid_dest_id(dest_id)
    await _ensure_destination_exists(dest_id)
    await _rate_limit_key_writes()
    try:
        removed = hec_key_store.clear(dest_id)
    except InvalidDestinationId as exc:
        raise HTTPException(400, str(exc))
    await _apply_token_change()
    info = hec_key_store.info(dest_id)
    logger.info(
        "hec_token_cleared_via_ui",
        extra={"removed": removed, "source_after": info.source, "dest_id": dest_id},
    )
    return {
        "id": dest_id,
        "removed": removed,
        "present": info.present,
        "source": info.source,
        "env_var": hec_key_store.env_var_for(dest_id),
    }


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def _stats_to_response(snap) -> HECStatsResponse:
    return HECStatsResponse(
        id=snap.id or None,
        name=snap.name or None,
        enabled=snap.enabled,
        running=snap.running,
        token_present=snap.token_present,
        events_sent=snap.events_sent,
        events_failed=snap.events_failed,
        events_dropped=snap.events_dropped,
        batches_sent=snap.batches_sent,
        batches_failed=snap.batches_failed,
        queue_depth=snap.queue_depth,
        queue_capacity=snap.queue_capacity,
        last_success_at=snap.last_success_at,
        last_error_at=snap.last_error_at,
        last_error=snap.last_error,
        last_latency_ms=snap.last_latency_ms,
    )


@router.get("/stats")
async def hec_stats() -> dict[str, Any]:
    """Return per-destination stats.

    The response is a JSON object ``{"destinations": [...]}`` so the
    legacy single-destination ``GET /api/hec/stats`` callers who only
    looked at the first item can keep using the same endpoint. A flat
    legacy view is exposed via ``/api/hec/stats/default`` and the
    legacy ``/api/hec/config`` shim below.
    """
    snaps = hec_runtime.stats()
    return {"destinations": [_stats_to_response(s).model_dump() for s in snaps]}


@router.get("/stats/{dest_id}", response_model=HECStatsResponse)
async def hec_stats_for(dest_id: str) -> HECStatsResponse:
    _require_valid_dest_id(dest_id)
    snap = hec_runtime.stats_for(dest_id)
    if snap is None:
        raise HTTPException(404, f"destination {dest_id!r} not found")
    return _stats_to_response(snap)


# ---------------------------------------------------------------------------
# Legacy single-destination shims
#
# These keep ``GET/PUT /api/hec/config``, ``POST /api/hec/test``, ``GET/PUT
# /api/hec/key``, ``DELETE /api/hec/key`` working. They all target the
# ``default`` destination, which the migration guarantees exists.
# ---------------------------------------------------------------------------


async def _default_destination_record() -> dict[str, Any]:
    rec = await db.get_hec_destination(DEFAULT_HEC_DEST_ID)
    if rec is None:
        # Fabricate an empty record so legacy callers get a stable
        # shape even if the migration somehow did not run.
        rec = {"id": DEFAULT_HEC_DEST_ID, "name": "Primary"}
    return rec


@router.get("/config")
async def get_hec_config_legacy() -> dict[str, Any]:
    rec = await _default_destination_record()
    return _public_destination(rec)


@router.put("/config")
async def update_hec_config_legacy(update: HECConfigUpdate) -> dict[str, Any]:
    patch = update.model_dump(exclude_none=True)
    if not patch:
        raise HTTPException(400, "No fields to update")
    rec = await db.update_hec_destination(DEFAULT_HEC_DEST_ID, patch)
    if rec is None:
        # Create the default destination on the fly so legacy callers
        # never hit a 404 against the well-known endpoint.
        record = {"id": DEFAULT_HEC_DEST_ID, "name": "Primary", **patch}
        rec = await db.add_hec_destination(record)
    await _reload_runtime()
    return _public_destination(rec)


@router.post("/test", response_model=HECTestResult)
async def test_hec_legacy() -> HECTestResult:
    return await test_destination(DEFAULT_HEC_DEST_ID)


@router.get("/key")
async def get_hec_key_status_legacy() -> dict[str, Any]:
    info = hec_key_store.info(DEFAULT_HEC_DEST_ID)
    return {
        "present": info.present,
        "source": info.source,
        "env_var": HEC_TOKEN_ENV,
    }


@router.put("/key")
async def set_hec_key_legacy(body: HECKeyUpdate) -> dict[str, Any]:
    res = await set_destination_key(DEFAULT_HEC_DEST_ID, body)
    # Drop the ``id`` field so the response shape exactly matches the
    # pre-multi-HEC API.
    return {k: v for k, v in res.items() if k != "id"}


@router.delete("/key")
async def clear_hec_key_legacy() -> dict[str, Any]:
    res = await clear_destination_key(DEFAULT_HEC_DEST_ID)
    return {k: v for k, v in res.items() if k != "id"}
