from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Iterable, Optional, Union

from threatgen.engine.config import DEFAULT_HEC_DEST_ID, HECConfig

from .client import HECSendResult
from .forwarder import HECForwarder, HECStats, _derive_source
from .key_store import ENV_KEY_NAME as HEC_TOKEN_ENV, hec_key_store

logger = logging.getLogger(__name__)


def _read_token(dest_id: str) -> str:
    """Read the HEC token for ``dest_id`` from env vars first, then OS
    keychain.

    Codeguard: never store the token in source, DB, or logs. The
    resolution order is enforced inside ``hec_key_store`` so env vars
    always take precedence over keychain-stored values.
    """
    token, _src = hec_key_store.get(dest_id)
    return (token or "").strip()


def _read_token_source(dest_id: str) -> str:
    """Return the current token source for ``dest_id``: 'env', 'keychain', or 'none'."""
    _val, src = hec_key_store.get(dest_id)
    return src


class HECRuntime:
    """Module-level singleton that owns one ``HECForwarder`` per HEC
    destination.

    Generated events are submitted with the same ``submit(sourcetype,
    raw_line, ts, is_threat)`` signature as before; the runtime fans
    them out to every enabled, running forwarder. This keeps the
    scheduler hot path unchanged.
    """

    def __init__(self) -> None:
        # Preserve insertion order; ``default`` ends up first when
        # present, which matches the legacy convenience-alias semantics.
        self._destinations: dict[str, HECConfig] = {}
        self._forwarders: dict[str, HECForwarder] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Identity helpers
    # ------------------------------------------------------------------

    @property
    def destinations(self) -> list[HECConfig]:
        """Return the configured destinations in insertion order."""
        return list(self._destinations.values())

    @property
    def forwarders(self) -> dict[str, HECForwarder]:
        """Return the currently-running forwarders keyed by destination id."""
        return dict(self._forwarders)

    @property
    def cfg(self) -> Optional[HECConfig]:
        """Convenience alias to the first (or ``default``) destination
        for legacy callers that still expect a single config."""
        if DEFAULT_HEC_DEST_ID in self._destinations:
            return self._destinations[DEFAULT_HEC_DEST_ID]
        if self._destinations:
            return next(iter(self._destinations.values()))
        return None

    @property
    def forwarder(self) -> Optional[HECForwarder]:
        """Convenience alias to the forwarder for the first/``default``
        destination (legacy callers)."""
        if DEFAULT_HEC_DEST_ID in self._forwarders:
            return self._forwarders[DEFAULT_HEC_DEST_ID]
        if self._forwarders:
            return next(iter(self._forwarders.values()))
        return None

    def token_env_set(self, dest_id: str = DEFAULT_HEC_DEST_ID) -> bool:
        """Legacy name kept for older callers. Returns True when any
        token is available (env var OR keychain) for ``dest_id``."""
        return bool(_read_token(dest_id))

    def token_source(self, dest_id: str = DEFAULT_HEC_DEST_ID) -> str:
        """'env' | 'keychain' | 'none' for ``dest_id``."""
        return _read_token_source(dest_id)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def configure(self, cfg: Union[HECConfig, Iterable[HECConfig], None]) -> None:
        """Record the desired configuration. Accepts either a single
        ``HECConfig`` (legacy single-destination callers) or an iterable
        of destinations. Lifecycle (start/stop/restart) is handled by
        explicit calls so we can await cleanly.
        """
        if cfg is None:
            self._destinations = {}
            return
        if isinstance(cfg, HECConfig):
            destinations = [cfg]
        else:
            destinations = list(cfg)

        ordered: dict[str, HECConfig] = {}
        for dest in destinations:
            if not isinstance(dest, HECConfig):
                continue
            dest_id = dest.id or DEFAULT_HEC_DEST_ID
            ordered[dest_id] = dest
        self._destinations = ordered

    async def start(self) -> None:
        """Start one forwarder per *enabled* destination. Idempotent."""
        async with self._lock:
            for dest_id, dest_cfg in self._destinations.items():
                if not dest_cfg.enabled:
                    continue
                if dest_id in self._forwarders:
                    continue
                token = _read_token(dest_id)
                fwd = HECForwarder(dest_cfg, token)
                await fwd.start()
                self._forwarders[dest_id] = fwd

    async def stop(self) -> None:
        """Stop every running forwarder."""
        async with self._lock:
            forwarders = list(self._forwarders.items())
            self._forwarders.clear()
        for dest_id, fwd in forwarders:
            try:
                await fwd.stop()
            except Exception:
                logger.exception("hec_forwarder_stop_failed", extra={"dest_id": dest_id})

    async def restart(
        self,
        cfg: Union[HECConfig, Iterable[HECConfig], None] = None,
    ) -> None:
        if cfg is not None:
            self.configure(cfg)
        await self.stop()
        await self.start()

    # ------------------------------------------------------------------
    # Hot path: fan-out submit
    # ------------------------------------------------------------------

    def submit(
        self,
        sourcetype: str,
        raw_line: str,
        ts: datetime,
        is_threat: bool = False,
    ) -> None:
        """Enqueue ``raw_line`` into every running forwarder.

        Signature is unchanged from the single-destination implementation
        so the scheduler's hot path needs no edits. Each forwarder owns
        its own bounded queue and drop-oldest overflow policy, so a slow
        Splunk on destination A cannot back up destination B.
        """
        if not self._forwarders:
            return
        for dest_id, fwd in self._forwarders.items():
            try:
                fwd.submit(sourcetype, raw_line, ts, is_threat)
            except Exception:
                logger.debug(
                    "hec_submit_failed", extra={"dest_id": dest_id}, exc_info=True
                )

    # ------------------------------------------------------------------
    # Stats and test-send
    # ------------------------------------------------------------------

    def stats(self) -> list[HECStats]:
        """Return one ``HECStats`` per configured destination."""
        out: list[HECStats] = []
        for dest_id, dest_cfg in self._destinations.items():
            fwd = self._forwarders.get(dest_id)
            if fwd is None:
                snap = HECStats(
                    id=dest_id,
                    name=dest_cfg.name,
                    enabled=bool(dest_cfg.enabled),
                    running=False,
                    token_present=self.token_env_set(dest_id),
                    queue_capacity=max(1, int(dest_cfg.queue_max)),
                )
            else:
                snap = fwd.snapshot_stats()
                # Ensure identity always reflects the latest config.
                snap.id = dest_id
                snap.name = dest_cfg.name
                snap.token_present = self.token_env_set(dest_id)
            out.append(snap)
        return out

    def stats_for(self, dest_id: str) -> Optional[HECStats]:
        for snap in self.stats():
            if snap.id == dest_id:
                return snap
        return None

    async def test_send(self, dest_id: str = DEFAULT_HEC_DEST_ID) -> HECSendResult:
        """Send a one-off test event using an ad-hoc client for
        ``dest_id`` (independent of any running forwarder)."""
        from .client import HECClient

        dest_cfg = self._destinations.get(dest_id)
        if dest_cfg is None:
            return HECSendResult(
                ok=False,
                status_code=None,
                latency_ms=0.0,
                error=f"destination {dest_id!r} not configured",
            )
        token = _read_token(dest_id)
        if not token:
            env_name = hec_key_store.env_var_for(dest_id)
            return HECSendResult(
                ok=False,
                status_code=None,
                latency_ms=0.0,
                error=f"{env_name} not set and no keychain token stored",
            )
        client = HECClient(dest_cfg, token)
        try:
            ts = datetime.utcnow()
            event = {
                "time": round(ts.timestamp(), 3),
                "host": dest_cfg.default_host or "threatgen",
                "source": _derive_source(dest_cfg.default_source, "test"),
                "sourcetype": "threatgen:test",
                "index": dest_cfg.default_index or "main",
                "event": f"threatgen HEC connectivity test at {ts.isoformat()}Z",
            }
            return await client.send_batch([event])
        finally:
            await client.close()


hec_runtime = HECRuntime()
