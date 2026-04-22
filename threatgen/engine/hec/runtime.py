from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from threatgen.engine.config import HECConfig

from .client import HECSendResult
from .forwarder import HECForwarder, HECStats
from .key_store import ENV_KEY_NAME as HEC_TOKEN_ENV, hec_key_store

logger = logging.getLogger(__name__)


def _read_token() -> str:
    """Read the HEC token from the env var first, then OS keychain.

    Codeguard: never store the token in source, DB, or logs. The
    resolution order is enforced inside ``hec_key_store`` so the env
    var always takes precedence over keychain-stored values.
    """
    token, _src = hec_key_store.get()
    return (token or "").strip()


def _read_token_source() -> str:
    """Return the current token source: 'env', 'keychain', or 'none'."""
    _val, src = hec_key_store.get()
    return src


class HECRuntime:
    """Module-level singleton that owns the HECForwarder lifecycle."""

    def __init__(self) -> None:
        self._cfg: Optional[HECConfig] = None
        self._forwarder: Optional[HECForwarder] = None
        self._lock = asyncio.Lock()

    @property
    def cfg(self) -> Optional[HECConfig]:
        return self._cfg

    @property
    def forwarder(self) -> Optional[HECForwarder]:
        return self._forwarder

    def token_env_set(self) -> bool:
        """Legacy name kept for older callers. Returns True when any
        token is available (env var OR keychain)."""
        return bool(_read_token())

    def token_source(self) -> str:
        """'env' | 'keychain' | 'none'."""
        return _read_token_source()

    def configure(self, cfg: HECConfig) -> None:
        """Record the desired configuration. Lifecycle (start/stop/restart)
        is handled by explicit calls so we can await cleanly."""
        self._cfg = cfg

    async def start(self) -> None:
        async with self._lock:
            if self._cfg is None:
                return
            if self._forwarder is not None:
                return
            token = _read_token()
            self._forwarder = HECForwarder(self._cfg, token)
            await self._forwarder.start()

    async def stop(self) -> None:
        async with self._lock:
            if self._forwarder is not None:
                try:
                    await self._forwarder.stop()
                finally:
                    self._forwarder = None

    async def restart(self, cfg: Optional[HECConfig] = None) -> None:
        if cfg is not None:
            self._cfg = cfg
        await self.stop()
        await self.start()

    def submit(self, sourcetype: str, raw_line: str, ts: datetime, is_threat: bool = False) -> None:
        fwd = self._forwarder
        if fwd is None:
            return
        try:
            fwd.submit(sourcetype, raw_line, ts, is_threat)
        except Exception:
            logger.debug("hec_submit_failed", exc_info=True)

    def stats(self) -> HECStats:
        fwd = self._forwarder
        if fwd is None:
            base = HECStats(
                enabled=bool(self._cfg and self._cfg.enabled),
                running=False,
                token_present=self.token_env_set(),
                queue_capacity=(self._cfg.queue_max if self._cfg else 0),
            )
            return base
        snap = fwd.snapshot_stats()
        snap.token_present = self.token_env_set()
        return snap

    async def test_send(self) -> HECSendResult:
        """Send a one-off test event using an ad-hoc client based on the
        current configuration (independent of the running forwarder)."""
        from .client import HECClient

        if self._cfg is None:
            return HECSendResult(ok=False, status_code=None, latency_ms=0.0, error="not configured")
        token = _read_token()
        if not token:
            return HECSendResult(
                ok=False,
                status_code=None,
                latency_ms=0.0,
                error=f"{HEC_TOKEN_ENV} not set",
            )
        client = HECClient(self._cfg, token)
        try:
            ts = datetime.utcnow()
            event = {
                "time": round(ts.timestamp(), 3),
                "host": self._cfg.default_host or "threatgen",
                "source": self._cfg.default_source or "threatgen",
                "sourcetype": "threatgen:test",
                "index": self._cfg.default_index or "main",
                "event": f"threatgen HEC connectivity test at {ts.isoformat()}Z",
            }
            return await client.send_batch([event])
        finally:
            await client.close()


hec_runtime = HECRuntime()
