from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from threatgen.engine.config import HECConfig

from .client import HECClient, HECSendResult

logger = logging.getLogger(__name__)

# Key entity fields promoted to HEC indexed fields so Exposure Analytics
# streaming entity discovery (which validates key presence via tstats against
# indexed fields, not search-time KV) sees them on every event.
_ENTITY_INDEXED_KEYS = ("nt_host", "ip", "user_id", "mac")


# Hard-coded canonical overlays applied after the configured sourcetype_map /
# source_map. These guarantee ThreatGen HEC events match Splunk ES Exposure
# Analytics' out-of-the-box discovery source filters regardless of what the
# persisted DB config contains. A stale DB row or an operator tweak cannot
# regress us below the minimum shape EA expects.
#
# Keyed by the *input* sourcetype the generator passes to submit() (i.e. the
# pre-canonical name), values are the canonical Splunk sourcetype / source
# that the EA discovery source template expects.
#
# Windows Security (EA "Windows Security Auth (Kerberos)" predefined source):
# ES 8's ``ea_network_asset_process`` data model object for this template
# filters on **indexed** ``sourcetype=WinEventLog:Security`` (not the plain
# ``WinEventLog`` name). Using only ``WinEventLog`` with
# ``source=WinEventLog:Security`` matches ad-hoc searches but the predefined
# Validate subsearch returns **zero** events, so required ``nt_host`` never
# passes. The Security channel must therefore use the fully-qualified
# sourcetype.
#
# Sysmon: OOB filters use ``sourcetype=XmlWinEventLog`` with
# ``source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational``; keep the plain
# sourcetype so we do not duplicate the long ``XmlWinEventLog:...`` form.
_CANONICAL_SOURCETYPE: dict[str, str] = {
    "wineventlog": "WinEventLog:Security",
    "sysmon": "XmlWinEventLog",
    "linux_secure": "linux_secure",
    "stream:dns": "stream:dns",
    "stream:http": "stream:http",
    "cisco:asa": "cisco:asa",
}

# EA discovery source filters for Linux sshd and Windows Sysmon / Security
# include a required ``source=`` term. We override the HEC ``source`` for just
# those three families so their OOB templates validate. The other families
# (stream:dns, stream:http, cisco:asa) have no ``source=`` requirement, so
# they keep the legacy ``threatgen:<family>`` path (which lets file-monitor
# and debug tooling continue to distinguish simulated traffic).
_CANONICAL_SOURCE: dict[str, str] = {
    "wineventlog": "WinEventLog:Security",
    "sysmon": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "linux_secure": "/var/log/secure",
}


def _derive_source(default_source: str, sourcetype: str) -> str:
    """Return the fallback HEC ``source`` field for a given sourcetype.

    Used only when neither the canonical overlay nor a config-supplied
    ``source_map`` entry applies. TA-threat_gen keys its parsing on
    ``[source::threatgen:<family>]`` stanzas (see
    splunk/TA-threat_gen/default/props.conf). We derive the per-family suffix
    by normalizing the sourcetype (replacing ':' and '/' with '_' and
    lowercasing) and appending it to the configured prefix.

    Examples (with default_source='threatgen'):
        'wineventlog'  -> 'threatgen:wineventlog'
        'sysmon'       -> 'threatgen:sysmon'
        'linux_secure' -> 'threatgen:linux_secure'
        'stream:dns'   -> 'threatgen:stream_dns'
        'stream:http'  -> 'threatgen:stream_http'
        'cisco:asa'    -> 'threatgen:cisco_asa'
    """
    prefix = (default_source or "threatgen").strip() or "threatgen"
    slug = (sourcetype or "").strip().replace(":", "_").replace("/", "_").lower()
    if not slug:
        return prefix
    return f"{prefix}:{slug}"


def _resolve_sourcetype(cfg_map: Optional[dict[str, str]], sourcetype: str) -> str:
    """Return the canonical sourcetype. Canonical overlay wins over config map
    wins over the raw input sourcetype."""
    canonical = _CANONICAL_SOURCETYPE.get(sourcetype)
    if canonical:
        return canonical
    if cfg_map:
        mapped = cfg_map.get(sourcetype)
        if mapped:
            return mapped
    return sourcetype


def _resolve_source(
    cfg_map: Optional[dict[str, str]],
    default_source: str,
    sourcetype: str,
) -> str:
    """Return the canonical HEC source. Canonical overlay wins over config map
    wins over the ``threatgen:<family>`` fallback."""
    canonical = _CANONICAL_SOURCE.get(sourcetype)
    if canonical:
        return canonical
    if cfg_map:
        mapped = cfg_map.get(sourcetype)
        if mapped:
            return mapped
    return _derive_source(default_source, sourcetype)


@dataclass
class HECStats:
    enabled: bool = False
    running: bool = False
    token_present: bool = False
    events_sent: int = 0
    events_failed: int = 0
    events_dropped: int = 0
    batches_sent: int = 0
    batches_failed: int = 0
    queue_depth: int = 0
    queue_capacity: int = 0
    last_success_at: Optional[str] = None
    last_error_at: Optional[str] = None
    last_error: Optional[str] = None
    last_latency_ms: Optional[float] = None


class HECForwarder:
    """Async HEC forwarder with a bounded queue, batching, retry, and
    drop-oldest overflow policy to prevent memory exhaustion."""

    def __init__(self, cfg: HECConfig, token: Optional[str]) -> None:
        self._cfg = cfg
        self._token = token or ""
        self._client = HECClient(cfg, token)
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=max(1, cfg.queue_max))
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._stats = HECStats(
            enabled=cfg.enabled,
            token_present=bool(token),
            queue_capacity=max(1, cfg.queue_max),
        )

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if not self._cfg.enabled:
            self._stats.enabled = False
            self._stats.running = False
            return
        if self.running:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._consume_loop())
        self._stats.enabled = True
        self._stats.running = True
        logger.info("hec_forwarder_started")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            except Exception:
                logger.debug("hec_forwarder_stop_error", exc_info=True)
            self._task = None
        await self._client.close()
        self._stats.running = False
        logger.info("hec_forwarder_stopped")

    def submit(
        self,
        sourcetype: str,
        raw_line: str,
        ts: datetime,
        is_threat: bool = False,
    ) -> None:
        """Non-blocking enqueue. On overflow, drops the oldest event."""
        if not self._cfg.enabled or not self.running:
            return
        if not raw_line:
            return

        event = self._build_event(sourcetype, raw_line, ts, is_threat)
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                _ = self._queue.get_nowait()
                self._queue.task_done()
                self._stats.events_dropped += 1
            except asyncio.QueueEmpty:
                pass
            try:
                self._queue.put_nowait(event)
            except asyncio.QueueFull:
                self._stats.events_dropped += 1

    def _build_event(
        self,
        sourcetype: str,
        raw_line: str,
        ts: datetime,
        is_threat: bool,
    ) -> dict[str, Any]:
        resolved_sourcetype = _resolve_sourcetype(
            getattr(self._cfg, "sourcetype_map", None), sourcetype
        )
        resolved_source = _resolve_source(
            getattr(self._cfg, "source_map", None),
            self._cfg.default_source,
            sourcetype,
        )
        epoch = ts.timestamp() if ts else time.time()
        event: dict[str, Any] = {
            "time": round(epoch, 3),
            "host": self._cfg.default_host or "threatgen",
            "source": resolved_source,
            "sourcetype": resolved_sourcetype,
            "index": self._cfg.default_index or "main",
            "event": raw_line,
        }

        indexed_fields: dict[str, str] = {}
        try:
            payload = json.loads(raw_line)
        except (ValueError, TypeError):
            payload = None
        if isinstance(payload, dict):
            for key in _ENTITY_INDEXED_KEYS:
                value = payload.get(key)
                if value is None:
                    continue
                text = str(value).strip()
                if text:
                    indexed_fields[key] = text

        if is_threat:
            indexed_fields["threatgen_is_threat"] = "1"

        if indexed_fields:
            event["fields"] = indexed_fields
        return event

    async def _consume_loop(self) -> None:
        flush_interval = max(0.1, float(self._cfg.flush_interval_s))
        batch_size = max(1, int(self._cfg.batch_size))

        try:
            while not self._stopping.is_set():
                batch: list[dict[str, Any]] = []
                deadline = time.monotonic() + flush_interval

                try:
                    first = await asyncio.wait_for(self._queue.get(), timeout=flush_interval)
                    batch.append(first)
                    self._queue.task_done()
                except asyncio.TimeoutError:
                    continue

                while len(batch) < batch_size:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        item = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                    except asyncio.TimeoutError:
                        break
                    batch.append(item)
                    self._queue.task_done()

                await self._send_with_retry(batch)
                self._stats.queue_depth = self._queue.qsize()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("hec_forwarder_loop_crashed")

    async def _send_with_retry(self, batch: list[dict[str, Any]]) -> None:
        retries = max(0, int(self._cfg.max_retries))
        attempt = 0
        last_result: Optional[HECSendResult] = None

        while attempt <= retries and not self._stopping.is_set():
            result = await self._client.send_batch(batch)
            last_result = result
            if result.ok:
                self._stats.events_sent += len(batch)
                self._stats.batches_sent += 1
                self._stats.last_success_at = datetime.utcnow().isoformat() + "Z"
                self._stats.last_latency_ms = round(result.latency_ms, 1)
                return
            # Retry only on transport errors or 5xx / 429.
            retryable = (
                result.status_code is None
                or result.status_code >= 500
                or result.status_code == 429
            )
            if not retryable or attempt >= retries:
                break
            backoff = min(30.0, (2 ** attempt) * 0.5) + random.uniform(0, 0.25)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=backoff)
                break
            except asyncio.TimeoutError:
                pass
            attempt += 1

        self._stats.events_failed += len(batch)
        self._stats.batches_failed += 1
        self._stats.last_error_at = datetime.utcnow().isoformat() + "Z"
        self._stats.last_error = last_result.error if last_result else "unknown error"

    def snapshot_stats(self) -> HECStats:
        self._stats.queue_depth = self._queue.qsize()
        self._stats.queue_capacity = self._queue.maxsize
        self._stats.running = self.running
        self._stats.enabled = self._cfg.enabled
        self._stats.token_present = bool(self._token)
        return self._stats

    async def test_send(self, sourcetype: str = "threatgen:test") -> HECSendResult:
        """Send a single synthetic event bypassing the queue. Useful for
        the UI Test button."""
        ts = datetime.utcnow()
        event = self._build_event(
            sourcetype,
            f"threatgen HEC connectivity test at {ts.isoformat()}Z",
            ts,
            is_threat=False,
        )
        return await self._client.send_batch([event])
