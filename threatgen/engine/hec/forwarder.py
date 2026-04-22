from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from threatgen.engine.config import HECConfig

from .client import HECClient, HECSendResult

logger = logging.getLogger(__name__)


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
        mapped = self._cfg.sourcetype_map.get(sourcetype) if self._cfg.sourcetype_map else None
        epoch = ts.timestamp() if ts else time.time()
        event: dict[str, Any] = {
            "time": round(epoch, 3),
            "host": self._cfg.default_host or "threatgen",
            "source": self._cfg.default_source or "threatgen",
            "sourcetype": mapped or sourcetype,
            "index": self._cfg.default_index or "main",
            "event": raw_line,
        }
        if is_threat:
            event["fields"] = {"threatgen_is_threat": "1"}
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
