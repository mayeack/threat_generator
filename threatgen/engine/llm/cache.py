from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class _PoolStats:
    total_added: int = 0
    total_consumed: int = 0
    last_added_ts: float = 0.0


@dataclass
class CacheSnapshot:
    enabled: bool
    degraded: bool
    key_present: bool
    last_refresh_ts: float
    last_error: Optional[str]
    pool_sizes: dict[str, int] = field(default_factory=dict)
    capacity: int = 0


class VariationCache:
    """Per-sourcetype pool of validated scenario dicts.

    Thread-safe across asyncio tasks via an asyncio.Lock. Kept intentionally
    simple: the scheduler consumes from the front (FIFO), the worker pushes
    fresh batches to the back. When a pool is empty, `pop` returns None and
    the caller is expected to fall back to pattern-based generation.
    """

    def __init__(self, sourcetypes: list[str], capacity: int = 50) -> None:
        self._capacity = max(1, capacity)
        self._pools: dict[str, deque[dict[str, Any]]] = {
            st: deque(maxlen=self._capacity) for st in sourcetypes
        }
        self._stats: dict[str, _PoolStats] = {st: _PoolStats() for st in sourcetypes}
        self._lock = asyncio.Lock()
        self._rng = random.Random()
        self.enabled: bool = False
        self.degraded: bool = False
        self.key_present: bool = False
        self.last_refresh_ts: float = 0.0
        self.last_error: Optional[str] = None

    @property
    def capacity(self) -> int:
        return self._capacity

    def set_capacity(self, capacity: int) -> None:
        self._capacity = max(1, capacity)
        for st, pool in self._pools.items():
            new_pool: deque[dict[str, Any]] = deque(pool, maxlen=self._capacity)
            self._pools[st] = new_pool

    def sourcetypes(self) -> list[str]:
        return list(self._pools.keys())

    async def size(self, sourcetype: str) -> int:
        async with self._lock:
            return len(self._pools.get(sourcetype, ()))

    async def all_sizes(self) -> dict[str, int]:
        async with self._lock:
            return {st: len(pool) for st, pool in self._pools.items()}

    async def extend(self, sourcetype: str, scenarios: list[dict[str, Any]]) -> int:
        """Push validated scenarios to the pool. Returns the count actually added."""
        if sourcetype not in self._pools:
            return 0
        added = 0
        async with self._lock:
            pool = self._pools[sourcetype]
            for sc in scenarios:
                pool.append(sc)
                added += 1
            self._stats[sourcetype].total_added += added
            self._stats[sourcetype].last_added_ts = time.time()
            self.last_refresh_ts = time.time()
        return added

    async def pop(self, sourcetype: str) -> Optional[dict[str, Any]]:
        if sourcetype not in self._pools:
            return None
        async with self._lock:
            pool = self._pools[sourcetype]
            if not pool:
                return None
            scenario = pool.popleft()
            self._stats[sourcetype].total_consumed += 1
            return scenario

    async def peek_samples(self, sourcetype: str, n: int) -> list[dict[str, Any]]:
        async with self._lock:
            pool = list(self._pools.get(sourcetype, ()))
        if not pool:
            return []
        n = min(n, len(pool))
        return self._rng.sample(pool, n)

    def snapshot(self) -> CacheSnapshot:
        pool_sizes = {st: len(pool) for st, pool in self._pools.items()}
        return CacheSnapshot(
            enabled=self.enabled,
            degraded=self.degraded,
            key_present=self.key_present,
            last_refresh_ts=self.last_refresh_ts,
            last_error=self.last_error,
            pool_sizes=pool_sizes,
            capacity=self._capacity,
        )

    def set_error(self, message: Optional[str]) -> None:
        self.last_error = message
        self.degraded = bool(message)


def serialize_snapshot(snapshot: CacheSnapshot) -> dict[str, Any]:
    return {
        "enabled": snapshot.enabled,
        "degraded": snapshot.degraded,
        "key_present": snapshot.key_present,
        "last_refresh_ts": snapshot.last_refresh_ts,
        "last_error": snapshot.last_error,
        "pool_sizes": snapshot.pool_sizes,
        "capacity": snapshot.capacity,
    }


def dump_for_persistence(cache: VariationCache) -> str:
    payload = {st: list(cache._pools[st]) for st in cache.sourcetypes()}  # noqa: SLF001
    return json.dumps(payload, separators=(",", ":"))


def load_from_persistence(cache: VariationCache, blob: str) -> None:
    try:
        payload = json.loads(blob)
    except json.JSONDecodeError:
        logger.warning("variation_cache_persist_unreadable")
        return
    if not isinstance(payload, dict):
        return
    for st, scenarios in payload.items():
        if st not in cache._pools or not isinstance(scenarios, list):  # noqa: SLF001
            continue
        pool = cache._pools[st]  # noqa: SLF001
        for sc in scenarios:
            if isinstance(sc, dict):
                pool.append(sc)
