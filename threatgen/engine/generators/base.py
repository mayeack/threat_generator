from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

from threatgen.engine.llm.cache import VariationCache
from threatgen.engine.topology import Topology

logger = logging.getLogger(__name__)


class BaseGenerator(ABC):
    """Base class for per-sourcetype generators.

    Subclasses implement two paths:
      * `_generate_pattern(ts)` - deterministic, fast, always-available
        pattern-based generation (the original behaviour).
      * `render_from_scenario(scenario, ts)` - render one or more log lines
        from an LLM-produced, schema-validated scenario dict. Topology
        lookups (hostname, IP, user, SID, GUID) are resolved here, at
        emission time, so the same cached scenario never renders twice
        identically.

    `generate(ts)` consults the optional `VariationCache` first and falls
    back to `_generate_pattern` on an empty pool or any rendering error.
    """

    sourcetype: str = ""

    def __init__(self, topology: Topology, cache: Optional[VariationCache] = None) -> None:
        self.topo = topology
        self.rng = topology.rng
        self._cache = cache

    def set_cache(self, cache: Optional[VariationCache]) -> None:
        self._cache = cache

    def generate(self, ts: datetime) -> list[str]:
        if self._cache is not None and self.sourcetype:
            scenario = _sync_pop(self._cache, self.sourcetype)
            if scenario is not None:
                try:
                    return self.render_from_scenario(scenario, ts)
                except Exception:
                    logger.warning(
                        "render_from_scenario_failed",
                        extra={"sourcetype": self.sourcetype},
                        exc_info=True,
                    )
        return self._generate_pattern(ts)

    @abstractmethod
    def _generate_pattern(self, ts: datetime) -> list[str]:
        """Deterministic fallback path. Must always succeed."""

    def render_from_scenario(self, scenario: dict[str, Any], ts: datetime) -> list[str]:
        """Default: ignore the scenario and delegate to the pattern path.

        Generators override this to take advantage of LLM-provided variety.
        """
        return self._generate_pattern(ts)


def _sync_pop(cache: VariationCache, sourcetype: str) -> Optional[dict[str, Any]]:
    """Non-blocking pop that avoids contending on the cache lock.

    The engine's tick loop is async but `generate` is a sync call site;
    we deliberately take a best-effort peek using the internal deque to
    avoid spawning coroutines per event. Writes to the cache happen from
    the background worker under the async lock; reads here are a single
    `popleft` which is safe under CPython's GIL.
    """
    pool = cache._pools.get(sourcetype)  # noqa: SLF001
    if not pool:
        return None
    try:
        return pool.popleft()
    except IndexError:
        return None
