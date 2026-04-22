from __future__ import annotations

"""Shared runtime holders for the LLM subsystem.

Kept as module-level singletons mirroring the existing pattern used by
engine/scheduler.py. This lets API routes, the scheduler, and the engine
share a single cache/worker/client trio without plumbing them through
every call site.
"""

from typing import Optional

from .cache import VariationCache
from .client import AnthropicClient, LLMConfig
from .planner import LLMCampaignPlanner
from .worker import VariationWorker

SOURCETYPES: list[str] = ["wineventlog", "sysmon", "linux_secure", "dns", "http", "firewall"]


class LLMRuntime:
    def __init__(self) -> None:
        self.cfg: LLMConfig = LLMConfig()
        self.client: Optional[AnthropicClient] = None
        self.cache: VariationCache = VariationCache(SOURCETYPES, capacity=self.cfg.variation_pool_size)
        self.worker: Optional[VariationWorker] = None
        self.planner: Optional[LLMCampaignPlanner] = None
        # Runtime-only pause flag. Not persisted; a process restart clears it.
        # When True, the variation worker will not be (re)started by config
        # or key-change events until the user explicitly resumes.
        self.paused: bool = False

    def configure(self, cfg: LLMConfig) -> None:
        self.cfg = cfg
        self.cache.set_capacity(cfg.variation_pool_size)
        if self.client is None:
            self.client = AnthropicClient(cfg)
        else:
            self.client.cfg = cfg
            # Drop any cached SDK client so the next call picks up a
            # rotated or newly-provided key.
            self.client.refresh_key()
        self.cache.key_present = self.client.key_present
        self.cache.enabled = cfg.enabled and self.client.key_present
        self.planner = LLMCampaignPlanner(self.client, cfg)
        if self.worker is None:
            self.worker = VariationWorker(self.client, self.cache, cfg)
        else:
            self.worker.cfg = cfg

    def refresh_key_state(self) -> None:
        """Called after a key is added/cleared through the API so
        cache.enabled / key_present reflect reality. Does not restart
        the worker; callers decide whether to start/stop it."""
        if self.client is None:
            return
        self.client.refresh_key()
        self.cache.key_present = self.client.key_present
        self.cache.enabled = self.cfg.enabled and self.client.key_present


runtime = LLMRuntime()
