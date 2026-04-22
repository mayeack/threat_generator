from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from jsonschema import ValidationError

from .cache import VariationCache
from .client import AnthropicClient, LLMConfig
from .exceptions import LLMDisabled, LLMUnavailable, LLMValidationError
from .prompts import build_variation_prompt
from .schemas import validate_batch, validate_scenario

logger = logging.getLogger(__name__)


class VariationWorker:
    """Background task that keeps per-sourcetype pools topped up via Claude.

    Runs a simple control loop that iterates over sourcetypes, requests a
    batch if below low-water, and sleeps between ticks. Never raises into
    the event loop: all errors mark the cache as degraded and get logged.
    """

    def __init__(self, client: AnthropicClient, cache: VariationCache, cfg: LLMConfig) -> None:
        self.client = client
        self.cache = cache
        self.cfg = cfg
        self._task: Optional[asyncio.Task[None]] = None
        self._stop = asyncio.Event()
        self._refresh_now = asyncio.Event()
        self._running: bool = False

    @property
    def running(self) -> bool:
        return self._running

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        if not self.cfg.enabled:
            logger.info("variation_worker_disabled_by_config")
            self.cache.enabled = False
            return
        if not self.client.key_present:
            logger.info("variation_worker_disabled_no_key")
            self.cache.enabled = False
            self.cache.key_present = False
            return
        self.cache.enabled = True
        self.cache.key_present = True
        self._stop.clear()
        self._refresh_now.clear()
        self._task = asyncio.create_task(self._run(), name="variation-worker")
        self._running = True

    async def stop(self) -> None:
        self._stop.set()
        self._refresh_now.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
        self._task = None
        self._running = False

    def request_refresh(self) -> None:
        self._refresh_now.set()

    async def _run(self) -> None:
        await self._initial_fill()
        interval = max(30.0, self.cfg.refresh_interval_minutes * 60.0 / max(1, len(self.cache.sourcetypes())))
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._refresh_now.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
            self._refresh_now.clear()
            if self._stop.is_set():
                break
            await self._top_up_all()

    async def _initial_fill(self) -> None:
        for st in self.cache.sourcetypes():
            if self._stop.is_set():
                return
            await self._refill_one(st, aggressive=True)

    async def _top_up_all(self) -> None:
        for st in self.cache.sourcetypes():
            if self._stop.is_set():
                return
            size = await self.cache.size(st)
            if size < self.cfg.low_water:
                await self._refill_one(st, aggressive=False)

    async def _refill_one(self, sourcetype: str, *, aggressive: bool) -> None:
        current = await self.cache.size(sourcetype)
        target = self.cache.capacity if aggressive else min(self.cache.capacity, current + self.cfg.batch_size * 2)
        if current >= target:
            return
        batch_size = min(self.cfg.batch_size, target - current)
        if batch_size <= 0:
            return
        system, user = build_variation_prompt(sourcetype, batch_size)
        start = time.monotonic()
        try:
            response = await self.client.generate_json(
                system=system,
                user=user,
                model=self.cfg.model,
                max_tokens=self.cfg.max_tokens_variations,
            )
        except LLMDisabled as exc:
            self.cache.set_error(f"llm disabled: {exc}")
            self.cache.enabled = False
            logger.info("variation_worker_stopping_disabled", extra={"reason": str(exc)})
            self._stop.set()
            return
        except LLMUnavailable as exc:
            self.cache.set_error(f"llm unavailable: {exc}")
            logger.warning(
                "variation_refill_failed",
                extra={"sourcetype": sourcetype, "error": str(exc)},
            )
            return
        except LLMValidationError as exc:
            self.cache.set_error(f"validation: {exc}")
            logger.warning(
                "variation_refill_invalid_json",
                extra={"sourcetype": sourcetype, "error": str(exc)},
            )
            return

        try:
            validate_batch(response)
        except ValidationError as exc:
            self.cache.set_error(f"batch schema: {exc.message}")
            logger.warning(
                "variation_batch_schema_fail",
                extra={"sourcetype": sourcetype, "path": list(exc.absolute_path)},
            )
            return

        scenarios = response.get("scenarios", [])
        accepted: list[dict] = []
        for sc in scenarios:
            if not isinstance(sc, dict):
                continue
            try:
                validate_scenario(sourcetype, sc)
            except ValidationError as exc:
                logger.debug(
                    "variation_scenario_rejected",
                    extra={"sourcetype": sourcetype, "path": list(exc.absolute_path), "msg": exc.message},
                )
                continue
            accepted.append(sc)

        if accepted:
            added = await self.cache.extend(sourcetype, accepted)
            self.cache.set_error(None)
            logger.info(
                "variation_refill_ok",
                extra={
                    "sourcetype": sourcetype,
                    "requested": batch_size,
                    "returned": len(scenarios),
                    "accepted": added,
                    "elapsed_ms": int((time.monotonic() - start) * 1000),
                },
            )
        else:
            self.cache.set_error(f"no valid scenarios returned for {sourcetype}")
            logger.warning(
                "variation_refill_empty",
                extra={"sourcetype": sourcetype, "returned": len(scenarios)},
            )
