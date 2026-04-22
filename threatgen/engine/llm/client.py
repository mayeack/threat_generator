from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .exceptions import LLMDisabled, LLMUnavailable, LLMValidationError
from .key_store import ENV_KEY_NAME as _ENV_KEY_NAME, key_store

logger = logging.getLogger(__name__)

_MAX_RESPONSE_BYTES = 256 * 1024


@dataclass
class LLMConfig:
    """Runtime configuration for the LLM integration.

    The API key is intentionally NOT part of this dataclass: it is read
    directly from the ANTHROPIC_API_KEY environment variable and never
    persisted to the config store or returned from API endpoints.
    """

    enabled: bool = True
    model: str = "claude-haiku-4-5"
    campaign_model: str = "claude-sonnet-4-5"
    variation_pool_size: int = 50
    low_water: int = 10
    batch_size: int = 10
    refresh_interval_minutes: int = 60
    request_timeout_s: float = 30.0
    max_concurrent_requests: int = 2
    max_retries: int = 2
    max_tokens_variations: int = 4096
    max_tokens_campaign: int = 4096


@dataclass
class _RateState:
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.monotonic)


class AnthropicClient:
    """Thin async wrapper over the Anthropic SDK with timeouts and retries.

    The client is constructed lazily: the SDK is only imported when a key is
    present, so the application can start with no dependency on network calls.
    """

    def __init__(self, cfg: LLMConfig) -> None:
        self.cfg = cfg
        self._sem = asyncio.Semaphore(max(1, cfg.max_concurrent_requests))
        self._rate = _RateState(tokens=cfg.max_concurrent_requests * 4)
        self._client: Optional[Any] = None
        # The active key material is resolved through KeyStore on every
        # request so we pick up env-var changes and keychain writes
        # without a full runtime restart. We cache only the SDK client
        # instance + the key it was built with so rotations can be
        # detected cheaply.
        self._built_with_key: Optional[str] = None

    @property
    def key_present(self) -> bool:
        key, _ = key_store.get()
        return bool(key)

    @property
    def key_source(self) -> str:
        _, src = key_store.get()
        return src

    def refresh_key(self) -> None:
        """Drop any cached SDK client so the next request picks up the
        current key (or noticed absence). Safe to call at any time."""
        self._client = None
        self._built_with_key = None

    def _ensure_client(self) -> Any:
        key, _src = key_store.get()
        if not key:
            # Force a rebuild on next call once a key is configured.
            self._client = None
            self._built_with_key = None
            raise LLMDisabled(f"{_ENV_KEY_NAME} is not set")

        if self._client is not None and self._built_with_key == key:
            return self._client

        try:
            import anthropic
        except ImportError as exc:
            raise LLMDisabled("anthropic SDK not installed") from exc

        self._client = anthropic.AsyncAnthropic(
            api_key=key,
            timeout=self.cfg.request_timeout_s,
            max_retries=0,
        )
        self._built_with_key = key
        return self._client

    async def _throttle(self) -> None:
        now = time.monotonic()
        elapsed = now - self._rate.last_refill
        self._rate.tokens = min(
            self._rate.tokens + elapsed * self.cfg.max_concurrent_requests,
            self.cfg.max_concurrent_requests * 4,
        )
        self._rate.last_refill = now
        if self._rate.tokens < 1.0:
            sleep_for = (1.0 - self._rate.tokens) / max(self.cfg.max_concurrent_requests, 1)
            await asyncio.sleep(sleep_for)
            self._rate.tokens = 1.0
        self._rate.tokens -= 1.0

    async def generate_json(
        self,
        *,
        system: str,
        user: str,
        model: Optional[str] = None,
        max_tokens: int = 2048,
    ) -> Any:
        """Ask the model for a JSON response and return the parsed object.

        Raises LLMDisabled if the API key is absent.
        Raises LLMUnavailable on transport / rate limit / server errors.
        Raises LLMValidationError if the response is not valid JSON.
        """

        client = self._ensure_client()

        attempt = 0
        backoff = 1.0
        last_exc: Optional[BaseException] = None

        while attempt <= self.cfg.max_retries:
            await self._throttle()
            try:
                async with self._sem:
                    message = await client.messages.create(
                        model=model or self.cfg.model,
                        max_tokens=max_tokens,
                        system=system,
                        messages=[{"role": "user", "content": user}],
                    )
            except Exception as exc:
                last_exc = exc
                transient = self._is_transient(exc)
                logger.warning(
                    "anthropic_call_failed",
                    extra={"attempt": attempt, "transient": transient, "error_type": type(exc).__name__},
                )
                if not transient or attempt >= self.cfg.max_retries:
                    raise LLMUnavailable(str(exc)) from exc
                await asyncio.sleep(backoff + random.uniform(0, 0.25))
                backoff = min(backoff * 2, 10.0)
                attempt += 1
                continue

            text = self._extract_text(message)
            if len(text) > _MAX_RESPONSE_BYTES:
                raise LLMValidationError("response exceeds size limit")
            try:
                return _parse_json_strict(text)
            except LLMValidationError as exc:
                last_exc = exc
                logger.warning(
                    "anthropic_response_not_json",
                    extra={"attempt": attempt, "len": len(text)},
                )
                if attempt >= self.cfg.max_retries:
                    raise
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 10.0)
                attempt += 1
                continue

        if last_exc:
            raise LLMUnavailable(str(last_exc)) from last_exc
        raise LLMUnavailable("exhausted retries without success")

    @staticmethod
    def _extract_text(message: Any) -> str:
        content = getattr(message, "content", None) or []
        parts: list[str] = []
        for block in content:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return "".join(parts)

    @staticmethod
    def _is_transient(exc: BaseException) -> bool:
        name = type(exc).__name__.lower()
        if "rate" in name or "timeout" in name or "connection" in name:
            return True
        status = getattr(exc, "status_code", None)
        if isinstance(status, int) and (status == 429 or 500 <= status < 600):
            return True
        return False


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)
_JSON_OBJECT_RE = re.compile(r"(\{.*\}|\[.*\])", re.DOTALL)


def _parse_json_strict(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        raise LLMValidationError("empty response")
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    fence = _JSON_FENCE_RE.search(stripped)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass

    match = _JSON_OBJECT_RE.search(stripped)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    raise LLMValidationError("response is not valid JSON")
