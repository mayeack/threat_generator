from __future__ import annotations


class LLMError(Exception):
    """Base class for LLM integration errors."""


class LLMDisabled(LLMError):
    """Raised when the LLM feature is intentionally disabled (no key, config off)."""


class LLMUnavailable(LLMError):
    """Raised when the Anthropic API is temporarily unreachable or returning errors."""


class LLMValidationError(LLMError):
    """Raised when a model response fails JSON Schema validation after retries."""
