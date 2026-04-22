"""Secure storage for the Anthropic API key.

Resolution order (highest priority first):

    1. ANTHROPIC_API_KEY environment variable
    2. OS secret store (macOS Keychain, Windows Credential Manager,
       Linux Secret Service) via the `keyring` package
    3. None (LLM subsystem stays disabled)

Security posture:
    * The key is NEVER persisted to the SQLite config store, YAML
      files, logs, or any response body.
    * When stored via keyring, it is encrypted at rest by the OS and
      protected by the logged-in user's credentials.
    * `ANTHROPIC_API_KEY` always wins over the keychain so operators
      can override at deploy time without mutating the keychain.
    * If the keyring backend is unavailable (headless Linux without
      Secret Service, locked keychain, etc.), writes fail fast with
      KeyStoreUnavailable rather than silently falling back to an
      insecure location.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

ENV_KEY_NAME = "ANTHROPIC_API_KEY"
KEYRING_SERVICE = "threatgen.anthropic"
KEYRING_USER = "default"

# Anthropic API keys currently look like `sk-ant-...` with base64url-ish
# characters. We deliberately keep this tolerant (length 20-500) so we
# don't hard-code a specific Anthropic format that may evolve. Code
# outside this module must treat the raw key as opaque.
_KEY_RE = re.compile(r"^sk-ant-[A-Za-z0-9_\-]{20,500}$")

Source = str  # "env" | "keychain" | "none"


class KeyStoreError(Exception):
    """Base class for KeyStore failures."""


class KeyStoreUnavailable(KeyStoreError):
    """The OS secret store is not available on this host."""


class InvalidKeyFormat(KeyStoreError):
    """Caller supplied a string that does not look like an API key."""


@dataclass(frozen=True)
class KeyInfo:
    source: Source  # where the active key (if any) came from
    present: bool   # True when a key is available to the client


def _import_keyring():
    """Import `keyring` lazily so test/headless environments that
    don't have a backend can still import this module."""
    try:
        import keyring  # type: ignore
        import keyring.errors  # type: ignore
        return keyring
    except Exception as exc:  # pragma: no cover - defensive
        raise KeyStoreUnavailable(f"keyring unavailable: {exc}") from exc


class KeyStore:
    """Thread-safe accessor for the Anthropic API key."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------
    def get(self) -> tuple[Optional[str], Source]:
        env_val = os.environ.get(ENV_KEY_NAME)
        if env_val and env_val.strip():
            return env_val.strip(), "env"

        try:
            keyring = _import_keyring()
        except KeyStoreUnavailable:
            return None, "none"

        try:
            val = keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
        except Exception as exc:
            logger.warning("keyring_read_failed", extra={"error_type": type(exc).__name__})
            return None, "none"

        if val:
            return val, "keychain"
        return None, "none"

    def info(self) -> KeyInfo:
        val, src = self.get()
        return KeyInfo(source=src, present=bool(val))

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------
    def set(self, api_key: str) -> None:
        if not isinstance(api_key, str):
            raise InvalidKeyFormat("api_key must be a string")
        cleaned = api_key.strip()
        if not _KEY_RE.match(cleaned):
            # Avoid echoing the key; include only length for diagnostics.
            raise InvalidKeyFormat(
                "api_key does not look like an Anthropic key "
                f"(len={len(cleaned)}, expected sk-ant-... 20-500 chars)"
            )

        if os.environ.get(ENV_KEY_NAME, "").strip():
            # Refuse to shadow an env-provided key. Operators set env
            # vars deliberately; silently writing to the keychain would
            # be surprising on restart / in another shell.
            raise KeyStoreError(
                f"{ENV_KEY_NAME} is already set in the environment; "
                "unset it before storing a key via the UI"
            )

        keyring = _import_keyring()  # raises KeyStoreUnavailable
        with self._lock:
            try:
                keyring.set_password(KEYRING_SERVICE, KEYRING_USER, cleaned)
            except Exception as exc:
                # Never log the key value or any substring.
                logger.error("keyring_write_failed", extra={"error_type": type(exc).__name__})
                raise KeyStoreUnavailable(f"failed to write to keychain: {exc}") from exc

        logger.info("anthropic_key_stored", extra={"source": "keychain"})

    def clear(self) -> bool:
        """Remove the keychain entry. Returns True if something was
        removed, False if nothing was stored. Does not touch the
        environment variable."""
        try:
            keyring = _import_keyring()
        except KeyStoreUnavailable:
            return False

        with self._lock:
            try:
                existing = keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
                if not existing:
                    return False
                keyring.delete_password(KEYRING_SERVICE, KEYRING_USER)
            except Exception as exc:
                logger.warning("keyring_delete_failed", extra={"error_type": type(exc).__name__})
                return False

        logger.info("anthropic_key_cleared", extra={"source": "keychain"})
        return True


# Module-level singleton, mirroring the runtime.py pattern.
key_store = KeyStore()
