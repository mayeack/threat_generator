"""Secure storage for the Splunk HEC token.

Resolution order (highest priority first):

    1. SPLUNK_HEC_TOKEN environment variable
    2. OS secret store (macOS Keychain, Windows Credential Manager,
       Linux Secret Service) via the `keyring` package
    3. None (HEC forwarder will start but emit errors)

Security posture (mirrors threatgen.engine.llm.key_store):
    * The token is NEVER persisted to the SQLite config store, YAML
      files, logs, or any API response body.
    * When stored via keyring, it is encrypted at rest by the OS and
      protected by the logged-in user's credentials.
    * `SPLUNK_HEC_TOKEN` always wins over the keychain so operators
      can override at deploy time without mutating the keychain.
    * If the keyring backend is unavailable (headless Linux without
      Secret Service, locked keychain, etc.), writes fail fast with
      KeyStoreUnavailable rather than silently falling back to an
      insecure location.
    * Splunk HEC tokens are UUIDs; we validate strict UUID shape
      before ever accepting a value from the UI.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

ENV_KEY_NAME = "SPLUNK_HEC_TOKEN"
KEYRING_SERVICE = "threatgen.splunk_hec"
KEYRING_USER = "default"

# Splunk HEC tokens are standard UUIDs (8-4-4-4-12 hex). Enforce the
# canonical shape so a paste-error (extra whitespace, trailing newline,
# missing dash, etc.) is caught before we ever store it.
_TOKEN_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

Source = str  # "env" | "keychain" | "none"


class KeyStoreError(Exception):
    """Base class for HEC key-store failures."""


class KeyStoreUnavailable(KeyStoreError):
    """The OS secret store is not available on this host."""


class InvalidKeyFormat(KeyStoreError):
    """Caller supplied a string that does not look like a HEC token."""


@dataclass(frozen=True)
class KeyInfo:
    source: Source  # where the active token (if any) came from
    present: bool   # True when a token is available to the forwarder


def _import_keyring():
    """Import `keyring` lazily so test/headless environments that
    don't have a backend can still import this module."""
    try:
        import keyring  # type: ignore
        import keyring.errors  # type: ignore
        return keyring
    except Exception as exc:  # pragma: no cover - defensive
        raise KeyStoreUnavailable(f"keyring unavailable: {exc}") from exc


class HECKeyStore:
    """Thread-safe accessor for the Splunk HEC token."""

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
            logger.warning(
                "hec_keyring_read_failed",
                extra={"error_type": type(exc).__name__},
            )
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
    def set(self, token: str) -> None:
        if not isinstance(token, str):
            raise InvalidKeyFormat("token must be a string")
        cleaned = token.strip()
        if not _TOKEN_RE.match(cleaned):
            # Avoid echoing the token; include only length for diagnostics.
            raise InvalidKeyFormat(
                "token does not look like a Splunk HEC token "
                f"(len={len(cleaned)}, expected 8-4-4-4-12 UUID)"
            )

        if os.environ.get(ENV_KEY_NAME, "").strip():
            # Refuse to shadow an env-provided token. Operators set env
            # vars deliberately; silently writing to the keychain would
            # be surprising on restart / in another shell.
            raise KeyStoreError(
                f"{ENV_KEY_NAME} is already set in the environment; "
                "unset it before storing a token via the UI"
            )

        keyring = _import_keyring()  # raises KeyStoreUnavailable
        with self._lock:
            try:
                keyring.set_password(KEYRING_SERVICE, KEYRING_USER, cleaned)
            except Exception as exc:
                # Never log the token value or any substring.
                logger.error(
                    "hec_keyring_write_failed",
                    extra={"error_type": type(exc).__name__},
                )
                raise KeyStoreUnavailable(
                    f"failed to write to keychain: {exc}"
                ) from exc

        logger.info("hec_token_stored", extra={"source": "keychain"})

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
                logger.warning(
                    "hec_keyring_delete_failed",
                    extra={"error_type": type(exc).__name__},
                )
                return False

        logger.info("hec_token_cleared", extra={"source": "keychain"})
        return True


hec_key_store = HECKeyStore()
