"""Secure storage for Splunk HEC tokens (one token per destination).

Resolution order per destination (highest priority first):

    1. ``SPLUNK_HEC_TOKEN_<DEST_ID_UPPER_SLUG>`` environment variable
       (per-destination override; ``dest_id`` is uppercased and any
       non-alphanumeric character becomes ``_`` to form the suffix)
    2. ``SPLUNK_HEC_TOKEN`` environment variable -- applies only to the
       ``default`` destination so single-destination deployments keep
       working unchanged
    3. OS secret store (macOS Keychain, Windows Credential Manager,
       Linux Secret Service) via the `keyring` package, keyed by
       service ``threatgen.splunk_hec`` / user ``<dest_id>``
    4. None (HEC forwarder will start but emit errors)

Security posture (mirrors threatgen.engine.llm.key_store):
    * Tokens are NEVER persisted to the SQLite config store, YAML
      files, logs, or any API response body.
    * When stored via keyring, they are encrypted at rest by the OS and
      protected by the logged-in user's credentials.
    * Env vars always win over the keychain so operators can override
      at deploy time without mutating the keychain.
    * If the keyring backend is unavailable (headless Linux without
      Secret Service, locked keychain, etc.), writes fail fast with
      KeyStoreUnavailable rather than silently falling back to an
      insecure location.
    * Splunk HEC tokens are UUIDs; we validate strict UUID shape
      before ever accepting a value from the UI.
    * ``dest_id`` is validated against ``is_valid_dest_id`` before it
      is used as a keychain user-name, env-var suffix, or anywhere
      else it could leave our process.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass
from typing import Optional

from threatgen.engine.config import DEFAULT_HEC_DEST_ID, is_valid_dest_id

logger = logging.getLogger(__name__)

ENV_KEY_NAME = "SPLUNK_HEC_TOKEN"
ENV_KEY_PREFIX = "SPLUNK_HEC_TOKEN_"
KEYRING_SERVICE = "threatgen.splunk_hec"
# Retained for backward compatibility with older callers; new code
# passes a destination id explicitly.
KEYRING_USER = DEFAULT_HEC_DEST_ID

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


class InvalidDestinationId(KeyStoreError):
    """Caller supplied a string that is not a valid destination id."""


def _per_dest_env_var(dest_id: str) -> str:
    """Return the env-var name for a per-destination token override.

    ``dest_id`` is already restricted to ``[a-z0-9-]`` by
    ``is_valid_dest_id``; we uppercase and replace ``-`` with ``_`` to
    form a safe suffix.
    """
    suffix = dest_id.upper().replace("-", "_")
    return ENV_KEY_PREFIX + suffix


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


def _validate_dest_id(dest_id: str) -> str:
    """Return ``dest_id`` after validation; raises on bad input."""
    if not is_valid_dest_id(dest_id):
        # Never echo the raw value in the message; an attacker who can
        # reach this path could otherwise observe a non-sanitized string
        # being reflected in error responses.
        raise InvalidDestinationId(
            "destination id must match [a-z0-9-]{1,40} (started with a letter or digit)"
        )
    return dest_id


def _env_for_destination(dest_id: str) -> Optional[str]:
    """Resolve any env-var override for this destination.

    Precedence: per-destination override > legacy ``SPLUNK_HEC_TOKEN``
    (the legacy fallback applies only to the ``default`` destination).
    """
    per_dest = os.environ.get(_per_dest_env_var(dest_id))
    if per_dest and per_dest.strip():
        return per_dest.strip()
    if dest_id == DEFAULT_HEC_DEST_ID:
        legacy = os.environ.get(ENV_KEY_NAME)
        if legacy and legacy.strip():
            return legacy.strip()
    return None


class HECKeyStore:
    """Thread-safe accessor for Splunk HEC tokens, namespaced by
    destination id."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------
    def get(self, dest_id: str = DEFAULT_HEC_DEST_ID) -> tuple[Optional[str], Source]:
        _validate_dest_id(dest_id)

        env_val = _env_for_destination(dest_id)
        if env_val:
            return env_val, "env"

        try:
            keyring = _import_keyring()
        except KeyStoreUnavailable:
            return None, "none"

        try:
            val = keyring.get_password(KEYRING_SERVICE, dest_id)
        except Exception as exc:
            logger.warning(
                "hec_keyring_read_failed",
                extra={"error_type": type(exc).__name__, "dest_id": dest_id},
            )
            return None, "none"

        if val:
            return val, "keychain"
        return None, "none"

    def info(self, dest_id: str = DEFAULT_HEC_DEST_ID) -> KeyInfo:
        val, src = self.get(dest_id)
        return KeyInfo(source=src, present=bool(val))

    def env_var_for(self, dest_id: str = DEFAULT_HEC_DEST_ID) -> str:
        """Return the env-var name that controls this destination.

        For the default destination this is the legacy ``SPLUNK_HEC_TOKEN``
        (so existing operator runbooks keep working); for any other
        destination it is the per-destination override variable.
        """
        _validate_dest_id(dest_id)
        if dest_id == DEFAULT_HEC_DEST_ID:
            return ENV_KEY_NAME
        return _per_dest_env_var(dest_id)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------
    def set(self, token: str, dest_id: str = DEFAULT_HEC_DEST_ID) -> None:
        _validate_dest_id(dest_id)

        if not isinstance(token, str):
            raise InvalidKeyFormat("token must be a string")
        cleaned = token.strip()
        if not _TOKEN_RE.match(cleaned):
            # Avoid echoing the token; include only length for diagnostics.
            raise InvalidKeyFormat(
                "token does not look like a Splunk HEC token "
                f"(len={len(cleaned)}, expected 8-4-4-4-12 UUID)"
            )

        # Refuse to shadow any env-provided token. Operators set env
        # vars deliberately; silently writing to the keychain would be
        # surprising on restart / in another shell.
        if _env_for_destination(dest_id):
            env_name = self.env_var_for(dest_id)
            raise KeyStoreError(
                f"{env_name} is already set in the environment; "
                "unset it before storing a token via the UI"
            )

        keyring = _import_keyring()  # raises KeyStoreUnavailable
        with self._lock:
            try:
                keyring.set_password(KEYRING_SERVICE, dest_id, cleaned)
            except Exception as exc:
                # Never log the token value or any substring.
                logger.error(
                    "hec_keyring_write_failed",
                    extra={"error_type": type(exc).__name__, "dest_id": dest_id},
                )
                raise KeyStoreUnavailable(
                    f"failed to write to keychain: {exc}"
                ) from exc

        logger.info("hec_token_stored", extra={"source": "keychain", "dest_id": dest_id})

    def clear(self, dest_id: str = DEFAULT_HEC_DEST_ID) -> bool:
        """Remove the keychain entry for ``dest_id``. Returns True if
        something was removed, False if nothing was stored. Does not
        touch any environment variable."""
        _validate_dest_id(dest_id)
        try:
            keyring = _import_keyring()
        except KeyStoreUnavailable:
            return False

        with self._lock:
            try:
                existing = keyring.get_password(KEYRING_SERVICE, dest_id)
                if not existing:
                    return False
                keyring.delete_password(KEYRING_SERVICE, dest_id)
            except Exception as exc:
                logger.warning(
                    "hec_keyring_delete_failed",
                    extra={"error_type": type(exc).__name__, "dest_id": dest_id},
                )
                return False

        logger.info("hec_token_cleared", extra={"source": "keychain", "dest_id": dest_id})
        return True


hec_key_store = HECKeyStore()
