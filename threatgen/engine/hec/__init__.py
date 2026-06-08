"""Splunk HEC forwarding subsystem (multi-destination).

Each destination's token is read EXCLUSIVELY from either an environment
variable (``SPLUNK_HEC_TOKEN`` for the default destination, or the
``SPLUNK_HEC_TOKEN_<DEST_ID>`` override for others) or the OS keychain
via the ``keyring`` package. Tokens are NEVER stored in the database,
returned via any API response, or logged.
"""

from .runtime import hec_runtime

__all__ = ["hec_runtime"]
