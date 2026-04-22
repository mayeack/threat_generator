"""Splunk HEC forwarding subsystem.

Token is read EXCLUSIVELY from the SPLUNK_HEC_TOKEN environment variable
and is never stored in the database, returned via API, or logged.
"""

from .runtime import hec_runtime

__all__ = ["hec_runtime"]
