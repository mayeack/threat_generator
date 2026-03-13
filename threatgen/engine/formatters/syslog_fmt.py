from __future__ import annotations

from datetime import datetime

from .base import BaseFormatter


class SyslogFormatter(BaseFormatter):
    """Syslog formatter for linux_secure with ISO 8601 timestamps."""

    def format(self, ts: datetime, **fields) -> str:
        hostname = fields.get("hostname", "localhost")
        process = fields.get("process", "sshd")
        pid = fields.get("pid", 1234)
        message = fields.get("message", "")

        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        return f"{ts_str} {hostname} {process}[{pid}]: {message}"


class CiscoASAFormatter(BaseFormatter):
    """Cisco ASA syslog with PRI header (facility LOCAL4 = 20)."""

    def format(self, ts: datetime, **fields) -> str:
        hostname = fields.get("hostname", "asa-fw-01")
        severity = fields.get("severity", 6)
        message_id = fields.get("message_id", "302013")
        message = fields.get("message", "")

        # PRI = facility * 8 + severity; LOCAL4 = 20
        pri = 20 * 8 + severity

        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        return f"<{pri}>{ts_str} {hostname} %ASA-{severity}-{message_id}: {message}"
