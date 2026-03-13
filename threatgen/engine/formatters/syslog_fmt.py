from __future__ import annotations

import json
from datetime import datetime

from .base import BaseFormatter


class SyslogFormatter(BaseFormatter):
    """Format linux_secure events as single-line JSON."""

    def format(self, ts: datetime, **fields) -> str:
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        data = {
            "timestamp": ts_str,
            "hostname": fields.get("hostname", "localhost"),
            "process": fields.get("process", "sshd"),
            "pid": fields.get("pid", 1234),
            "message": fields.get("message", ""),
        }
        return json.dumps(data, separators=(",", ":"))


class CiscoASAFormatter(BaseFormatter):
    """Format Cisco ASA events as single-line JSON."""

    def format(self, ts: datetime, **fields) -> str:
        hostname = fields.get("hostname", "asa-fw-01")
        severity = fields.get("severity", 6)
        message_id = fields.get("message_id", "302013")

        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        data = {
            "timestamp": ts_str,
            "hostname": hostname,
            "severity": severity,
            "facility": "LOCAL4",
            "message_id": message_id,
            "tag": f"%ASA-{severity}-{message_id}",
            "message": fields.get("message", ""),
        }
        return json.dumps(data, separators=(",", ":"))
