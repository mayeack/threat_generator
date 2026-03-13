from __future__ import annotations

import json
from datetime import datetime

from .base import BaseFormatter


class WinEventLogFormatter(BaseFormatter):
    """Format events as single-line JSON for WinEventLog:Security."""

    def format(self, ts: datetime, **fields) -> str:
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        data = {
            "timestamp": ts_str,
            "LogName": "Security",
            "SourceName": "Microsoft Windows security auditing.",
            "EventCode": fields.get("event_code", 4624),
            "EventType": 0,
            "Type": "Information",
            "ComputerName": fields.get("computer", "UNKNOWN"),
            "TaskCategory": fields.get("task_category", "Logon"),
            "OpCode": "Info",
            "RecordNumber": fields.get("record_number", 0),
            "Keywords": fields.get("keywords", "Audit Success"),
            "Message": fields.get("message", ""),
        }
        return json.dumps(data, separators=(",", ":"))
