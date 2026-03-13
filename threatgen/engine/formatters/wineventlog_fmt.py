from __future__ import annotations

from datetime import datetime

from .base import BaseFormatter


class WinEventLogFormatter(BaseFormatter):
    """Format events to match Splunk_TA_windows WinEventLog:Security output."""

    def format(self, ts: datetime, **fields) -> str:
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        event_code = fields.get("event_code", 4624)
        computer = fields.get("computer", "UNKNOWN")
        task_category = fields.get("task_category", "Logon")
        keywords = fields.get("keywords", "Audit Success")
        message = fields.get("message", "")
        record_number = fields.get("record_number", 0)

        lines = [
            ts_str,
            "LogName=Security",
            "SourceName=Microsoft Windows security auditing.",
            f"EventCode={event_code}",
            "EventType=0",
            "Type=Information",
            f"ComputerName={computer}",
            f"TaskCategory={task_category}",
            "OpCode=Info",
            f"RecordNumber={record_number}",
            f"Keywords={keywords}",
            f"Message={message}",
        ]
        return "\n".join(lines)
