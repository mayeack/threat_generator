from __future__ import annotations

from datetime import datetime

from .base import BaseFormatter


class WinEventLogFormatter(BaseFormatter):
    def format(self, ts: datetime, **fields) -> str:
        ts_str = ts.strftime("%m/%d/%Y %I:%M:%S %p")
        event_code = fields.get("event_code", 4624)
        computer = fields.get("computer", "UNKNOWN")
        task_category = fields.get("task_category", "Logon")
        keywords = fields.get("keywords", "Audit Success")
        message = fields.get("message", "")

        lines = [
            ts_str,
            "LogName=Security",
            f"EventCode={event_code}",
            "EventType=0",
            f"ComputerName={computer}",
            "SourceName=Microsoft-Windows-Security-Auditing",
            "Type=Information",
            f"TaskCategory={task_category}",
            "OpCode=Info",
            f"Keywords={keywords}",
            f"Message={message}",
        ]
        return "\n".join(lines)
