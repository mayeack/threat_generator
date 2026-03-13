from __future__ import annotations

import json
from datetime import datetime

from .base import BaseFormatter

SYSMON_GUID = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"


class SysmonFormatter(BaseFormatter):
    """Format events as single-line JSON for Sysmon."""

    def format(self, ts: datetime, **fields) -> str:
        event_id = fields.get("event_id", 1)
        computer = fields.get("computer", "UNKNOWN")
        task = fields.get("task", event_id)
        data_fields: list[tuple[str, str]] = fields.get("data_fields", [])
        record_id = fields.get("record_id", 0)
        sysmon_pid = fields.get("sysmon_pid", 2084)
        sysmon_tid = fields.get("sysmon_tid", 3912)

        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

        event_data = {name: value for name, value in data_fields}

        data = {
            "timestamp": ts_str,
            "Provider": "Microsoft-Windows-Sysmon",
            "ProviderGuid": SYSMON_GUID,
            "EventID": event_id,
            "Version": 5,
            "Level": 4,
            "Task": task,
            "Opcode": 0,
            "Keywords": "0x8000000000000000",
            "EventRecordID": record_id,
            "ProcessID": sysmon_pid,
            "ThreadID": sysmon_tid,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": computer,
            "UserID": "S-1-5-18",
            "EventData": event_data,
        }
        return json.dumps(data, separators=(",", ":"))
