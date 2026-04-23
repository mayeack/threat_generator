from __future__ import annotations

import json
from datetime import datetime

from .base import BaseFormatter

SYSMON_GUID = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"


class SysmonFormatter(BaseFormatter):
    """Format events as single-line JSON for Sysmon.

    Top-level entity-discovery fields are emitted alongside the native
    EventData map so Splunk ES Exposure Analytics can auto-discover Asset,
    IP, User, and MAC entities from a streaming source search.
    """

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

        data: dict[str, object] = {
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

        nt_host = fields.get("nt_host")
        if nt_host:
            data["nt_host"] = nt_host
        dest_nt_host = fields.get("dest_nt_host")
        if dest_nt_host:
            data["dest_nt_host"] = dest_nt_host
        user = fields.get("user")
        if user:
            data["user"] = user
        user_id = fields.get("user_id")
        if user_id:
            data["user_id"] = user_id
        src_ip = fields.get("src_ip")
        if src_ip:
            data["src_ip"] = src_ip
        dest_ip = fields.get("dest_ip")
        if dest_ip:
            data["dest_ip"] = dest_ip
        ip = fields.get("ip") or src_ip or dest_ip
        if ip:
            data["ip"] = ip
        mac = fields.get("mac")
        if mac:
            data["mac"] = mac

        return json.dumps(data, separators=(",", ":"))
