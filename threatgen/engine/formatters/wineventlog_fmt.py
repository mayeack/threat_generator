from __future__ import annotations

import json
from datetime import datetime

from .base import BaseFormatter


class WinEventLogFormatter(BaseFormatter):
    """Format events as single-line JSON for WinEventLog:Security.

    Top-level entity-discovery fields (nt_host, user_id, ip, mac, src_ip,
    dest_ip, user, dest_nt_host) are emitted alongside the native WinEventLog
    keys so Splunk ES Exposure Analytics can auto-discover Asset, IP, User,
    and MAC entities from a streaming source search with no pipe operators.
    """

    def format(self, ts: datetime, **fields) -> str:
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        data: dict[str, object] = {
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
        ip = fields.get("ip") or dest_ip or src_ip
        if ip:
            data["ip"] = ip
        mac = fields.get("mac")
        if mac:
            data["mac"] = mac

        return json.dumps(data, separators=(",", ":"))
