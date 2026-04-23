from __future__ import annotations

import json
from datetime import datetime

from .base import BaseFormatter


def _augment_with_entities(data: dict[str, object], fields: dict[str, object]) -> None:
    """Attach top-level entity-discovery fields (ES Exposure Analytics)."""
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


class SyslogFormatter(BaseFormatter):
    """Format linux_secure events as single-line JSON."""

    def format(self, ts: datetime, **fields) -> str:
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        data: dict[str, object] = {
            "timestamp": ts_str,
            "hostname": fields.get("hostname", "localhost"),
            "process": fields.get("process", "sshd"),
            "pid": fields.get("pid", 1234),
            "message": fields.get("message", ""),
        }
        _augment_with_entities(data, fields)
        return json.dumps(data, separators=(",", ":"))


class CiscoASAFormatter(BaseFormatter):
    """Format Cisco ASA events as single-line JSON."""

    def format(self, ts: datetime, **fields) -> str:
        hostname = fields.get("hostname", "asa-fw-01")
        severity = fields.get("severity", 6)
        message_id = fields.get("message_id", "302013")

        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        data: dict[str, object] = {
            "timestamp": ts_str,
            "hostname": hostname,
            "severity": severity,
            "facility": "LOCAL4",
            "message_id": message_id,
            "tag": f"%ASA-{severity}-{message_id}",
            "message": fields.get("message", ""),
        }
        # Optional VPN session attributes (only included when the caller
        # is emitting a VPN message such as %ASA-6-722051 / %ASA-4-113019).
        # Presence of ``group_policy`` is the trigger; EA's
        # "ASA VPN Sessions" discovery source filters on ``tag=vpn``, which
        # is applied via eventtypes.conf/tags.conf in the TA for the
        # relevant message IDs. The ``username`` and ``group_policy`` keys
        # make downstream CIM/VPN datamodel mappings richer without
        # affecting non-VPN events.
        username = fields.get("username")
        if username:
            data["username"] = username
        group_policy = fields.get("group_policy")
        if group_policy:
            data["group_policy"] = group_policy
        tunnel_group = fields.get("tunnel_group")
        if tunnel_group:
            data["tunnel_group"] = tunnel_group
        session_type = fields.get("session_type")
        if session_type:
            data["session_type"] = session_type
        _augment_with_entities(data, fields)
        return json.dumps(data, separators=(",", ":"))
