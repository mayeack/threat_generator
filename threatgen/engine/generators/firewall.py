from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from threatgen.engine.llm.cache import VariationCache

from ..formatters.syslog_fmt import CiscoASAFormatter
from ..topology import Topology
from .base import BaseGenerator

EVENTS = [
    ("302013", 30, 6),  # Built TCP
    ("302014", 25, 6),  # Teardown TCP
    ("302015", 10, 6),  # Built UDP
    ("106023", 10, 4),  # Deny by ACL
    ("106100", 10, 6),  # ACL permitted
    ("305011", 8, 6),   # Built NAT
    ("305012", 5, 6),   # Teardown NAT
    ("722051", 10, 6),  # SVC: Session created (AnyConnect) - VPN
    ("113019", 5, 4),   # VPN session disconnected
    ("113004", 5, 6),   # AAA user authentication Successful (VPN companion)
    ("411001", 1, 6),   # Line protocol up/down
    ("199005", 0.5, 6), # System reloaded
    ("105004", 0.5, 6), # Monitor connected
]

MSG_IDS = [e[0] for e in EVENTS]
MSG_WEIGHTS = [e[1] for e in EVENTS]
MSG_SEV = {e[0]: e[2] for e in EVENTS}

INTERFACES = ["inside", "outside", "dmz"]
ACL_NAMES = ["outside_access_in", "dmz_access_in", "inside_access_out"]

# VPN session fields used to render %ASA-6-722051 / %ASA-4-113019 /
# %ASA-6-113004 messages. Kept small and deterministic so Exposure Analytics
# validation queries consistently find matching literals ("Group <",
# "assigned to session") and so downstream CIM/VPN datamodels see a stable
# vocabulary for group policies, tunnel groups, and session types.
VPN_GROUP_POLICIES = [
    "GroupPolicy_VPN-Users",
    "GroupPolicy_Contractors",
    "GroupPolicy_Admins",
]
VPN_TUNNEL_GROUPS = ["VPN-Users", "Contractors", "Admins"]
VPN_USERS = ["alice", "bob", "carol", "dave", "eve"]
VPN_SESSION_TYPES = ["SSL", "IKEv2"]
VPN_DISCONNECT_REASONS = [
    "User Requested",
    "Idle Timeout",
    "Peer Terminate",
    "Session Administratively Terminated",
]
VPN_AAA_SERVERS = ["radius", "ldap", "tacacs"]


class FirewallGenerator(BaseGenerator):
    sourcetype = "cisco:asa"

    def __init__(self, topology: Topology, cache: Optional[VariationCache] = None) -> None:
        super().__init__(topology, cache)
        self.fmt = CiscoASAFormatter()

    def _emit(
        self,
        ts: datetime,
        fw,
        severity: int,
        msg_id: str,
        message: str,
        src_ip: Optional[str],
        dest_ip: Optional[str],
        *,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        group_policy: Optional[str] = None,
        tunnel_group: Optional[str] = None,
        session_type: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> list[str]:
        line = self.fmt.format(
            ts,
            hostname=fw.hostname,
            severity=severity,
            message_id=msg_id,
            message=message,
            nt_host=fw.hostname,
            mac=getattr(fw, "mac", ""),
            src_ip=src_ip,
            dest_ip=dest_ip,
            ip=ip,
            user_id=user_id,
            user=username,
            username=username,
            group_policy=group_policy,
            tunnel_group=tunnel_group,
            session_type=session_type,
        )
        return [line]

    def _generate_pattern(self, ts: datetime) -> list[str]:
        msg_id = self.rng.choices(MSG_IDS, weights=MSG_WEIGHTS, k=1)[0]
        fw = self.topo.random_firewall()
        severity = MSG_SEV[msg_id]

        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None

        if msg_id == "302013":
            msg, src_ip, dst_ip = self._built_tcp(fw)
        elif msg_id == "302014":
            msg, src_ip, dst_ip = self._teardown_tcp(fw)
        elif msg_id == "302015":
            msg, src_ip, dst_ip = self._built_udp(fw)
        elif msg_id == "106023":
            msg, src_ip, dst_ip = self._deny_acl(fw)
        elif msg_id == "106100":
            msg, src_ip, dst_ip = self._acl_permitted(fw)
        elif msg_id == "305011":
            msg, src_ip, dst_ip = self._built_nat(fw)
        elif msg_id == "305012":
            msg, src_ip, dst_ip = self._teardown_nat(fw)
        elif msg_id in ("722051", "113019", "113004"):
            return self._emit_vpn(ts, fw, severity, msg_id)
        elif msg_id == "411001":
            iface = self.rng.choice(INTERFACES)
            msg = f"Line protocol on Interface {iface}, changed state to up"
        elif msg_id == "199005":
            msg = "System reloaded"
        else:
            msg = f"(Secondary) Monitoring on interface {self.rng.choice(INTERFACES)} normal"

        return self._emit(ts, fw, severity, msg_id, msg, src_ip, dst_ip)

    def _built_tcp(self, fw):
        conn_id = fw.next_conn_id()
        src_ip, dst_ip, src_iface, dst_iface = self._random_flow(fw)
        dst_port = self.rng.choice([80, 443, 22, 25, 8080, 3389])
        msg = (
            f"Built outbound TCP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"({src_ip}/{self.topo.random_ephemeral_port()}) to {dst_iface}:{dst_ip}/{dst_port} ({dst_ip}/{dst_port})"
        )
        return msg, src_ip, dst_ip

    def _teardown_tcp(self, fw):
        conn_id = self.rng.randint(1, max(fw._conn_counter, 1))
        src_ip, dst_ip, src_iface, dst_iface = self._random_flow(fw)
        duration = f"0:{self.rng.randint(0, 59):02d}:{self.rng.randint(0, 59):02d}"
        tx = self.rng.randint(100, 50000)
        rx = self.rng.randint(100, 50000)
        msg = (
            f"Teardown TCP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"to {dst_iface}:{dst_ip}/{self.rng.choice([80, 443, 22])} duration {duration} bytes {tx + rx} "
            f"TCP FINs"
        )
        return msg, src_ip, dst_ip

    def _built_udp(self, fw):
        conn_id = fw.next_conn_id()
        src_ip, dst_ip, src_iface, dst_iface = self._random_flow(fw)
        dst_port = self.rng.choice([53, 123, 514, 161])
        msg = (
            f"Built outbound UDP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"({src_ip}/{self.topo.random_ephemeral_port()}) to {dst_iface}:{dst_ip}/{dst_port} ({dst_ip}/{dst_port})"
        )
        return msg, src_ip, dst_ip

    def _deny_acl(self, fw):
        src_ip = self.topo.random_external_ip()
        dst = self.topo.random_dmz_server()
        acl = self.rng.choice(ACL_NAMES)
        dst_port = self.rng.choice([22, 3389, 445, 3306, 5432])
        msg = (
            f"Deny tcp src outside:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"dst dmz:{dst.ip}/{dst_port} by access-group \"{acl}\" [0x0, 0x0]"
        )
        return msg, src_ip, dst.ip

    def _acl_permitted(self, fw):
        src_ip = self.topo.random_external_ip()
        dst = self.topo.random_dmz_server()
        acl = self.rng.choice(ACL_NAMES)
        dst_port = self.rng.choice(dst.ports) if dst.ports else 443
        msg = (
            f"access-list {acl} permitted tcp outside/{src_ip}({self.topo.random_ephemeral_port()}) -> "
            f"dmz/{dst.ip}({dst_port}) hit-cnt 1 first hit"
        )
        return msg, src_ip, dst.ip

    def _built_nat(self, fw):
        host = self.topo.random_windows_host()
        nat_ip = self.topo.random_nat_ip()
        msg = (
            f"Built dynamic TCP translation from inside:{host.ip}/{self.topo.random_ephemeral_port()} "
            f"to outside:{nat_ip}/{self.topo.random_ephemeral_port()}"
        )
        return msg, host.ip, nat_ip

    def _teardown_nat(self, fw):
        host = self.topo.random_windows_host()
        nat_ip = self.topo.random_nat_ip()
        msg = (
            f"Teardown dynamic TCP translation from inside:{host.ip}/{self.topo.random_ephemeral_port()} "
            f"to outside:{nat_ip}/{self.topo.random_ephemeral_port()} duration 0:01:30"
        )
        return msg, host.ip, nat_ip

    def _emit_vpn(
        self,
        ts: datetime,
        fw,
        severity: int,
        msg_id: str,
    ) -> list[str]:
        """Render a Cisco ASA VPN session message and emit it with the full
        entity-field envelope. Covers %ASA-6-722051 (session created),
        %ASA-4-113019 (session disconnected), and %ASA-6-113004 (AAA auth
        success companion). These are the messages Exposure Analytics'
        "ASA VPN Sessions" discovery source filters for via
        ``"Group <" tag=vpn ("assigned to session")``; the required literal
        strings are rendered here and ``tag=vpn`` is applied at search time
        via the TA's eventtypes/tags configuration."""
        username = self.rng.choice(VPN_USERS)
        group_policy = self.rng.choice(VPN_GROUP_POLICIES)
        tunnel_group = self.rng.choice(VPN_TUNNEL_GROUPS)
        session_type = self.rng.choice(VPN_SESSION_TYPES)
        assigned_ip = self.topo.random_windows_host().ip
        public_ip = self.topo.random_external_ip()

        if msg_id == "722051":
            msg = (
                f"Group <{group_policy}> User <{username}> IP <{public_ip}> "
                f"IPv4 Address <{assigned_ip}> IPv6 address <::> assigned to session"
            )
            src_ip = public_ip
            dst_ip = assigned_ip
            ip = assigned_ip
        elif msg_id == "113019":
            duration = (
                f"{self.rng.randint(0, 4)}h:"
                f"{self.rng.randint(0, 59):02d}m:"
                f"{self.rng.randint(0, 59):02d}s"
            )
            bytes_xmt = self.rng.randint(1024, 1_000_000)
            bytes_rcv = self.rng.randint(1024, 1_000_000)
            reason = self.rng.choice(VPN_DISCONNECT_REASONS)
            msg = (
                f"Group <{group_policy}> Username <{username}>, IP <{public_ip}>, "
                f"Session disconnected. Session Type: {session_type}, "
                f"Duration: {duration}, Bytes xmt: {bytes_xmt}, "
                f"Bytes rcv: {bytes_rcv}, Reason: {reason}"
            )
            src_ip = public_ip
            dst_ip = None
            ip = public_ip
        else:  # 113004
            server = self.rng.choice(VPN_AAA_SERVERS)
            msg = (
                f"AAA user authentication Successful : server =  <{server}> : "
                f"user = {username}"
            )
            src_ip = public_ip
            dst_ip = None
            ip = public_ip

        return self._emit(
            ts,
            fw,
            severity,
            msg_id,
            msg,
            src_ip,
            dst_ip,
            user_id=username,
            username=username,
            group_policy=group_policy,
            tunnel_group=tunnel_group,
            session_type=session_type,
            ip=ip,
        )

    def _random_flow(self, fw):
        direction = self.rng.choice(["outbound", "inbound", "dmz"])
        if direction == "outbound":
            src = self.topo.random_windows_host().ip
            dst = self.topo.random_external_ip()
            return src, dst, "inside", "outside"
        elif direction == "inbound":
            src = self.topo.random_external_ip()
            dst = self.topo.random_dmz_server().ip
            return src, dst, "outside", "dmz"
        else:
            src = self.topo.random_dmz_server().ip
            dst = self.topo.random_linux_host().ip
            return src, dst, "dmz", "inside"

    def render_from_scenario(self, scenario: dict[str, Any], ts: datetime) -> list[str]:
        msg_id = str(scenario.get("message_id") or "302013")
        if msg_id not in MSG_SEV:
            msg_id = "302013"
        severity = MSG_SEV[msg_id]
        fw = self.topo.random_firewall()
        direction = str(scenario.get("direction") or "outbound")
        if direction not in ("outbound", "inbound", "dmz"):
            direction = "outbound"
        dst_port = scenario.get("dst_port")
        try:
            dst_port = int(dst_port) if dst_port is not None else None
        except (TypeError, ValueError):
            dst_port = None
        if dst_port is not None and not 1 <= dst_port <= 65535:
            dst_port = None
        acl = str(scenario.get("acl_name") or self.rng.choice(ACL_NAMES))[:64]

        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None

        if msg_id == "302013":
            msg, src_ip, dst_ip = self._scenario_built_tcp(fw, direction, dst_port)
        elif msg_id == "302014":
            msg, src_ip, dst_ip = self._scenario_teardown_tcp(fw, direction, dst_port)
        elif msg_id == "302015":
            msg, src_ip, dst_ip = self._scenario_built_udp(fw, direction, dst_port)
        elif msg_id == "106023":
            msg, src_ip, dst_ip = self._scenario_deny_acl(fw, acl, dst_port)
        elif msg_id == "106100":
            msg, src_ip, dst_ip = self._scenario_acl_permitted(fw, acl, dst_port)
        elif msg_id == "305011":
            msg, src_ip, dst_ip = self._built_nat(fw)
        elif msg_id == "305012":
            msg, src_ip, dst_ip = self._teardown_nat(fw)
        elif msg_id in ("722051", "113019", "113004"):
            return self._emit_vpn(ts, fw, severity, msg_id)
        elif msg_id == "411001":
            iface = str(scenario.get("interface") or self.rng.choice(INTERFACES))
            if iface not in INTERFACES:
                iface = "inside"
            msg = f"Line protocol on Interface {iface}, changed state to up"
        elif msg_id == "199005":
            msg = "System reloaded"
        else:
            msg = f"(Secondary) Monitoring on interface {self.rng.choice(INTERFACES)} normal"

        return self._emit(ts, fw, severity, msg_id, msg, src_ip, dst_ip)

    def _flow_from_direction(self, fw, direction: str):
        if direction == "outbound":
            src = self.topo.random_windows_host().ip
            dst = self.topo.random_external_ip()
            return src, dst, "inside", "outside"
        if direction == "inbound":
            src = self.topo.random_external_ip()
            dst = self.topo.random_dmz_server().ip
            return src, dst, "outside", "dmz"
        src = self.topo.random_dmz_server().ip
        dst = self.topo.random_linux_host().ip
        return src, dst, "dmz", "inside"

    def _scenario_built_tcp(self, fw, direction, dst_port):
        conn_id = fw.next_conn_id()
        src_ip, dst_ip, src_iface, dst_iface = self._flow_from_direction(fw, direction)
        port = dst_port or self.rng.choice([80, 443, 22, 25, 8080, 3389])
        msg = (
            f"Built outbound TCP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"({src_ip}/{self.topo.random_ephemeral_port()}) to {dst_iface}:{dst_ip}/{port} ({dst_ip}/{port})"
        )
        return msg, src_ip, dst_ip

    def _scenario_teardown_tcp(self, fw, direction, dst_port):
        conn_id = self.rng.randint(1, max(fw._conn_counter, 1))
        src_ip, dst_ip, src_iface, dst_iface = self._flow_from_direction(fw, direction)
        duration = f"0:{self.rng.randint(0, 59):02d}:{self.rng.randint(0, 59):02d}"
        tx = self.rng.randint(100, 50000)
        rx = self.rng.randint(100, 50000)
        port = dst_port or self.rng.choice([80, 443, 22])
        msg = (
            f"Teardown TCP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"to {dst_iface}:{dst_ip}/{port} duration {duration} bytes {tx + rx} TCP FINs"
        )
        return msg, src_ip, dst_ip

    def _scenario_built_udp(self, fw, direction, dst_port):
        conn_id = fw.next_conn_id()
        src_ip, dst_ip, src_iface, dst_iface = self._flow_from_direction(fw, direction)
        port = dst_port or self.rng.choice([53, 123, 514, 161])
        msg = (
            f"Built outbound UDP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"({src_ip}/{self.topo.random_ephemeral_port()}) to {dst_iface}:{dst_ip}/{port} ({dst_ip}/{port})"
        )
        return msg, src_ip, dst_ip

    def _scenario_deny_acl(self, fw, acl, dst_port):
        src_ip = self.topo.random_external_ip()
        dst = self.topo.random_dmz_server()
        port = dst_port or self.rng.choice([22, 3389, 445, 3306, 5432])
        msg = (
            f"Deny tcp src outside:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"dst dmz:{dst.ip}/{port} by access-group \"{acl}\" [0x0, 0x0]"
        )
        return msg, src_ip, dst.ip

    def _scenario_acl_permitted(self, fw, acl, dst_port):
        src_ip = self.topo.random_external_ip()
        dst = self.topo.random_dmz_server()
        port = dst_port or (self.rng.choice(dst.ports) if dst.ports else 443)
        msg = (
            f"access-list {acl} permitted tcp outside/{src_ip}({self.topo.random_ephemeral_port()}) -> "
            f"dmz/{dst.ip}({port}) hit-cnt 1 first hit"
        )
        return msg, src_ip, dst.ip
