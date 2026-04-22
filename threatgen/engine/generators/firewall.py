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
    ("411001", 1, 6),   # Line protocol up/down
    ("199005", 0.5, 6), # System reloaded
    ("105004", 0.5, 6), # Monitor connected
]

MSG_IDS = [e[0] for e in EVENTS]
MSG_WEIGHTS = [e[1] for e in EVENTS]
MSG_SEV = {e[0]: e[2] for e in EVENTS}

INTERFACES = ["inside", "outside", "dmz"]
ACL_NAMES = ["outside_access_in", "dmz_access_in", "inside_access_out"]


class FirewallGenerator(BaseGenerator):
    sourcetype = "cisco:asa"

    def __init__(self, topology: Topology, cache: Optional[VariationCache] = None) -> None:
        super().__init__(topology, cache)
        self.fmt = CiscoASAFormatter()

    def _generate_pattern(self, ts: datetime) -> list[str]:
        msg_id = self.rng.choices(MSG_IDS, weights=MSG_WEIGHTS, k=1)[0]
        fw = self.topo.random_firewall()
        severity = MSG_SEV[msg_id]

        if msg_id == "302013":
            msg = self._built_tcp(fw)
        elif msg_id == "302014":
            msg = self._teardown_tcp(fw)
        elif msg_id == "302015":
            msg = self._built_udp(fw)
        elif msg_id == "106023":
            msg = self._deny_acl(fw)
        elif msg_id == "106100":
            msg = self._acl_permitted(fw)
        elif msg_id == "305011":
            msg = self._built_nat(fw)
        elif msg_id == "305012":
            msg = self._teardown_nat(fw)
        elif msg_id == "411001":
            iface = self.rng.choice(INTERFACES)
            msg = f"Line protocol on Interface {iface}, changed state to up"
        elif msg_id == "199005":
            msg = "System reloaded"
        else:
            msg = f"(Secondary) Monitoring on interface {self.rng.choice(INTERFACES)} normal"

        line = self.fmt.format(ts, hostname=fw.hostname, severity=severity, message_id=msg_id, message=msg)
        return [line]

    def _built_tcp(self, fw) -> str:
        conn_id = fw.next_conn_id()
        src_ip, dst_ip, src_iface, dst_iface = self._random_flow(fw)
        dst_port = self.rng.choice([80, 443, 22, 25, 8080, 3389])
        return (
            f"Built outbound TCP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"({src_ip}/{self.topo.random_ephemeral_port()}) to {dst_iface}:{dst_ip}/{dst_port} ({dst_ip}/{dst_port})"
        )

    def _teardown_tcp(self, fw) -> str:
        conn_id = self.rng.randint(1, max(fw._conn_counter, 1))
        src_ip, dst_ip, src_iface, dst_iface = self._random_flow(fw)
        duration = f"0:{self.rng.randint(0, 59):02d}:{self.rng.randint(0, 59):02d}"
        tx = self.rng.randint(100, 50000)
        rx = self.rng.randint(100, 50000)
        return (
            f"Teardown TCP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"to {dst_iface}:{dst_ip}/{self.rng.choice([80, 443, 22])} duration {duration} bytes {tx + rx} "
            f"TCP FINs"
        )

    def _built_udp(self, fw) -> str:
        conn_id = fw.next_conn_id()
        src_ip, dst_ip, src_iface, dst_iface = self._random_flow(fw)
        dst_port = self.rng.choice([53, 123, 514, 161])
        return (
            f"Built outbound UDP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"({src_ip}/{self.topo.random_ephemeral_port()}) to {dst_iface}:{dst_ip}/{dst_port} ({dst_ip}/{dst_port})"
        )

    def _deny_acl(self, fw) -> str:
        src_ip = self.topo.random_external_ip()
        dst = self.topo.random_dmz_server()
        acl = self.rng.choice(ACL_NAMES)
        dst_port = self.rng.choice([22, 3389, 445, 3306, 5432])
        return (
            f"Deny tcp src outside:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"dst dmz:{dst.ip}/{dst_port} by access-group \"{acl}\" [0x0, 0x0]"
        )

    def _acl_permitted(self, fw) -> str:
        src_ip = self.topo.random_external_ip()
        dst = self.topo.random_dmz_server()
        acl = self.rng.choice(ACL_NAMES)
        dst_port = self.rng.choice(dst.ports) if dst.ports else 443
        return (
            f"access-list {acl} permitted tcp outside/{src_ip}({self.topo.random_ephemeral_port()}) -> "
            f"dmz/{dst.ip}({dst_port}) hit-cnt 1 first hit"
        )

    def _built_nat(self, fw) -> str:
        host = self.topo.random_windows_host()
        nat_ip = self.topo.random_nat_ip()
        return f"Built dynamic TCP translation from inside:{host.ip}/{self.topo.random_ephemeral_port()} to outside:{nat_ip}/{self.topo.random_ephemeral_port()}"

    def _teardown_nat(self, fw) -> str:
        host = self.topo.random_windows_host()
        nat_ip = self.topo.random_nat_ip()
        return f"Teardown dynamic TCP translation from inside:{host.ip}/{self.topo.random_ephemeral_port()} to outside:{nat_ip}/{self.topo.random_ephemeral_port()} duration 0:01:30"

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

        if msg_id == "302013":
            msg = self._scenario_built_tcp(fw, direction, dst_port)
        elif msg_id == "302014":
            msg = self._scenario_teardown_tcp(fw, direction, dst_port)
        elif msg_id == "302015":
            msg = self._scenario_built_udp(fw, direction, dst_port)
        elif msg_id == "106023":
            msg = self._scenario_deny_acl(fw, acl, dst_port)
        elif msg_id == "106100":
            msg = self._scenario_acl_permitted(fw, acl, dst_port)
        elif msg_id == "305011":
            msg = self._built_nat(fw)
        elif msg_id == "305012":
            msg = self._teardown_nat(fw)
        elif msg_id == "411001":
            iface = str(scenario.get("interface") or self.rng.choice(INTERFACES))
            if iface not in INTERFACES:
                iface = "inside"
            msg = f"Line protocol on Interface {iface}, changed state to up"
        elif msg_id == "199005":
            msg = "System reloaded"
        else:
            msg = f"(Secondary) Monitoring on interface {self.rng.choice(INTERFACES)} normal"

        line = self.fmt.format(ts, hostname=fw.hostname, severity=severity, message_id=msg_id, message=msg)
        return [line]

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
        return (
            f"Built outbound TCP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"({src_ip}/{self.topo.random_ephemeral_port()}) to {dst_iface}:{dst_ip}/{port} ({dst_ip}/{port})"
        )

    def _scenario_teardown_tcp(self, fw, direction, dst_port):
        conn_id = self.rng.randint(1, max(fw._conn_counter, 1))
        src_ip, dst_ip, src_iface, dst_iface = self._flow_from_direction(fw, direction)
        duration = f"0:{self.rng.randint(0, 59):02d}:{self.rng.randint(0, 59):02d}"
        tx = self.rng.randint(100, 50000)
        rx = self.rng.randint(100, 50000)
        port = dst_port or self.rng.choice([80, 443, 22])
        return (
            f"Teardown TCP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"to {dst_iface}:{dst_ip}/{port} duration {duration} bytes {tx + rx} TCP FINs"
        )

    def _scenario_built_udp(self, fw, direction, dst_port):
        conn_id = fw.next_conn_id()
        src_ip, dst_ip, src_iface, dst_iface = self._flow_from_direction(fw, direction)
        port = dst_port or self.rng.choice([53, 123, 514, 161])
        return (
            f"Built outbound UDP connection {conn_id} for {src_iface}:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"({src_ip}/{self.topo.random_ephemeral_port()}) to {dst_iface}:{dst_ip}/{port} ({dst_ip}/{port})"
        )

    def _scenario_deny_acl(self, fw, acl, dst_port):
        src_ip = self.topo.random_external_ip()
        dst = self.topo.random_dmz_server()
        port = dst_port or self.rng.choice([22, 3389, 445, 3306, 5432])
        return (
            f"Deny tcp src outside:{src_ip}/{self.topo.random_ephemeral_port()} "
            f"dst dmz:{dst.ip}/{port} by access-group \"{acl}\" [0x0, 0x0]"
        )

    def _scenario_acl_permitted(self, fw, acl, dst_port):
        src_ip = self.topo.random_external_ip()
        dst = self.topo.random_dmz_server()
        port = dst_port or (self.rng.choice(dst.ports) if dst.ports else 443)
        return (
            f"access-list {acl} permitted tcp outside/{src_ip}({self.topo.random_ephemeral_port()}) -> "
            f"dmz/{dst.ip}({port}) hit-cnt 1 first hit"
        )
