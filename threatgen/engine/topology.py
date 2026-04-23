from __future__ import annotations

import hashlib
import random
import uuid
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Any, Optional


def _deterministic_mac(seed: str) -> str:
    """Derive a stable locally-administered MAC address from a seed string.

    The 02: OUI prefix is the IEEE locally-administered unicast space, so it
    cannot collide with real vendor MACs. Five bytes of SHA-256 provide the
    remaining entropy and keep the value stable across runs for a given host.
    """
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return "02:" + ":".join(digest[i : i + 2] for i in (0, 2, 4, 6, 8)).upper()


@dataclass
class WindowsHost:
    hostname: str
    ip: str
    os_version: str = "Windows 10 Enterprise"
    domain: str = "CORPDOMAIN"
    mac: str = ""


@dataclass
class LinuxHost:
    hostname: str
    ip: str
    os_version: str = "Ubuntu 22.04"
    mac: str = ""


@dataclass
class DMZServer:
    ip: str
    hostname: str
    role: str
    ports: list[int] = field(default_factory=list)
    mac: str = ""


@dataclass
class Firewall:
    hostname: str
    inside_ip: str
    outside_ip: str
    dmz_ip: str
    mac: str = ""
    _conn_counter: int = field(default=0, repr=False)

    def next_conn_id(self) -> int:
        self._conn_counter += 1
        return self._conn_counter


@dataclass
class User:
    username: str
    domain: str = "CORPDOMAIN"
    sid: str = ""
    is_admin: bool = False


class Topology:
    def __init__(self, data: dict[str, Any], rng: random.Random) -> None:
        self.rng = rng
        self.domain_name: str = data.get("domain_name", "CORPDOMAIN")
        self.dns_fqdn: str = data.get("dns_fqdn", "corp.local")
        self.dns_server_ip: str = data.get("dns_server_ip", "10.1.0.10")

        self.windows_hosts = [
            WindowsHost(
                h["hostname"],
                h["ip"],
                h.get("os_version", "Windows 10 Enterprise"),
                self.domain_name,
                h.get("mac") or _deterministic_mac(h["hostname"]),
            )
            for h in data.get("windows_hosts", [])
        ]
        self.linux_hosts = [
            LinuxHost(
                h["hostname"],
                h["ip"],
                h.get("os_version", "Ubuntu 22.04"),
                h.get("mac") or _deterministic_mac(h["hostname"]),
            )
            for h in data.get("linux_hosts", [])
        ]
        self.domain_controllers = [
            WindowsHost(
                h["hostname"],
                h["ip"],
                h.get("os_version", "Windows Server 2019"),
                self.domain_name,
                h.get("mac") or _deterministic_mac(h["hostname"]),
            )
            for h in data.get("domain_controllers", [])
        ]
        self.file_servers = [
            WindowsHost(
                h["hostname"],
                h["ip"],
                h.get("os_version", "Windows Server 2019"),
                self.domain_name,
                h.get("mac") or _deterministic_mac(h["hostname"]),
            )
            for h in data.get("file_servers", [])
        ]
        self.dmz_servers = [
            DMZServer(
                d["ip"],
                d["hostname"],
                d["role"],
                d.get("ports", []),
                d.get("mac") or _deterministic_mac(d["hostname"]),
            )
            for d in data.get("dmz_servers", [])
        ]
        self.firewalls = [
            Firewall(
                f["hostname"],
                f["inside_ip"],
                f["outside_ip"],
                f["dmz_ip"],
                f.get("mac") or _deterministic_mac(f["hostname"]),
            )
            for f in data.get("firewalls", [])
        ]

        self.users: list[User] = []
        self.admin_users: list[User] = []
        for i, u in enumerate(data.get("users", [])):
            sid = f"S-1-5-21-3623811015-3361044348-30300820-{1001 + i}"
            user = User(u["username"], self.domain_name, sid, u.get("is_admin", False))
            self.users.append(user)
            if user.is_admin:
                self.admin_users.append(user)

        self.normal_external_networks = [
            IPv4Network(n) for n in data.get("external_ip_pools", {}).get("normal", [])
        ]
        self.threat_ips = data.get("external_ip_pools", {}).get("threat", [])

        nat_str = data.get("nat_pool", "203.0.113.100-203.0.113.120")
        parts = nat_str.split("-")
        self.nat_pool_start = IPv4Address(parts[0])
        self.nat_pool_end = IPv4Address(parts[1]) if len(parts) > 1 else self.nat_pool_start

        self.common_ports: dict[str, list[int]] = data.get("common_ports", {})

        self.terndoor_c2_ips: list[str] = []
        self.peertime_domains: list[str] = []
        self.peertime_ips: list[str] = []
        self.bruteentry_ips: list[str] = []
        self.cobaltstrike_domains: list[str] = []
        self.cobaltstrike_ips: list[str] = []
        self.darkgate_ips: list[str] = []
        self.cryptojack_pools: list[str] = []
        self.cryptojack_ips: list[str] = []
        self.ransomsim_ips: list[str] = []
        self.phishkit_domains: list[str] = []
        self.phishkit_proxy_ips: list[str] = []
        self.snakebyte_domains: list[str] = []
        self.snakebyte_ips: list[str] = []

    def set_iocs(self, campaigns: dict[str, Any]) -> None:
        td = campaigns.get("terndoor", {})
        self.terndoor_c2_ips = td.get("c2_ips", [])
        be = campaigns.get("bruteentry", {})
        self.bruteentry_ips = be.get("orb_ips", [])
        pt = campaigns.get("peertime", {})
        self.peertime_domains = pt.get("domains", [])
        self.peertime_ips = pt.get("c2_ips", [])
        cs = campaigns.get("cobaltstrike", {})
        self.cobaltstrike_domains = cs.get("c2_domains", [])
        self.cobaltstrike_ips = cs.get("c2_ips", [])
        dg = campaigns.get("darkgate", {})
        self.darkgate_ips = dg.get("c2_ips", [])
        cj = campaigns.get("cryptojack", {})
        self.cryptojack_pools = cj.get("mining_pools", [])
        self.cryptojack_ips = cj.get("c2_ips", [])
        rs = campaigns.get("ransomsim", {})
        self.ransomsim_ips = rs.get("c2_ips", [])
        pk = campaigns.get("phishkit", {})
        self.phishkit_domains = pk.get("phish_domains", [])
        self.phishkit_proxy_ips = pk.get("proxy_ips", [])
        sb = campaigns.get("snakebyte", {})
        self.snakebyte_domains = sb.get("c2_domains", [])
        self.snakebyte_ips = sb.get("c2_ips", [])

    def random_windows_host(self) -> WindowsHost:
        return self.rng.choice(self.windows_hosts)

    def random_linux_host(self) -> LinuxHost:
        return self.rng.choice(self.linux_hosts)

    def random_user(self) -> User:
        return self.rng.choice(self.users)

    def random_admin_user(self) -> User:
        return self.rng.choice(self.admin_users)

    def random_firewall(self) -> Firewall:
        return self.rng.choice(self.firewalls)

    def random_domain_controller(self) -> WindowsHost:
        return self.rng.choice(self.domain_controllers) if self.domain_controllers else self.random_windows_host()

    def random_file_server(self) -> WindowsHost:
        return self.rng.choice(self.file_servers) if self.file_servers else self.random_windows_host()

    def random_dmz_server(self, role: Optional[str] = None) -> DMZServer:
        pool = [s for s in self.dmz_servers if s.role == role] if role else self.dmz_servers
        return self.rng.choice(pool) if pool else self.rng.choice(self.dmz_servers)

    def random_external_ip(self) -> str:
        net = self.rng.choice(self.normal_external_networks)
        hosts = list(net.hosts())
        return str(self.rng.choice(hosts))

    def random_nat_ip(self) -> str:
        start_int = int(self.nat_pool_start)
        end_int = int(self.nat_pool_end)
        return str(IPv4Address(self.rng.randint(start_int, end_int)))

    def random_ephemeral_port(self) -> int:
        return self.rng.randint(49152, 65535)

    def random_guid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128), version=4))

    def random_logon_id(self) -> str:
        return f"0x{self.rng.randint(0x100000, 0xFFFFFF):X}"

    def random_process_id(self) -> int:
        return self.rng.randint(100, 65000)

    def random_mac(self) -> str:
        """Generate a fresh locally-administered MAC address (non-stable)."""
        octets = [0x02] + [self.rng.randint(0x00, 0xFF) for _ in range(5)]
        return ":".join(f"{b:02X}" for b in octets)

    def fqdn(self, hostname: str) -> str:
        return f"{hostname}.{self.dns_fqdn}"
