from __future__ import annotations

from datetime import datetime

from ..formatters.json_fmt import JSONFormatter
from ..formatters.syslog_fmt import CiscoASAFormatter, SyslogFormatter
from ..topology import Topology
from .base import BaseCampaign

SSH_USERS = ["root", "admin", "ubuntu", "ec2-user", "deploy", "postgres", "default", "test", "oracle", "ftpuser", "www-data", "nginx", "backup", "guest", "support"]
TOMCAT_USERS = ["admin", "tomcat", "manager", "role1", "both", "admin123", "root", "deployer"]
PG_USERS = ["postgres", "admin", "dbadmin", "replicator", "app_user", "readonly", "backup"]


class BruteEntryCampaign(BaseCampaign):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.syslog_fmt = SyslogFormatter()
        self.asa_fmt = CiscoASAFormatter()
        self.json_fmt = JSONFormatter()

    @property
    def total_phases(self) -> int:
        return 3

    def generate(self, ts: datetime) -> dict[str, list[str]]:
        phase = self.advance_phase()
        orb_ip = self.rng.choice(self.topo.bruteentry_ips) if self.topo.bruteentry_ips else "212.11.64.105"

        if phase == 0:
            return self._ssh_brute(ts, orb_ip)
        elif phase == 1:
            return self._tomcat_brute(ts, orb_ip)
        else:
            return self._postgres_brute(ts, orb_ip)

    def _ssh_brute(self, ts, orb_ip):
        target = self.topo.random_linux_host()
        attempts = self.rng.randint(8, 25)
        pid = self.rng.randint(10000, 65000)
        port = self.rng.randint(40000, 60000)

        linux_lines = []
        for i in range(attempts):
            user = self.rng.choice(SSH_USERS)
            if self.rng.random() < 0.30:
                msg = f"Invalid user {user} from {orb_ip} port {port} ssh2"
            else:
                msg = f"Failed password for {user} from {orb_ip} port {port} ssh2"
            linux_lines.append(self.syslog_fmt.format(ts, hostname=target.hostname, process="sshd", pid=pid, message=msg))

        linux_lines.append(self.syslog_fmt.format(
            ts, hostname=target.hostname, process="sshd", pid=pid,
            message=f"Disconnected from {orb_ip} port {port} [preauth]",
        ))

        fw = self.topo.random_firewall()
        asa_line = self.asa_fmt.format(
            ts, hostname=fw.hostname, severity=4, message_id="106023",
            message=f"Deny tcp src outside:{orb_ip}/{self.topo.random_ephemeral_port()} dst inside:{target.ip}/22 by access-group \"outside_access_in\" [0x0, 0x0]",
        )

        dns_data = {
            "host_addr": [],
            "message_type": ["QUERY", "RESPONSE"],
            "name": [orb_ip],
            "query": [orb_ip],
            "query_type": ["PTR"],
            "reply_code": "NXDomain",
            "reply_code_id": 3,
            "response_time": self.rng.randint(5000, 15000),
            "transaction_id": self.rng.randint(1000, 65535),
            "ttl": [0],
            "bytes": 60,
            "src_ip": target.ip,
            "src_port": self.topo.random_ephemeral_port(),
            "bytes_in": 30,
            "dest_ip": self.topo.dns_server_ip,
            "dest_port": 53,
            "bytes_out": 30,
            "time_taken": self.rng.randint(5000, 15000),
            "transport": "udp",
            "flow_id": self.topo.random_guid(),
            "protocol_stack": "ip:udp:dns",
        }
        dns_line = self.json_fmt.format(ts, data=dns_data)

        return {"linux_secure": linux_lines, "cisco:asa": [asa_line], "dns": [dns_line]}

    def _tomcat_brute(self, ts, orb_ip):
        dmz = self.topo.random_dmz_server("tomcat")
        attempts = self.rng.randint(5, 15)

        http_lines = []
        for i in range(attempts):
            user = self.rng.choice(TOMCAT_USERS)
            is_last = i == attempts - 1
            status = 200 if is_last and self.rng.random() < 0.15 else 401
            method = self.rng.choice(["POST", "GET"])
            dest_port = self.rng.choice([8080, 8443, 80])

            data = {
                "bytes": self.rng.randint(400, 1200),
                "src_ip": orb_ip,
                "src_port": self.topo.random_ephemeral_port(),
                "bytes_in": self.rng.randint(200, 600),
                "dest_ip": dmz.ip,
                "dest_port": dest_port,
                "bytes_out": self.rng.randint(200, 600),
                "time_taken": self.rng.randint(10000, 80000),
                "transport": "tcp",
                "flow_id": self.topo.random_guid(),
                "http_method": method,
                "status": status,
                "uri_path": "/manager/html",
                "site": self.topo.fqdn(dmz.hostname),
                "http_user_agent": "Mozilla/5.0 (compatible; brute-force-server-v1.0)",
                "http_content_type": "text/html",
                "http_comment": f"HTTP/1.1 {status} {'OK' if status == 200 else 'Unauthorized'}",
                "server": "Apache-Coyote/1.1",
                "protocol_stack": "ip:tcp:http",
            }
            http_lines.append(self.json_fmt.format(ts, data=data))

        fw = self.topo.random_firewall()
        asa_line = self.asa_fmt.format(
            ts, hostname=fw.hostname, severity=6, message_id="302013",
            message=(
                f"Built inbound TCP connection {fw.next_conn_id()} for outside:{orb_ip}/{self.topo.random_ephemeral_port()} "
                f"({orb_ip}/{self.topo.random_ephemeral_port()}) to dmz:{dmz.ip}/8080 ({dmz.ip}/8080)"
            ),
        )

        return {"http": http_lines, "cisco:asa": [asa_line]}

    def _postgres_brute(self, ts, orb_ip):
        target = self.topo.random_linux_host()
        attempts = self.rng.randint(5, 15)
        pid = self.rng.randint(10000, 65000)

        fw = self.topo.random_firewall()
        asa_lines = []
        for _ in range(attempts):
            asa_lines.append(self.asa_fmt.format(
                ts, hostname=fw.hostname, severity=4, message_id="106023",
                message=f"Deny tcp src outside:{orb_ip}/{self.topo.random_ephemeral_port()} dst inside:{target.ip}/5432 by access-group \"outside_access_in\" [0x0, 0x0]",
            ))

        linux_lines = []
        for _ in range(min(attempts, 5)):
            user = self.rng.choice(PG_USERS)
            msg = f"Connection matched pg_hba.conf reject line: host all {user} {orb_ip}/32 reject"
            linux_lines.append(self.syslog_fmt.format(ts, hostname=target.hostname, process="postgres", pid=pid, message=msg))

        return {"cisco:asa": asa_lines, "linux_secure": linux_lines}
