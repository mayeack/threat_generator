from __future__ import annotations

from datetime import datetime

from ..formatters.json_fmt import JSONFormatter
from ..formatters.syslog_fmt import CiscoASAFormatter
from ..topology import Topology
from .base import BaseCampaign


class PhishKitCampaign(BaseCampaign):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.asa_fmt = CiscoASAFormatter()
        self.json_fmt = JSONFormatter()

    @property
    def total_phases(self) -> int:
        return 4

    def _pick_domain(self):
        return self.rng.choice(self.topo.phishkit_domains) if self.topo.phishkit_domains else "login-microsoftonline.click"

    def _pick_proxy_ip(self):
        return self.rng.choice(self.topo.phishkit_proxy_ips) if self.topo.phishkit_proxy_ips else "79.137.202.91"

    def generate(self, ts: datetime) -> dict[str, list[str]]:
        phase = self.advance_phase()

        if phase == 0:
            return self._phish_dns_resolve(ts)
        elif phase == 1:
            return self._proxy_traffic(ts)
        elif phase == 2:
            return self._credential_capture(ts)
        else:
            return self._anomalous_access(ts)

    def _phish_dns_resolve(self, ts):
        domain = self._pick_domain()
        proxy_ip = self._pick_proxy_ip()
        host = self.topo.random_windows_host()

        dns_data = {
            "host_addr": [proxy_ip],
            "message_type": ["QUERY", "RESPONSE"],
            "name": [domain],
            "query": [domain],
            "query_type": ["A"],
            "reply_code": "NoError",
            "reply_code_id": 0,
            "response_time": self.rng.randint(5000, 20000),
            "transaction_id": self.rng.randint(1000, 65535),
            "ttl": [60],
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
                f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{proxy_ip}/443 ({proxy_ip}/443)"
            ),
        )

        return {"dns": [dns_line], "cisco:asa": [asa_line]}

    def _proxy_traffic(self, ts):
        domain = self._pick_domain()
        proxy_ip = self._pick_proxy_ip()
        host = self.topo.random_windows_host()
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]

        http_lines = []
        for path in ["/auth/login", "/common/oauth2/authorize", "/auth/complete"]:
            data = {
                "bytes": self.rng.randint(2000, 15000),
                "src_ip": host.ip,
                "src_port": self.topo.random_ephemeral_port(),
                "bytes_in": self.rng.randint(500, 3000),
                "dest_ip": proxy_ip,
                "dest_port": 443,
                "bytes_out": self.rng.randint(2000, 15000),
                "time_taken": self.rng.randint(50000, 300000),
                "transport": "tcp",
                "flow_id": self.topo.random_guid(),
                "http_method": "GET" if "login" in path else "POST",
                "status": 200,
                "uri_path": path,
                "site": domain,
                "http_user_agent": self.rng.choice(user_agents),
                "http_content_type": "text/html",
                "http_comment": "HTTP/1.1 200 OK",
                "server": "nginx",
                "protocol_stack": "ip:tcp:http",
            }
            http_lines.append(self.json_fmt.format(ts, data=data))

        return {"http": http_lines}

    def _credential_capture(self, ts):
        domain = self._pick_domain()
        proxy_ip = self._pick_proxy_ip()
        host = self.topo.random_windows_host()

        http_data = {
            "bytes": self.rng.randint(500, 2000),
            "src_ip": host.ip,
            "src_port": self.topo.random_ephemeral_port(),
            "bytes_in": self.rng.randint(200, 800),
            "dest_ip": proxy_ip,
            "dest_port": 443,
            "bytes_out": self.rng.randint(500, 2000),
            "time_taken": self.rng.randint(100000, 500000),
            "transport": "tcp",
            "flow_id": self.topo.random_guid(),
            "http_method": "POST",
            "status": 302,
            "uri_path": "/common/oauth2/token",
            "site": domain,
            "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "http_content_type": "application/x-www-form-urlencoded",
            "http_comment": "HTTP/1.1 302 Found",
            "server": "nginx",
            "protocol_stack": "ip:tcp:http",
        }
        http_line = self.json_fmt.format(ts, data=http_data)

        fw = self.topo.random_firewall()
        asa_line = self.asa_fmt.format(
            ts, hostname=fw.hostname, severity=6, message_id="302013",
            message=(
                f"Built outbound TCP connection {fw.next_conn_id()} for inside:{host.ip}/{self.topo.random_ephemeral_port()} "
                f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{proxy_ip}/443 ({proxy_ip}/443)"
            ),
        )

        return {"http": [http_line], "cisco:asa": [asa_line]}

    def _anomalous_access(self, ts):
        proxy_ip = self._pick_proxy_ip()
        mail_server = self.topo.random_dmz_server("mail")

        http_lines = []
        for path in ["/owa/auth.owa", "/ews/exchange.asmx", "/api/v2.0/me/messages"]:
            data = {
                "bytes": self.rng.randint(5000, 50000),
                "src_ip": proxy_ip,
                "src_port": self.topo.random_ephemeral_port(),
                "bytes_in": self.rng.randint(500, 2000),
                "dest_ip": mail_server.ip,
                "dest_port": 443,
                "bytes_out": self.rng.randint(5000, 50000),
                "time_taken": self.rng.randint(100000, 500000),
                "transport": "tcp",
                "flow_id": self.topo.random_guid(),
                "http_method": "GET" if "messages" in path else "POST",
                "status": 200,
                "uri_path": path,
                "site": self.topo.fqdn(mail_server.hostname),
                "http_user_agent": "python-requests/2.31.0",
                "http_content_type": "application/json",
                "http_comment": "HTTP/1.1 200 OK",
                "server": "Microsoft-IIS/10.0",
                "protocol_stack": "ip:tcp:http",
            }
            http_lines.append(self.json_fmt.format(ts, data=data))

        fw = self.topo.random_firewall()
        asa_line = self.asa_fmt.format(
            ts, hostname=fw.hostname, severity=4, message_id="106023",
            message=f"Deny tcp src outside:{proxy_ip}/{self.topo.random_ephemeral_port()} dst dmz:{mail_server.ip}/443 by access-group \"outside_access_in\" [0x0, 0x0]",
        )

        return {"http": http_lines, "cisco:asa": [asa_line]}
