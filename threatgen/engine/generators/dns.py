from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from threatgen.engine.llm.cache import VariationCache

from ..formatters.json_fmt import JSONFormatter
from ..topology import Topology
from .base import BaseGenerator

QUERY_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"]
QUERY_WEIGHTS = [60, 10, 8, 5, 5, 4, 3, 5]

REPLY_CODES = ["NoError", "NXDomain", "ServFail", "Refused"]
REPLY_WEIGHTS = [85, 10, 3, 2]
REPLY_CODE_IDS = {"NoError": 0, "NXDomain": 3, "ServFail": 2, "Refused": 5}

EXTERNAL_DOMAINS = [
    "www.google.com", "mail.google.com", "accounts.google.com",
    "login.microsoftonline.com", "outlook.office365.com", "graph.microsoft.com",
    "www.github.com", "api.github.com", "s3.amazonaws.com",
    "cdn.cloudflare.com", "ajax.googleapis.com", "update.microsoft.com",
    "ocsp.digicert.com", "slack-msgs.com", "zoom.us", "ntp.ubuntu.com",
]

INTERNAL_DOMAINS = [
    "dc01.corp.local", "fileserver01.corp.local", "mail.corp.local",
    "intranet.corp.local", "jenkins.corp.local", "gitlab.corp.local",
    "wiki.corp.local", "jira.corp.local",
]


class DNSGenerator(BaseGenerator):
    sourcetype = "stream:dns"

    def __init__(self, topology: Topology, cache: Optional[VariationCache] = None) -> None:
        super().__init__(topology, cache)
        self.fmt = JSONFormatter()

    def _generate_pattern(self, ts: datetime) -> list[str]:
        is_internal = self.rng.random() < 0.30
        domain = self.rng.choice(INTERNAL_DOMAINS if is_internal else EXTERNAL_DOMAINS)
        qtype = self.rng.choices(QUERY_TYPES, weights=QUERY_WEIGHTS, k=1)[0]
        reply_code = self.rng.choices(REPLY_CODES, weights=REPLY_WEIGHTS, k=1)[0]
        ttl = self.rng.choice([60, 120, 300, 600, 3600])
        return self._render(ts, domain, qtype, reply_code, is_internal, ttl)

    def render_from_scenario(self, scenario: dict[str, Any], ts: datetime) -> list[str]:
        domain = str(scenario.get("domain") or self.rng.choice(EXTERNAL_DOMAINS))[:253]
        qtype = str(scenario.get("query_type") or "A")
        if qtype not in QUERY_TYPES:
            qtype = "A"
        reply_code = str(scenario.get("reply_code") or "NoError")
        if reply_code not in REPLY_CODES:
            reply_code = "NoError"
        is_internal = bool(scenario.get("is_internal_domain", False))
        ttl_raw = scenario.get("ttl")
        ttl = int(ttl_raw) if isinstance(ttl_raw, int) and 10 <= ttl_raw <= 86400 else self.rng.choice([60, 300, 3600])
        return self._render(ts, domain, qtype, reply_code, is_internal, ttl)

    def _render(
        self,
        ts: datetime,
        domain: str,
        qtype: str,
        reply_code: str,
        is_internal: bool,
        ttl: int,
    ) -> list[str]:
        if self.rng.random() < 0.7:
            host = self.topo.random_windows_host()
        else:
            host = self.topo.random_linux_host()
        src_ip = host.ip
        resolved_ip = self.topo.dns_server_ip if is_internal else self.topo.random_external_ip()
        response_time = self.rng.randint(1000, 50000)
        txid = self.rng.randint(1000, 65535)
        bytes_in = self.rng.randint(28, 80)
        bytes_out = self.rng.randint(60, 300)

        data = {
            "host_addr": [resolved_ip],
            "message_type": ["QUERY", "RESPONSE"],
            "name": [domain],
            "query": [domain],
            "query_type": [qtype],
            "reply_code": reply_code,
            "reply_code_id": REPLY_CODE_IDS.get(reply_code, 0),
            "response_time": response_time,
            "transaction_id": txid,
            "ttl": [ttl],
            "bytes": bytes_in + bytes_out,
            "src_ip": src_ip,
            "src_port": self.topo.random_ephemeral_port(),
            "bytes_in": bytes_in,
            "dest_ip": self.topo.dns_server_ip,
            "dest_port": 53,
            "bytes_out": bytes_out,
            "time_taken": response_time,
            "transport": "udp",
            "flow_id": self.topo.random_guid(),
            "protocol_stack": "ip:udp:dns",
            "nt_host": host.hostname,
            "mac": getattr(host, "mac", ""),
            "ip": src_ip,
        }

        user = self.topo.random_user()
        data["user"] = user.username
        data["user_id"] = user.username

        line = self.fmt.format(ts, data=data)
        return [line]
