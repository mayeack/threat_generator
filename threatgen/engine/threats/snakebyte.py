from __future__ import annotations

import base64
from datetime import datetime

from ..formatters.json_fmt import JSONFormatter
from ..formatters.syslog_fmt import CiscoASAFormatter
from ..formatters.sysmon_fmt import SysmonFormatter
from ..formatters.wineventlog_fmt import WinEventLogFormatter
from ..topology import Topology
from .base import BaseCampaign

SYSMON_PID = 2084
SYSMON_TID = 3912

STAGING_PATHS = [
    r"C:\Users\Public\Libraries\~cache",
    r"C:\ProgramData\Microsoft\Crypto\RSA\tmp",
    r"C:\Windows\Temp\perfmon",
]


class SnakeByteCampaign(BaseCampaign):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.sysmon_fmt = SysmonFormatter()
        self.winevent_fmt = WinEventLogFormatter()
        self.asa_fmt = CiscoASAFormatter()
        self.json_fmt = JSONFormatter()
        self._victim_host = topology.random_windows_host()
        self._sysmon_record_id = self.rng.randint(1000000, 1099999)
        self._winevent_record_number = self.rng.randint(1100000, 1199999)
        self._staging_dir = self.rng.choice(STAGING_PATHS)

    def _next_sysmon_record(self) -> int:
        self._sysmon_record_id += 1
        return self._sysmon_record_id

    def _next_winevent_record(self) -> int:
        self._winevent_record_number += 1
        return self._winevent_record_number

    @property
    def total_phases(self) -> int:
        return 4

    def _pick_c2_domain(self):
        return self.rng.choice(self.topo.snakebyte_domains) if self.topo.snakebyte_domains else "ns1.dnsupdate.info"

    def _pick_c2_ip(self):
        return self.rng.choice(self.topo.snakebyte_ips) if self.topo.snakebyte_ips else "185.141.63.120"

    def generate(self, ts: datetime) -> dict[str, list[str]]:
        phase = self.advance_phase()
        host = self._victim_host
        computer = self.topo.fqdn(host.hostname)

        if phase == 0:
            return self._data_collection(ts, host, computer)
        elif phase == 1:
            return self._archive_staging(ts, host, computer)
        elif phase == 2:
            return self._dns_tunnel_exfil(ts, host, computer)
        else:
            return self._https_exfil(ts, host, computer)

    def _data_collection(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

        file_server = self.topo.rng.choice(self.topo.file_servers) if self.topo.file_servers else host

        sysmon_line = self.sysmon_fmt.format(ts, event_id=3, computer=computer, task=3,
            record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
            data_fields=[
                ("RuleName", "technique_id=T1005,technique_name=Data from Local System"),
                ("UtcTime", ts_str),
                ("ProcessGuid", self.topo.random_guid()),
                ("ProcessId", str(self.topo.random_process_id())),
                ("Image", r"C:\Windows\System32\robocopy.exe"),
                ("User", r"NT AUTHORITY\SYSTEM"),
                ("Protocol", "tcp"),
                ("Initiated", "true"),
                ("SourceIp", host.ip),
                ("SourceHostname", computer),
                ("SourcePort", str(self.topo.random_ephemeral_port())),
                ("DestinationIp", file_server.ip),
                ("DestinationHostname", self.topo.fqdn(file_server.hostname)),
                ("DestinationPort", "445"),
            ])

        win_line = self.winevent_fmt.format(
            ts, event_code=5145, computer=computer,
            task_category="Detailed File Share", keywords="Audit Success",
            record_number=self._next_winevent_record(),
            message=(
                "A network share object was checked to see whether client can be granted desired access.\n"
                "\n"
                "Subject:\n"
                "\tSecurity ID:\t\tS-1-5-18\n"
                "\tAccount Name:\t\tSYSTEM\n"
                "\tAccount Domain:\t\tNT AUTHORITY\n"
                "\tLogon ID:\t\t0x3E7\n"
                "\n"
                "Network Information:\n"
                f"\tObject Type:\t\tFile\n"
                f"\tSource Address:\t\t{host.ip}\n"
                "\tSource Port:\t\t445\n"
                "\n"
                f"\tShare Name:\t\t\\\\*\\SYSVOL\n"
                f"\tShare Path:\t\t\\\\{file_server.hostname}\\SYSVOL\n"
                "\tRelative Target Name:\t*"
            ),
        )

        return {"sysmon": [sysmon_line], "wineventlog": [win_line]}

    def _archive_staging(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        archive_name = f"d{self.rng.randint(10000,99999)}.7z"

        sysmon_lines = [
            self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1560.001,technique_name=Archive via Utility"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\Temp\7za.exe"),
                    ("CommandLine", f"7za.exe a -p -mx9 {self._staging_dir}\\{archive_name} {self._staging_dir}\\*.dat"),
                    ("CurrentDirectory", self._staging_dir + "\\"),
                    ("User", r"NT AUTHORITY\SYSTEM"),
                    ("LogonGuid", self.topo.random_guid()),
                    ("LogonId", "0x3E7"),
                    ("IntegrityLevel", "System"),
                    ("Hashes", "SHA256=0"),
                    ("ParentProcessGuid", self.topo.random_guid()),
                    ("ParentProcessId", str(self.topo.random_process_id())),
                    ("ParentImage", r"C:\Windows\System32\cmd.exe"),
                    ("ParentCommandLine", "cmd.exe /c"),
                ]),
            self.sysmon_fmt.format(ts, event_id=11, computer=computer, task=11,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1560.001,technique_name=Archive via Utility"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\Temp\7za.exe"),
                    ("TargetFilename", f"{self._staging_dir}\\{archive_name}"),
                    ("CreationUtcTime", ts_str),
                ]),
        ]

        return {"sysmon": sysmon_lines}

    def _dns_tunnel_exfil(self, ts, host, computer):
        c2_domain = self._pick_c2_domain()
        c2_ip = self._pick_c2_ip()

        dns_lines = []
        for _ in range(self.rng.randint(8, 20)):
            encoded_chunk = base64.b32encode(
                bytes(self.rng.randint(0, 255) for _ in range(self.rng.randint(10, 30)))
            ).decode().rstrip("=").lower()
            subdomain = f"{encoded_chunk}.{c2_domain}"

            dns_data = {
                "host_addr": [c2_ip],
                "message_type": ["QUERY", "RESPONSE"],
                "name": [subdomain],
                "query": [subdomain],
                "query_type": [self.rng.choice(["TXT", "CNAME", "MX"])],
                "reply_code": "NoError",
                "reply_code_id": 0,
                "response_time": self.rng.randint(5000, 30000),
                "transaction_id": self.rng.randint(1000, 65535),
                "ttl": [0],
                "bytes": self.rng.randint(100, 500),
                "src_ip": host.ip,
                "src_port": self.topo.random_ephemeral_port(),
                "bytes_in": self.rng.randint(40, 100),
                "dest_ip": self.topo.dns_server_ip,
                "dest_port": 53,
                "bytes_out": self.rng.randint(100, 500),
                "time_taken": self.rng.randint(5000, 30000),
                "transport": "udp",
                "flow_id": self.topo.random_guid(),
                "protocol_stack": "ip:udp:dns",
            }
            dns_lines.append(self.json_fmt.format(ts, data=dns_data))

        return {"dns": dns_lines}

    def _https_exfil(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        c2_ip = self._pick_c2_ip()

        sysmon_line = self.sysmon_fmt.format(ts, event_id=3, computer=computer, task=3,
            record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
            data_fields=[
                ("RuleName", "technique_id=T1048.001,technique_name=Exfiltration Over Symmetric Encrypted Non-C2 Protocol"),
                ("UtcTime", ts_str),
                ("ProcessGuid", self.topo.random_guid()),
                ("ProcessId", str(self.topo.random_process_id())),
                ("Image", r"C:\Windows\System32\curl.exe"),
                ("User", r"NT AUTHORITY\SYSTEM"),
                ("Protocol", "tcp"),
                ("Initiated", "true"),
                ("SourceIp", host.ip),
                ("SourceHostname", computer),
                ("SourcePort", str(self.topo.random_ephemeral_port())),
                ("DestinationIp", c2_ip),
                ("DestinationHostname", ""),
                ("DestinationPort", "443"),
            ])

        fw = self.topo.random_firewall()
        asa_line = self.asa_fmt.format(
            ts, hostname=fw.hostname, severity=6, message_id="302013",
            message=(
                f"Built outbound TCP connection {fw.next_conn_id()} for inside:{host.ip}/{self.topo.random_ephemeral_port()} "
                f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{c2_ip}/443 ({c2_ip}/443)"
            ),
        )

        return {"sysmon": [sysmon_line], "cisco:asa": [asa_line]}
