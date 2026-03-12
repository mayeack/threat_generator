from __future__ import annotations

from datetime import datetime

from ..formatters.json_fmt import JSONFormatter
from ..formatters.syslog_fmt import CiscoASAFormatter
from ..formatters.sysmon_fmt import SysmonFormatter
from ..formatters.wineventlog_fmt import WinEventLogFormatter
from ..topology import Topology
from .base import BaseCampaign

LOADER_HASHES = [
    "711d9427ee43bc2186b9124f31cba2db5f54ec9a0d56dc2948e1a4377bada289",
    "3c098a687947938e36ab34b9f09a11ebd82d50089cbfe6e237d810faa729f8ff",
    "f36913607356a32ea106103387105c635fa923f8ed98ad0194b66ec79e379a02",
]
PAYLOAD_HASHES = [
    "a5e413456ce9fc60bb44d442b72546e9e4118a61894fbe4b5c56e4dfad6055e3",
    "075b20a21ea6a0d2201a12a049f332ecc61348fc0ad3cfee038c6ad6aa44e744",
    "1f5635a512a923e98a90cdc1b2fb988a2da78706e07e419dae9e1a54dd4d682b",
]
DRIVER_HASH = "2d2ca7d21310b14f5f5641bbf4a9ff4c3e566b1fbbd370034c6844cedc8f0538"


class TernDoorCampaign(BaseCampaign):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.sysmon_fmt = SysmonFormatter()
        self.winevent_fmt = WinEventLogFormatter()
        self.asa_fmt = CiscoASAFormatter()
        self.json_fmt = JSONFormatter()
        self._victim_host = topology.random_windows_host()

    @property
    def total_phases(self) -> int:
        return 5

    def generate(self, ts: datetime) -> dict[str, list[str]]:
        phase = self.advance_phase()
        host = self._victim_host
        computer = self.topo.fqdn(host.hostname)

        if phase == 0:
            return self._dll_sideloading(ts, host, computer)
        elif phase == 1:
            return self._persistence(ts, host, computer)
        elif phase == 2:
            return self._driver_install(ts, host, computer)
        else:
            return self._c2_beacon(ts, host, computer)

    def _dll_sideloading(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")
        dll_hash = self.rng.choice(LOADER_HASHES)

        sysmon_lines = []

        sysmon_lines.append(self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1, data_fields=[
            ("RuleName", "technique_id=T1574.002,technique_name=DLL Side-Loading"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", r"C:\ProgramData\WSPrint\WSPrint.exe"),
            ("CommandLine", r"C:\ProgramData\WSPrint\WSPrint.exe"),
            ("CurrentDirectory", r"C:\ProgramData\WSPrint\\"),
            ("User", f"{host.domain}\\SYSTEM"),
            ("LogonGuid", self.topo.random_guid()),
            ("LogonId", "0x3E7"),
            ("IntegrityLevel", "System"),
            ("Hashes", f"SHA256={self.rng.choice(PAYLOAD_HASHES)}"),
            ("ParentProcessGuid", self.topo.random_guid()),
            ("ParentProcessId", str(self.topo.random_process_id())),
            ("ParentImage", r"C:\Windows\System32\svchost.exe"),
            ("ParentCommandLine", r"C:\Windows\System32\svchost.exe -k netsvcs"),
        ]))

        sysmon_lines.append(self.sysmon_fmt.format(ts, event_id=7, computer=computer, task=7, data_fields=[
            ("RuleName", "technique_id=T1574.002,technique_name=DLL Side-Loading"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", r"C:\ProgramData\WSPrint\WSPrint.exe"),
            ("ImageLoaded", r"C:\ProgramData\WSPrint\BugSplatRc64.dll"),
            ("Hashes", f"SHA256={dll_hash}"),
            ("Signed", "false"),
            ("Signature", "-"),
            ("SignatureStatus", "Unavailable"),
        ]))

        msiexec_pid = self.topo.random_process_id()
        sysmon_lines.append(self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1, data_fields=[
            ("RuleName", "technique_id=T1055,technique_name=Process Injection"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(msiexec_pid)),
            ("Image", r"C:\Windows\System32\msiexec.exe"),
            ("CommandLine", r"C:\Windows\System32\msiexec.exe /V"),
            ("CurrentDirectory", r"C:\Windows\System32\\"),
            ("User", r"NT AUTHORITY\SYSTEM"),
            ("LogonGuid", self.topo.random_guid()),
            ("LogonId", "0x3E7"),
            ("IntegrityLevel", "System"),
            ("Hashes", f"SHA256={self.rng.choice(PAYLOAD_HASHES)}"),
            ("ParentProcessGuid", self.topo.random_guid()),
            ("ParentProcessId", str(self.topo.random_process_id())),
            ("ParentImage", r"C:\ProgramData\WSPrint\WSPrint.exe"),
            ("ParentCommandLine", r"C:\ProgramData\WSPrint\WSPrint.exe"),
        ]))

        win_line = self.winevent_fmt.format(
            ts, event_code=4688, computer=computer,
            task_category="Process Creation", keywords="Audit Success",
            message=(
                f"A new process has been created.\n"
                f"Creator Subject:\n"
                f"  Security ID: S-1-5-18\n"
                f"  Account Name: SYSTEM\n"
                f"  Account Domain: NT AUTHORITY\n"
                f"  Logon ID: 0x3E7\n"
                f"Process Information:\n"
                f"  New Process ID: 0x{self.topo.random_process_id():X}\n"
                f"  New Process Name: C:\\ProgramData\\WSPrint\\WSPrint.exe\n"
                f"  Creator Process ID: 0x{self.topo.random_process_id():X}\n"
                f"  Creator Process Name: C:\\Windows\\System32\\svchost.exe"
            ),
        )

        return {"sysmon": sysmon_lines, "wineventlog": [win_line]}

    def _persistence(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")
        sysmon_lines = []

        win_line = self.winevent_fmt.format(
            ts, event_code=4698, computer=computer,
            task_category="Other Object Access Events", keywords="Audit Success",
            message=(
                f"A scheduled task was created.\n"
                f"Subject:\n"
                f"  Security ID: S-1-5-18\n"
                f"  Account Name: SYSTEM\n"
                f"  Account Domain: NT AUTHORITY\n"
                f"  Logon ID: 0x3E7\n"
                f'Task Name: \\WSPrint\n'
                f'Task Content: schtasks /create /tn WSPrint /tr "C:\\ProgramData\\WSPrint\\WSPrint.exe" /ru "SYSTEM" /sc onstart /F'
            ),
        )

        sysmon_lines.append(self.sysmon_fmt.format(ts, event_id=13, computer=computer, task=13, data_fields=[
            ("RuleName", "technique_id=T1547.001,technique_name=Registry Run Keys"),
            ("EventType", "SetValue"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", r"C:\Windows\System32\msiexec.exe"),
            ("TargetObject", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Default"),
            ("Details", r"C:\ProgramData\WSPrint\WSPrint.exe"),
        ]))

        sysmon_lines.append(self.sysmon_fmt.format(ts, event_id=13, computer=computer, task=13, data_fields=[
            ("RuleName", "technique_id=T1053.005,technique_name=Scheduled Task"),
            ("EventType", "SetValue"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", r"C:\Windows\System32\svchost.exe"),
            ("TargetObject", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WSPrint\Index"),
            ("Details", "DWORD (0x00000000)"),
        ]))

        return {"wineventlog": [win_line], "sysmon": sysmon_lines}

    def _driver_install(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")
        sysmon_lines = []

        sysmon_lines.append(self.sysmon_fmt.format(ts, event_id=11, computer=computer, task=11, data_fields=[
            ("RuleName", "technique_id=T1014,technique_name=Rootkit"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", r"C:\Windows\System32\msiexec.exe"),
            ("TargetFilename", r"C:\Windows\System32\drivers\WSPrint.sys"),
            ("CreationUtcTime", ts_str),
        ]))

        sysmon_lines.append(self.sysmon_fmt.format(ts, event_id=13, computer=computer, task=13, data_fields=[
            ("RuleName", "technique_id=T1543.003,technique_name=Windows Service"),
            ("EventType", "SetValue"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", r"C:\Windows\System32\msiexec.exe"),
            ("TargetObject", r"HKLM\SYSTEM\CurrentControlSet\Services\VMTool\ImagePath"),
            ("Details", r"\??\C:\Windows\System32\drivers\WSPrint.sys"),
        ]))

        return {"sysmon": sysmon_lines}

    def _c2_beacon(self, ts, host, computer):
        c2_ip = self.rng.choice(self.topo.terndoor_c2_ips) if self.topo.terndoor_c2_ips else "154.205.154.82"
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")

        sysmon_line = self.sysmon_fmt.format(ts, event_id=3, computer=computer, task=3, data_fields=[
            ("RuleName", "technique_id=T1071.001,technique_name=Web Protocols"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", r"C:\Windows\System32\msiexec.exe"),
            ("User", r"NT AUTHORITY\SYSTEM"),
            ("Protocol", "tcp"),
            ("Initiated", "true"),
            ("SourceIp", host.ip),
            ("SourceHostname", self.topo.fqdn(host.hostname)),
            ("SourcePort", str(self.topo.random_ephemeral_port())),
            ("DestinationIp", c2_ip),
            ("DestinationHostname", ""),
            ("DestinationPort", "443"),
        ])

        dns_data = {
            "host_addr": [c2_ip],
            "message_type": ["QUERY", "RESPONSE"],
            "name": [c2_ip],
            "query": [c2_ip],
            "query_type": ["A"],
            "reply_code": "NoError",
            "reply_code_id": 0,
            "response_time": self.rng.randint(5000, 20000),
            "transaction_id": self.rng.randint(1000, 65535),
            "ttl": [300],
            "bytes": self.rng.randint(60, 150),
            "src_ip": host.ip,
            "src_port": self.topo.random_ephemeral_port(),
            "bytes_in": 33,
            "dest_ip": self.topo.dns_server_ip,
            "dest_port": 53,
            "bytes_out": self.rng.randint(60, 120),
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

        return {"sysmon": [sysmon_line], "dns": [dns_line], "firewall": [asa_line]}
