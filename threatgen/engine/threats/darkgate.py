from __future__ import annotations

from datetime import datetime

from ..formatters.syslog_fmt import CiscoASAFormatter
from ..formatters.sysmon_fmt import SysmonFormatter
from ..formatters.wineventlog_fmt import WinEventLogFormatter
from ..topology import Topology
from .base import BaseCampaign

AUTOIT_HASHES = [
    "d7b6c33218b84e4d5a6c55738ccad1fb2fb9a7bf16e3c8c2c21b4a5f0e8d2a93",
    "a19f42e0bc8e7a3e3b1d0c3ea7bd5ef1fce48e210cd2dd35e6a913b0c7e4f88a",
]
MSI_HASHES = [
    "f3e8a71d0b24c65e9d0ca43a6b97e531dacf4b702183a3e6c7d49cf0bae20157",
    "c2d8e35f19a7b4d0e5f68a1c3b09d742e6f1a5b80c347d29eaf5061b8c72d4e3",
]

SYSMON_PID = 2084
SYSMON_TID = 3912


class DarkGateCampaign(BaseCampaign):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.sysmon_fmt = SysmonFormatter()
        self.winevent_fmt = WinEventLogFormatter()
        self.asa_fmt = CiscoASAFormatter()
        self._victim_host = topology.random_windows_host()
        self._sysmon_record_id = self.rng.randint(600000, 699999)
        self._winevent_record_number = self.rng.randint(700000, 799999)

    def _next_sysmon_record(self) -> int:
        self._sysmon_record_id += 1
        return self._sysmon_record_id

    def _next_winevent_record(self) -> int:
        self._winevent_record_number += 1
        return self._winevent_record_number

    @property
    def total_phases(self) -> int:
        return 4

    def _pick_c2_ip(self):
        return self.rng.choice(self.topo.darkgate_ips) if self.topo.darkgate_ips else "5.188.86.114"

    def generate(self, ts: datetime) -> dict[str, list[str]]:
        phase = self.advance_phase()
        host = self._victim_host
        computer = self.topo.fqdn(host.hostname)

        if phase == 0:
            return self._msi_execution(ts, host, computer)
        elif phase == 1:
            return self._autoit_loader(ts, host, computer)
        elif phase == 2:
            return self._credential_harvest(ts, host, computer)
        else:
            return self._exfil_callback(ts, host, computer)

    def _msi_execution(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        user = self.topo.random_user()
        msi_hash = self.rng.choice(MSI_HASHES)
        msi_name = self.rng.choice(["Invoice_2024.msi", "Document_Scan.msi", "Shipment_Details.msi", "Payment_Receipt.msi"])

        sysmon_lines = [
            self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1218.007,technique_name=Msiexec"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\System32\msiexec.exe"),
                    ("CommandLine", f"msiexec.exe /i C:\\Users\\{user.username}\\Downloads\\{msi_name} /qn"),
                    ("CurrentDirectory", f"C:\\Users\\{user.username}\\Downloads\\"),
                    ("User", f"{host.domain}\\{user.username}"),
                    ("LogonGuid", self.topo.random_guid()),
                    ("LogonId", self.topo.random_logon_id()),
                    ("IntegrityLevel", "Medium"),
                    ("Hashes", f"SHA256={msi_hash}"),
                    ("ParentProcessGuid", self.topo.random_guid()),
                    ("ParentProcessId", str(self.topo.random_process_id())),
                    ("ParentImage", r"C:\Windows\explorer.exe"),
                    ("ParentCommandLine", r"C:\Windows\Explorer.EXE"),
                ]),
            self.sysmon_fmt.format(ts, event_id=11, computer=computer, task=11,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1218.007,technique_name=Msiexec"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\System32\msiexec.exe"),
                    ("TargetFilename", f"C:\\Users\\{user.username}\\AppData\\Roaming\\khjld\\Autoit3.exe"),
                    ("CreationUtcTime", ts_str),
                ]),
        ]

        win_line = self.winevent_fmt.format(
            ts, event_code=1040, computer=computer,
            task_category="", keywords="Information",
            record_number=self._next_winevent_record(),
            message=f"Windows Installer transaction: Installation started. Package: C:\\Users\\{user.username}\\Downloads\\{msi_name}",
        )

        return {"sysmon": sysmon_lines, "wineventlog": [win_line]}

    def _autoit_loader(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        user = self.topo.random_user()
        autoit_hash = self.rng.choice(AUTOIT_HASHES)
        script_name = self.rng.choice(["qbkxl.au3", "rvsjm.au3", "wtkpd.au3"])

        sysmon_lines = [
            self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1059.010,technique_name=AutoHotKey and AutoIt"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", f"C:\\Users\\{user.username}\\AppData\\Roaming\\khjld\\Autoit3.exe"),
                    ("CommandLine", f"C:\\Users\\{user.username}\\AppData\\Roaming\\khjld\\Autoit3.exe C:\\Users\\{user.username}\\AppData\\Roaming\\khjld\\{script_name}"),
                    ("CurrentDirectory", f"C:\\Users\\{user.username}\\AppData\\Roaming\\khjld\\"),
                    ("User", f"{host.domain}\\{user.username}"),
                    ("LogonGuid", self.topo.random_guid()),
                    ("LogonId", self.topo.random_logon_id()),
                    ("IntegrityLevel", "Medium"),
                    ("Hashes", f"SHA256={autoit_hash}"),
                    ("ParentProcessGuid", self.topo.random_guid()),
                    ("ParentProcessId", str(self.topo.random_process_id())),
                    ("ParentImage", r"C:\Windows\System32\msiexec.exe"),
                    ("ParentCommandLine", "msiexec.exe /i"),
                ]),
            self.sysmon_fmt.format(ts, event_id=13, computer=computer, task=13,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1547.001,technique_name=Registry Run Keys"),
                    ("EventType", "SetValue"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", f"C:\\Users\\{user.username}\\AppData\\Roaming\\khjld\\Autoit3.exe"),
                    ("TargetObject", f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\khjld"),
                    ("Details", f"C:\\Users\\{user.username}\\AppData\\Roaming\\khjld\\Autoit3.exe {script_name}"),
                ]),
        ]

        return {"sysmon": sysmon_lines}

    def _credential_harvest(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        user = self.topo.random_user()
        browsers = [
            (r"C:\Users\{user}\AppData\Local\Google\Chrome\User Data\Default\Login Data", "Chrome"),
            (r"C:\Users\{user}\AppData\Roaming\Mozilla\Firefox\Profiles\default\logins.json", "Firefox"),
            (r"C:\Users\{user}\AppData\Local\Microsoft\Edge\User Data\Default\Login Data", "Edge"),
        ]
        browser_path, browser_name = self.rng.choice(browsers)
        browser_path = browser_path.replace("{user}", user.username)

        sysmon_lines = [
            self.sysmon_fmt.format(ts, event_id=11, computer=computer, task=11,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1555.003,technique_name=Credentials from Web Browsers"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", f"C:\\Users\\{user.username}\\AppData\\Roaming\\khjld\\Autoit3.exe"),
                    ("TargetFilename", f"C:\\Users\\{user.username}\\AppData\\Local\\Temp\\tmpdb_{self.rng.randint(1000,9999)}.tmp"),
                    ("CreationUtcTime", ts_str),
                ]),
        ]

        win_line = self.winevent_fmt.format(
            ts, event_code=4663, computer=computer,
            task_category="File System", keywords="Audit Success",
            record_number=self._next_winevent_record(),
            message=(
                "An attempt was made to access an object.\n"
                "\n"
                "Subject:\n"
                f"\tSecurity ID:\t\t{user.sid}\n"
                f"\tAccount Name:\t\t{user.username}\n"
                f"\tAccount Domain:\t\t{host.domain}\n"
                f"\tLogon ID:\t\t{self.topo.random_logon_id()}\n"
                "\n"
                "Object:\n"
                f"\tObject Name:\t\t{browser_path}\n"
                "\tHandle ID:\t\t0x1234\n"
                "\n"
                "Process Information:\n"
                f"\tProcess Name:\tC:\\Users\\{user.username}\\AppData\\Roaming\\khjld\\Autoit3.exe\n"
                "\n"
                "Access Request Information:\n"
                "\tAccesses:\t\tReadData (or ListDirectory)"
            ),
        )

        return {"sysmon": sysmon_lines, "wineventlog": [win_line]}

    def _exfil_callback(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        c2_ip = self._pick_c2_ip()

        sysmon_line = self.sysmon_fmt.format(ts, event_id=3, computer=computer, task=3,
            record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
            data_fields=[
                ("RuleName", "technique_id=T1041,technique_name=Exfiltration Over C2 Channel"),
                ("UtcTime", ts_str),
                ("ProcessGuid", self.topo.random_guid()),
                ("ProcessId", str(self.topo.random_process_id())),
                ("Image", r"C:\Users\jsmith\AppData\Roaming\khjld\Autoit3.exe"),
                ("User", f"{host.domain}\\SYSTEM"),
                ("Protocol", "tcp"),
                ("Initiated", "true"),
                ("SourceIp", host.ip),
                ("SourceHostname", computer),
                ("SourcePort", str(self.topo.random_ephemeral_port())),
                ("DestinationIp", c2_ip),
                ("DestinationHostname", ""),
                ("DestinationPort", str(self.rng.choice([80, 443, 8080]))),
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
