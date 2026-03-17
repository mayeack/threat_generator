from __future__ import annotations

from datetime import datetime

from ..formatters.syslog_fmt import CiscoASAFormatter
from ..formatters.sysmon_fmt import SysmonFormatter
from ..formatters.wineventlog_fmt import WinEventLogFormatter
from ..topology import Topology
from .base import BaseCampaign

RANSOM_HASHES = [
    "e5a93e8e5a3b4e6f8a9d0c1b2f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1",
    "b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7",
]

ENCRYPTED_EXTENSIONS = [".locked", ".encrypted", ".crypted", ".enc"]
TARGET_SERVICES = ["vss", "sql", "svc", "memtas", "mepocs", "sophos", "veeam", "backup"]
RANSOM_NOTE_NAMES = ["README_RESTORE.txt", "DECRYPT_FILES.html", "HOW_TO_RECOVER.txt"]

SYSMON_PID = 2084
SYSMON_TID = 3912


class RansomSimCampaign(BaseCampaign):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.sysmon_fmt = SysmonFormatter()
        self.winevent_fmt = WinEventLogFormatter()
        self.asa_fmt = CiscoASAFormatter()
        self._victim_host = topology.random_windows_host()
        self._sysmon_record_id = self.rng.randint(800000, 899999)
        self._winevent_record_number = self.rng.randint(900000, 999999)

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
        return self.rng.choice(self.topo.ransomsim_ips) if self.topo.ransomsim_ips else "193.233.20.57"

    def generate(self, ts: datetime) -> dict[str, list[str]]:
        phase = self.advance_phase()
        host = self._victim_host
        computer = self.topo.fqdn(host.hostname)

        if phase == 0:
            return self._shadow_copy_delete(ts, host, computer)
        elif phase == 1:
            return self._service_stop(ts, host, computer)
        elif phase == 2:
            return self._file_encryption(ts, host, computer)
        else:
            return self._ransom_note_and_callback(ts, host, computer)

    def _shadow_copy_delete(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

        sysmon_lines = [
            self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1490,technique_name=Inhibit System Recovery"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\System32\vssadmin.exe"),
                    ("CommandLine", "vssadmin.exe delete shadows /all /quiet"),
                    ("CurrentDirectory", r"C:\Windows\System32\\"),
                    ("User", r"NT AUTHORITY\SYSTEM"),
                    ("LogonGuid", self.topo.random_guid()),
                    ("LogonId", "0x3E7"),
                    ("IntegrityLevel", "System"),
                    ("Hashes", f"SHA256={self.rng.choice(RANSOM_HASHES)}"),
                    ("ParentProcessGuid", self.topo.random_guid()),
                    ("ParentProcessId", str(self.topo.random_process_id())),
                    ("ParentImage", r"C:\Windows\System32\cmd.exe"),
                    ("ParentCommandLine", r"cmd.exe /c vssadmin.exe delete shadows /all /quiet"),
                ]),
            self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1490,technique_name=Inhibit System Recovery"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\System32\wbem\WMIC.exe"),
                    ("CommandLine", "wmic shadowcopy delete"),
                    ("CurrentDirectory", r"C:\Windows\System32\\"),
                    ("User", r"NT AUTHORITY\SYSTEM"),
                    ("LogonGuid", self.topo.random_guid()),
                    ("LogonId", "0x3E7"),
                    ("IntegrityLevel", "System"),
                    ("Hashes", f"SHA256={self.rng.choice(RANSOM_HASHES)}"),
                    ("ParentProcessGuid", self.topo.random_guid()),
                    ("ParentProcessId", str(self.topo.random_process_id())),
                    ("ParentImage", r"C:\Windows\System32\cmd.exe"),
                    ("ParentCommandLine", "cmd.exe /c wmic shadowcopy delete"),
                ]),
            self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1490,technique_name=Inhibit System Recovery"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\System32\bcdedit.exe"),
                    ("CommandLine", "bcdedit /set {default} recoveryenabled No"),
                    ("CurrentDirectory", r"C:\Windows\System32\\"),
                    ("User", r"NT AUTHORITY\SYSTEM"),
                    ("LogonGuid", self.topo.random_guid()),
                    ("LogonId", "0x3E7"),
                    ("IntegrityLevel", "System"),
                    ("Hashes", f"SHA256={self.rng.choice(RANSOM_HASHES)}"),
                    ("ParentProcessGuid", self.topo.random_guid()),
                    ("ParentProcessId", str(self.topo.random_process_id())),
                    ("ParentImage", r"C:\Windows\System32\cmd.exe"),
                    ("ParentCommandLine", "cmd.exe /c bcdedit /set {default} recoveryenabled No"),
                ]),
        ]

        return {"sysmon": sysmon_lines}

    def _service_stop(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        stopped_services = self.rng.sample(TARGET_SERVICES, min(4, len(TARGET_SERVICES)))

        sysmon_lines = []
        for svc in stopped_services:
            sysmon_lines.append(self.sysmon_fmt.format(ts, event_id=1, computer=computer, task=1,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1489,technique_name=Service Stop"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\System32\net.exe"),
                    ("CommandLine", f"net stop {svc} /y"),
                    ("CurrentDirectory", r"C:\Windows\System32\\"),
                    ("User", r"NT AUTHORITY\SYSTEM"),
                    ("LogonGuid", self.topo.random_guid()),
                    ("LogonId", "0x3E7"),
                    ("IntegrityLevel", "System"),
                    ("Hashes", f"SHA256={self.rng.choice(RANSOM_HASHES)}"),
                    ("ParentProcessGuid", self.topo.random_guid()),
                    ("ParentProcessId", str(self.topo.random_process_id())),
                    ("ParentImage", r"C:\Windows\System32\cmd.exe"),
                    ("ParentCommandLine", f"cmd.exe /c net stop {svc} /y"),
                ]))

        win_lines = []
        for svc in stopped_services:
            win_lines.append(self.winevent_fmt.format(
                ts, event_code=7036, computer=computer,
                task_category="", keywords="Information",
                record_number=self._next_winevent_record(),
                message=f"The {svc} service entered the stopped state.",
            ))

        return {"sysmon": sysmon_lines, "wineventlog": win_lines}

    def _file_encryption(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        ext = self.rng.choice(ENCRYPTED_EXTENSIONS)
        user = self.topo.random_user()
        file_dirs = [
            f"C:\\Users\\{user.username}\\Documents",
            f"C:\\Users\\{user.username}\\Desktop",
            "C:\\Shares\\Finance",
            "C:\\Shares\\HR",
        ]
        file_names = ["report.xlsx", "budget.docx", "contacts.csv", "presentation.pptx", "database.accdb", "notes.txt"]

        sysmon_lines = []
        for _ in range(self.rng.randint(6, 12)):
            dir_path = self.rng.choice(file_dirs)
            fname = self.rng.choice(file_names)
            sysmon_lines.append(self.sysmon_fmt.format(ts, event_id=11, computer=computer, task=11,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1486,technique_name=Data Encrypted for Impact"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\Temp\svchost.exe"),
                    ("TargetFilename", f"{dir_path}\\{fname}{ext}"),
                    ("CreationUtcTime", ts_str),
                ]))

        return {"sysmon": sysmon_lines}

    def _ransom_note_and_callback(self, ts, host, computer):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        c2_ip = self._pick_c2_ip()
        note_name = self.rng.choice(RANSOM_NOTE_NAMES)

        sysmon_lines = [
            self.sysmon_fmt.format(ts, event_id=11, computer=computer, task=11,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1486,technique_name=Data Encrypted for Impact"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\Temp\svchost.exe"),
                    ("TargetFilename", f"C:\\Users\\Public\\Desktop\\{note_name}"),
                    ("CreationUtcTime", ts_str),
                ]),
            self.sysmon_fmt.format(ts, event_id=3, computer=computer, task=3,
                record_id=self._next_sysmon_record(), sysmon_pid=SYSMON_PID, sysmon_tid=SYSMON_TID,
                data_fields=[
                    ("RuleName", "technique_id=T1071.001,technique_name=Web Protocols"),
                    ("UtcTime", ts_str),
                    ("ProcessGuid", self.topo.random_guid()),
                    ("ProcessId", str(self.topo.random_process_id())),
                    ("Image", r"C:\Windows\Temp\svchost.exe"),
                    ("User", r"NT AUTHORITY\SYSTEM"),
                    ("Protocol", "tcp"),
                    ("Initiated", "true"),
                    ("SourceIp", host.ip),
                    ("SourceHostname", computer),
                    ("SourcePort", str(self.topo.random_ephemeral_port())),
                    ("DestinationIp", c2_ip),
                    ("DestinationHostname", ""),
                    ("DestinationPort", "443"),
                ]),
        ]

        fw = self.topo.random_firewall()
        asa_line = self.asa_fmt.format(
            ts, hostname=fw.hostname, severity=6, message_id="302013",
            message=(
                f"Built outbound TCP connection {fw.next_conn_id()} for inside:{host.ip}/{self.topo.random_ephemeral_port()} "
                f"({host.ip}/{self.topo.random_ephemeral_port()}) to outside:{c2_ip}/443 ({c2_ip}/443)"
            ),
        )

        return {"sysmon": sysmon_lines, "firewall": [asa_line]}
