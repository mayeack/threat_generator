from __future__ import annotations

import hashlib
from datetime import datetime

from ..formatters.sysmon_fmt import SysmonFormatter
from ..topology import Topology
from .base import BaseGenerator

EVENTS = [
    (1, 35, "ProcessCreate"),
    (3, 25, "NetworkConnect"),
    (7, 20, "ImageLoaded"),
    (11, 15, "FileCreate"),
    (13, 5, "RegistryValueSet"),
]
EVENT_IDS = [e[0] for e in EVENTS]
EVENT_WEIGHTS = [e[1] for e in EVENTS]

PROCESS_TREE = [
    (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe"),
    (r"C:\Windows\explorer.exe", r"C:\Windows\System32\userinit.exe"),
    (r"C:\Windows\System32\conhost.exe", r"C:\Windows\System32\csrss.exe"),
    (r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe", r"C:\Windows\explorer.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\cmd.exe", r"C:\Windows\explorer.exe"),
    (r"C:\Program Files\Windows Defender\MsMpEng.exe", r"C:\Windows\System32\services.exe"),
]

LOADED_DLLS = [
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\KernelBase.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\gdi32.dll",
    r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\System32\msvcrt.dll",
    r"C:\Windows\System32\ws2_32.dll",
]

REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo",
    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
    r"HKCU\Software\Microsoft\Office\16.0\Common\General",
]

TEMP_FILES = [
    r"C:\Users\{user}\AppData\Local\Temp\tmp{rand}.tmp",
    r"C:\Windows\Temp\{rand}.tmp",
    r"C:\Users\{user}\AppData\Local\Microsoft\Windows\INetCache\Content.{rand}",
]

EXTERNAL_DOMAINS = [
    "www.google.com", "login.microsoftonline.com", "outlook.office365.com",
    "s3.amazonaws.com", "cdn.cloudflare.com", "update.microsoft.com",
]


class SysmonGenerator(BaseGenerator):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.fmt = SysmonFormatter()

    def generate(self, ts: datetime) -> list[str]:
        event_id = self.rng.choices(EVENT_IDS, weights=EVENT_WEIGHTS, k=1)[0]
        host = self.topo.random_windows_host()
        computer = self.topo.fqdn(host.hostname)

        if event_id == 1:
            data_fields = self._process_create(ts, host)
        elif event_id == 3:
            data_fields = self._network_connect(ts, host)
        elif event_id == 7:
            data_fields = self._image_loaded(ts, host)
        elif event_id == 11:
            data_fields = self._file_create(ts, host)
        else:
            data_fields = self._registry_value_set(ts, host)

        line = self.fmt.format(ts, event_id=event_id, computer=computer, task=event_id, data_fields=data_fields)
        return [line]

    def _fake_hash(self, seed_str: str) -> str:
        return hashlib.sha256(seed_str.encode()).hexdigest().upper()

    def _process_create(self, ts, host):
        image, parent_image = self.rng.choice(PROCESS_TREE)
        user = self.topo.random_user()
        pid = self.topo.random_process_id()
        ppid = self.topo.random_process_id()
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")
        return [
            ("RuleName", ""),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(pid)),
            ("Image", image),
            ("CommandLine", image),
            ("CurrentDirectory", r"C:\Windows\System32\\"),
            ("User", f"{host.domain}\\{user.username}"),
            ("LogonGuid", self.topo.random_guid()),
            ("LogonId", self.topo.random_logon_id()),
            ("IntegrityLevel", "Medium"),
            ("Hashes", f"SHA256={self._fake_hash(f'{image}{ts_str}')}"),
            ("ParentProcessGuid", self.topo.random_guid()),
            ("ParentProcessId", str(ppid)),
            ("ParentImage", parent_image),
            ("ParentCommandLine", parent_image),
        ]

    def _network_connect(self, ts, host):
        image = self.rng.choice([p[0] for p in PROCESS_TREE])
        user = self.topo.random_user()
        dest_ip = self.topo.random_external_ip()
        dest_domain = self.rng.choice(EXTERNAL_DOMAINS)
        dest_port = self.rng.choice([80, 443])
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")
        return [
            ("RuleName", ""),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", image),
            ("User", f"{host.domain}\\{user.username}"),
            ("Protocol", "tcp"),
            ("Initiated", "true"),
            ("SourceIp", host.ip),
            ("SourceHostname", self.topo.fqdn(host.hostname)),
            ("SourcePort", str(self.topo.random_ephemeral_port())),
            ("DestinationIp", dest_ip),
            ("DestinationHostname", dest_domain),
            ("DestinationPort", str(dest_port)),
        ]

    def _image_loaded(self, ts, host):
        image = self.rng.choice([p[0] for p in PROCESS_TREE])
        dll = self.rng.choice(LOADED_DLLS)
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")
        return [
            ("RuleName", ""),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", image),
            ("ImageLoaded", dll),
            ("Hashes", f"SHA256={self._fake_hash(dll)}"),
            ("Signed", "true"),
            ("Signature", "Microsoft Windows"),
            ("SignatureStatus", "Valid"),
        ]

    def _file_create(self, ts, host):
        user = self.topo.random_user()
        template = self.rng.choice(TEMP_FILES)
        rand_hex = f"{self.rng.randint(0, 0xFFFFFF):06X}"
        target = template.format(user=user.username, rand=rand_hex)
        image = self.rng.choice([p[0] for p in PROCESS_TREE])
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")
        return [
            ("RuleName", ""),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", image),
            ("TargetFilename", target),
            ("CreationUtcTime", ts_str),
        ]

    def _registry_value_set(self, ts, host):
        image = self.rng.choice([p[0] for p in PROCESS_TREE])
        key = self.rng.choice(REGISTRY_KEYS)
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")
        return [
            ("RuleName", ""),
            ("EventType", "SetValue"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", image),
            ("TargetObject", key),
            ("Details", "DWORD (0x00000001)"),
        ]
