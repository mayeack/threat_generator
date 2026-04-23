from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Optional

from threatgen.engine.llm.cache import VariationCache

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

SYSMON_PID = 2084
SYSMON_TID = 3912


class SysmonGenerator(BaseGenerator):
    sourcetype = "sysmon"

    def __init__(self, topology: Topology, cache: Optional[VariationCache] = None) -> None:
        super().__init__(topology, cache)
        self.fmt = SysmonFormatter()
        self._record_id = self.rng.randint(100000, 999999)

    def _next_record(self) -> int:
        self._record_id += 1
        return self._record_id

    def _emit(
        self,
        ts: datetime,
        event_id: int,
        host,
        data_fields: list[tuple[str, str]],
        entities: dict[str, Any],
    ) -> list[str]:
        computer = self.topo.fqdn(host.hostname)
        line = self.fmt.format(
            ts,
            event_id=event_id,
            computer=computer,
            task=event_id,
            data_fields=data_fields,
            record_id=self._next_record(),
            sysmon_pid=SYSMON_PID,
            sysmon_tid=SYSMON_TID,
            nt_host=host.hostname,
            mac=getattr(host, "mac", None),
            **entities,
        )
        return [line]

    def _generate_pattern(self, ts: datetime) -> list[str]:
        event_id = self.rng.choices(EVENT_IDS, weights=EVENT_WEIGHTS, k=1)[0]
        host = self.topo.random_windows_host()

        if event_id == 1:
            data_fields, entities = self._process_create(ts, host)
        elif event_id == 3:
            data_fields, entities = self._network_connect(ts, host)
        elif event_id == 7:
            data_fields, entities = self._image_loaded(ts, host)
        elif event_id == 11:
            data_fields, entities = self._file_create(ts, host)
        else:
            data_fields, entities = self._registry_value_set(ts, host)

        return self._emit(ts, event_id, host, data_fields, entities)

    def _fake_hash(self, seed_str: str) -> str:
        return hashlib.sha256(seed_str.encode()).hexdigest().upper()

    def _process_create(self, ts, host) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        image, parent_image = self.rng.choice(PROCESS_TREE)
        user = self.topo.random_user()
        pid = self.topo.random_process_id()
        ppid = self.topo.random_process_id()
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        fields = [
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
        return fields, {"user": user.username, "user_id": user.username}

    def _network_connect(self, ts, host) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        image = self.rng.choice([p[0] for p in PROCESS_TREE])
        user = self.topo.random_user()
        dest_ip = self.topo.random_external_ip()
        dest_domain = self.rng.choice(EXTERNAL_DOMAINS)
        dest_port = self.rng.choice([80, 443])
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        fields = [
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
        return fields, {
            "user": user.username,
            "user_id": user.username,
            "src_ip": host.ip,
            "dest_ip": dest_ip,
        }

    def _image_loaded(self, ts, host) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        image = self.rng.choice([p[0] for p in PROCESS_TREE])
        dll = self.rng.choice(LOADED_DLLS)
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        fields = [
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
        return fields, {}

    def _file_create(self, ts, host) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        user = self.topo.random_user()
        template = self.rng.choice(TEMP_FILES)
        rand_hex = f"{self.rng.randint(0, 0xFFFFFF):06X}"
        target = template.format(user=user.username, rand=rand_hex)
        image = self.rng.choice([p[0] for p in PROCESS_TREE])
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        fields = [
            ("RuleName", ""),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", image),
            ("TargetFilename", target),
            ("CreationUtcTime", ts_str),
        ]
        return fields, {"user": user.username, "user_id": user.username}

    def _registry_value_set(self, ts, host) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        image = self.rng.choice([p[0] for p in PROCESS_TREE])
        key = self.rng.choice(REGISTRY_KEYS)
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        fields = [
            ("RuleName", ""),
            ("EventType", "SetValue"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", image),
            ("TargetObject", key),
            ("Details", "DWORD (0x00000001)"),
        ]
        return fields, {}

    def render_from_scenario(self, scenario: dict[str, Any], ts: datetime) -> list[str]:
        event_id = int(scenario.get("event_id", 1))
        if event_id not in (1, 3, 7, 11, 13):
            event_id = 1
        host = self.topo.random_windows_host()

        if event_id == 1:
            data_fields, entities = self._scenario_process_create(scenario, ts, host)
        elif event_id == 3:
            data_fields, entities = self._scenario_network_connect(scenario, ts, host)
        elif event_id == 7:
            data_fields, entities = self._scenario_image_loaded(scenario, ts)
        elif event_id == 11:
            data_fields, entities = self._scenario_file_create(scenario, ts, host)
        else:
            data_fields, entities = self._scenario_registry_value_set(scenario, ts)

        return self._emit(ts, event_id, host, data_fields, entities)

    def _scenario_process_create(self, scenario, ts, host) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        user = self.topo.random_user()
        image = _safe_path(scenario.get("image"), user, self.rng.choice([p[0] for p in PROCESS_TREE]))
        parent = _safe_path(scenario.get("parent_image"), user, self.rng.choice([p[1] for p in PROCESS_TREE]))
        command_line = _safe_path(scenario.get("command_line"), user, image)
        parent_cmd = _safe_path(scenario.get("parent_command_line"), user, parent)
        cur_dir = _safe_path(scenario.get("current_directory"), user, r"C:\Windows\System32\\")
        integrity = str(scenario.get("integrity_level") or "Medium")[:16]
        if integrity not in ("Low", "Medium", "High", "System"):
            integrity = "Medium"
        rule_name = str(scenario.get("rule_name") or "")[:256]
        pid = self.topo.random_process_id()
        ppid = self.topo.random_process_id()
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        fields = [
            ("RuleName", rule_name),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(pid)),
            ("Image", image),
            ("CommandLine", command_line),
            ("CurrentDirectory", cur_dir),
            ("User", f"{host.domain}\\{user.username}"),
            ("LogonGuid", self.topo.random_guid()),
            ("LogonId", self.topo.random_logon_id()),
            ("IntegrityLevel", integrity),
            ("Hashes", f"SHA256={self._fake_hash(f'{image}{ts_str}')}"),
            ("ParentProcessGuid", self.topo.random_guid()),
            ("ParentProcessId", str(ppid)),
            ("ParentImage", parent),
            ("ParentCommandLine", parent_cmd),
        ]
        return fields, {"user": user.username, "user_id": user.username}

    def _scenario_network_connect(self, scenario, ts, host) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        user = self.topo.random_user()
        image = _safe_path(scenario.get("image"), user, self.rng.choice([p[0] for p in PROCESS_TREE]))
        use_external = bool(scenario.get("use_external_destination", True))
        dest_ip = self.topo.random_external_ip() if use_external else self.topo.random_linux_host().ip
        dest_domain = str(scenario.get("destination_domain") or self.rng.choice(EXTERNAL_DOMAINS))[:253]
        dest_port = int(scenario.get("destination_port") or 443)
        if not 1 <= dest_port <= 65535:
            dest_port = 443
        protocol = str(scenario.get("protocol") or "tcp")
        if protocol not in ("tcp", "udp"):
            protocol = "tcp"
        rule_name = str(scenario.get("rule_name") or "")[:256]
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        fields = [
            ("RuleName", rule_name),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", image),
            ("User", f"{host.domain}\\{user.username}"),
            ("Protocol", protocol),
            ("Initiated", "true"),
            ("SourceIp", host.ip),
            ("SourceHostname", self.topo.fqdn(host.hostname)),
            ("SourcePort", str(self.topo.random_ephemeral_port())),
            ("DestinationIp", dest_ip),
            ("DestinationHostname", dest_domain),
            ("DestinationPort", str(dest_port)),
        ]
        return fields, {
            "user": user.username,
            "user_id": user.username,
            "src_ip": host.ip,
            "dest_ip": dest_ip,
        }

    def _scenario_image_loaded(self, scenario, ts) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        image = _safe_path(scenario.get("image"), None, self.rng.choice([p[0] for p in PROCESS_TREE]))
        dll = _safe_path(scenario.get("loaded_dll"), None, self.rng.choice(LOADED_DLLS))
        signed = bool(scenario.get("dll_signed", True))
        rule_name = str(scenario.get("rule_name") or "")[:256]
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        fields = [
            ("RuleName", rule_name),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", image),
            ("ImageLoaded", dll),
            ("Hashes", f"SHA256={self._fake_hash(dll)}"),
            ("Signed", "true" if signed else "false"),
            ("Signature", "Microsoft Windows" if signed else "-"),
            ("SignatureStatus", "Valid" if signed else "Unavailable"),
        ]
        return fields, {}

    def _scenario_file_create(self, scenario, ts, host) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        user = self.topo.random_user()
        raw = scenario.get("target_filename")
        if raw:
            target = _safe_path(raw, user, raw)
        else:
            template = self.rng.choice(TEMP_FILES)
            rand_hex = f"{self.rng.randint(0, 0xFFFFFF):06X}"
            target = template.format(user=user.username, rand=rand_hex)
        image = _safe_path(scenario.get("image"), user, self.rng.choice([p[0] for p in PROCESS_TREE]))
        rule_name = str(scenario.get("rule_name") or "")[:256]
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        fields = [
            ("RuleName", rule_name),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", image),
            ("TargetFilename", target),
            ("CreationUtcTime", ts_str),
        ]
        return fields, {"user": user.username, "user_id": user.username}

    def _scenario_registry_value_set(self, scenario, ts) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        image = _safe_path(scenario.get("image"), None, self.rng.choice([p[0] for p in PROCESS_TREE]))
        key = str(scenario.get("registry_key") or self.rng.choice(REGISTRY_KEYS))[:260]
        value = str(scenario.get("registry_value") or "DWORD (0x00000001)")[:512]
        rule_name = str(scenario.get("rule_name") or "")[:256]
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        fields = [
            ("RuleName", rule_name),
            ("EventType", "SetValue"),
            ("UtcTime", ts_str),
            ("ProcessGuid", self.topo.random_guid()),
            ("ProcessId", str(self.topo.random_process_id())),
            ("Image", image),
            ("TargetObject", key),
            ("Details", value),
        ]
        return fields, {}


def _safe_path(value, user, default):
    if not isinstance(value, str) or not value.strip():
        return default
    out = value
    username = user.username if user else ""
    out = out.replace("<USER>", username).replace("<user>", username).replace("{user}", username)
    return out[:260]
