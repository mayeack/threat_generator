from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from threatgen.engine.llm.cache import VariationCache

from ..formatters.wineventlog_fmt import WinEventLogFormatter
from ..topology import Topology
from .base import BaseGenerator

EVENTS = [
    (4624, 40, "Logon", "Audit Success"),
    (4625, 5, "Logon", "Audit Failure"),
    (4634, 20, "Logoff", "Audit Success"),
    (4672, 10, "Special Logon", "Audit Success"),
    (4688, 20, "Process Creation", "Audit Success"),
    (4738, 2, "User Account Management", "Audit Success"),
]

EVENT_IDS = [e[0] for e in EVENTS]
EVENT_WEIGHTS = [e[1] for e in EVENTS]
EVENT_MAP = {e[0]: (e[2], e[3]) for e in EVENTS}

LOGON_TYPES = {2: "Interactive", 3: "Network", 5: "Service", 7: "Unlock", 10: "RemoteInteractive"}

PROCESS_PATHS = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\conhost.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Program Files\Windows Defender\MsMpEng.exe",
    r"C:\Windows\System32\taskhostw.exe",
    r"C:\Windows\System32\RuntimeBroker.exe",
]

PRIVILEGES = [
    "SeSecurityPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege", "SeDebugPrivilege", "SeSystemEnvironmentPrivilege",
    "SeLoadDriverPrivilege", "SeImpersonatePrivilege",
]

LOGON_PROCESSES = ["User32", "Advapi", "NtLmSsp", "Kerberos", "Negotiate"]
AUTH_PACKAGES = ["Negotiate", "Kerberos", "NTLM"]


class WinEventLogGenerator(BaseGenerator):
    sourcetype = "wineventlog"

    def __init__(self, topology: Topology, cache: Optional[VariationCache] = None) -> None:
        super().__init__(topology, cache)
        self.fmt = WinEventLogFormatter()
        self._record_number = self.rng.randint(100000, 999999)

    def _next_record(self) -> int:
        self._record_number += 1
        return self._record_number

    def _generate_pattern(self, ts: datetime) -> list[str]:
        event_id = self.rng.choices(EVENT_IDS, weights=EVENT_WEIGHTS, k=1)[0]
        task_category, keywords = EVENT_MAP[event_id]

        host = self.topo.random_windows_host()
        computer = self.topo.fqdn(host.hostname)

        if event_id == 4624:
            msg = self._logon(ts, host)
        elif event_id == 4625:
            msg = self._failed_logon(ts, host)
        elif event_id == 4634:
            msg = self._logoff(ts, host)
        elif event_id == 4672:
            msg = self._special_logon(ts, host)
        elif event_id == 4688:
            msg = self._process_create(ts, host)
        else:
            msg = self._account_changed(ts, host)

        line = self.fmt.format(
            ts,
            event_code=event_id,
            computer=computer,
            task_category=task_category,
            keywords=keywords,
            message=msg,
            record_number=self._next_record(),
        )
        return [line]

    def _logon(self, ts: datetime, host) -> str:
        user = self.topo.random_user()
        logon_type = self.rng.choice(list(LOGON_TYPES.keys()))
        src_ip = self.topo.random_external_ip() if logon_type == 10 else host.ip
        logon_id = self.topo.random_logon_id()
        logon_process = self.rng.choice(LOGON_PROCESSES)
        auth_package = self.rng.choice(AUTH_PACKAGES)
        return (
            "An account was successfully logged on.\n"
            "\n"
            "Subject:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            "\n"
            f"Logon Type:\t\t\t{logon_type}\n"
            "\n"
            "New Logon:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            f"\tLogon GUID:\t\t{self.topo.random_guid()}\n"
            "\n"
            "Network Information:\n"
            f"\tWorkstation Name:\t{host.hostname}\n"
            f"\tSource Network Address:\t{src_ip}\n"
            f"\tSource Port:\t\t{self.topo.random_ephemeral_port()}\n"
            "\n"
            "Detailed Authentication Information:\n"
            f"\tLogon Process:\t\t{logon_process}\n"
            f"\tAuthentication Package:\t{auth_package}\n"
            "\tTransited Services:\t-\n"
            "\tPackage Name (NTLM only):\t-\n"
            "\tKey Length:\t\t0"
        )

    def _failed_logon(self, ts: datetime, host) -> str:
        user = self.topo.random_user()
        src_ip = self.topo.random_external_ip()
        caller_pid = self.topo.random_process_id()
        return (
            "An account failed to log on.\n"
            "\n"
            "Subject:\n"
            "\tSecurity ID:\t\tS-1-0-0\n"
            "\tAccount Name:\t\t-\n"
            "\tAccount Domain:\t\t-\n"
            "\tLogon ID:\t\t0x0\n"
            "\n"
            "Logon Type:\t\t\t3\n"
            "\n"
            "Account For Which Logon Failed:\n"
            f"\tSecurity ID:\t\tS-1-0-0\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            "\n"
            "Failure Information:\n"
            "\tFailure Reason:\t\tUnknown user name or bad password.\n"
            "\tStatus:\t\t\t0xC000006D\n"
            "\tSub Status:\t\t0xC000006A\n"
            "\n"
            "Process Information:\n"
            f"\tCaller Process ID:\t0x{caller_pid:X}\n"
            f"\tCaller Process Name:\tC:\\Windows\\System32\\svchost.exe\n"
            "\n"
            "Network Information:\n"
            f"\tWorkstation Name:\t{host.hostname}\n"
            f"\tSource Network Address:\t{src_ip}\n"
            f"\tSource Port:\t\t{self.topo.random_ephemeral_port()}\n"
            "\n"
            "Detailed Authentication Information:\n"
            "\tLogon Process:\t\tNtLmSsp\n"
            "\tAuthentication Package:\tNTLM\n"
            "\tTransited Services:\t-\n"
            "\tPackage Name (NTLM only):\t-\n"
            "\tKey Length:\t\t0"
        )

    def _logoff(self, ts: datetime, host) -> str:
        user = self.topo.random_user()
        logon_type = self.rng.choice([2, 3, 7])
        logon_id = self.topo.random_logon_id()
        return (
            "An account was logged off.\n"
            "\n"
            "Subject:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            "\n"
            f"Logon Type:\t\t\t{logon_type}"
        )

    def _special_logon(self, ts: datetime, host) -> str:
        user = self.topo.random_admin_user()
        logon_id = self.topo.random_logon_id()
        privs = self.rng.sample(PRIVILEGES, k=self.rng.randint(2, 5))
        priv_list = "\n\t\t\t".join(privs)
        return (
            "Special privileges assigned to new logon.\n"
            "\n"
            "Subject:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            "\n"
            f"Privileges:\t\t\t{priv_list}"
        )

    def _process_create(self, ts: datetime, host) -> str:
        user = self.topo.random_user()
        proc = self.rng.choice(PROCESS_PATHS)
        parent = self.rng.choice(PROCESS_PATHS)
        pid = self.topo.random_process_id()
        ppid = self.topo.random_process_id()
        logon_id = self.topo.random_logon_id()
        token_type = self.rng.choice(["%%1936", "%%1937", "%%1938"])
        return (
            "A new process has been created.\n"
            "\n"
            "Creator Subject:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            "\n"
            "Target Subject:\n"
            "\tSecurity ID:\t\tS-1-0-0\n"
            "\tAccount Name:\t\t-\n"
            "\tAccount Domain:\t\t-\n"
            "\tLogon ID:\t\t0x0\n"
            "\n"
            "Process Information:\n"
            f"\tNew Process ID:\t\t0x{pid:X}\n"
            f"\tNew Process Name:\t{proc}\n"
            f"\tToken Elevation Type:\t{token_type}\n"
            f"\tMandatory Label:\tS-1-16-8192\n"
            f"\tCreator Process ID:\t0x{ppid:X}\n"
            f"\tCreator Process Name:\t{parent}\n"
            f"\tProcess Command Line:\t{proc}"
        )

    def _account_changed(self, ts: datetime, host) -> str:
        admin = self.topo.random_admin_user()
        target = self.topo.random_user()
        logon_id = self.topo.random_logon_id()
        return (
            "A user account was changed.\n"
            "\n"
            "Subject:\n"
            f"\tSecurity ID:\t\t{admin.sid}\n"
            f"\tAccount Name:\t\t{admin.username}\n"
            f"\tAccount Domain:\t\t{admin.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            "\n"
            "Target Account:\n"
            f"\tSecurity ID:\t\t{target.sid}\n"
            f"\tAccount Name:\t\t{target.username}\n"
            f"\tAccount Domain:\t\t{target.domain}"
        )

    def render_from_scenario(self, scenario: dict[str, Any], ts: datetime) -> list[str]:
        event_id = int(scenario.get("event_code", 4624))
        if event_id not in EVENT_MAP:
            event_id = 4624
        task_category, keywords = EVENT_MAP[event_id]

        host = self.topo.random_windows_host()
        computer = self.topo.fqdn(host.hostname)

        if event_id == 4624:
            msg = self._scenario_logon(scenario, host)
        elif event_id == 4625:
            msg = self._scenario_failed_logon(scenario, host)
        elif event_id == 4634:
            msg = self._logoff(ts, host)
        elif event_id == 4672:
            msg = self._scenario_special_logon(scenario)
        elif event_id == 4688:
            msg = self._scenario_process_create(scenario, host)
        elif event_id == 4738:
            msg = self._account_changed(ts, host)
        else:
            msg = self._logon(ts, host)

        line = self.fmt.format(
            ts,
            event_code=event_id,
            computer=computer,
            task_category=task_category,
            keywords=keywords,
            message=msg,
            record_number=self._next_record(),
        )
        return [line]

    def _scenario_logon(self, scenario: dict[str, Any], host) -> str:
        user = self.topo.random_admin_user() if scenario.get("use_admin_user") else self.topo.random_user()
        logon_type = int(scenario.get("logon_type", self.rng.choice(list(LOGON_TYPES.keys()))))
        if logon_type not in LOGON_TYPES:
            logon_type = 3
        use_external = bool(scenario.get("external_source")) or logon_type == 10
        src_ip = self.topo.random_external_ip() if use_external else host.ip
        logon_id = self.topo.random_logon_id()
        logon_process = str(scenario.get("logon_process") or self.rng.choice(LOGON_PROCESSES))[:32]
        auth_package = str(scenario.get("auth_package") or self.rng.choice(AUTH_PACKAGES))[:32]
        return (
            "An account was successfully logged on.\n"
            "\n"
            "Subject:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            "\n"
            f"Logon Type:\t\t\t{logon_type}\n"
            "\n"
            "New Logon:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            f"\tLogon GUID:\t\t{self.topo.random_guid()}\n"
            "\n"
            "Network Information:\n"
            f"\tWorkstation Name:\t{host.hostname}\n"
            f"\tSource Network Address:\t{src_ip}\n"
            f"\tSource Port:\t\t{self.topo.random_ephemeral_port()}\n"
            "\n"
            "Detailed Authentication Information:\n"
            f"\tLogon Process:\t\t{logon_process}\n"
            f"\tAuthentication Package:\t{auth_package}\n"
            "\tTransited Services:\t-\n"
            "\tPackage Name (NTLM only):\t-\n"
            "\tKey Length:\t\t0"
        )

    def _scenario_failed_logon(self, scenario: dict[str, Any], host) -> str:
        user = self.topo.random_user()
        use_external = scenario.get("external_source", True)
        src_ip = self.topo.random_external_ip() if use_external else host.ip
        caller_pid = self.topo.random_process_id()
        reason = str(scenario.get("failure_reason") or "Unknown user name or bad password.")[:128]
        return (
            "An account failed to log on.\n"
            "\n"
            "Subject:\n"
            "\tSecurity ID:\t\tS-1-0-0\n"
            "\tAccount Name:\t\t-\n"
            "\tAccount Domain:\t\t-\n"
            "\tLogon ID:\t\t0x0\n"
            "\n"
            "Logon Type:\t\t\t3\n"
            "\n"
            "Account For Which Logon Failed:\n"
            f"\tSecurity ID:\t\tS-1-0-0\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            "\n"
            "Failure Information:\n"
            f"\tFailure Reason:\t\t{reason}\n"
            "\tStatus:\t\t\t0xC000006D\n"
            "\tSub Status:\t\t0xC000006A\n"
            "\n"
            "Process Information:\n"
            f"\tCaller Process ID:\t0x{caller_pid:X}\n"
            f"\tCaller Process Name:\tC:\\Windows\\System32\\svchost.exe\n"
            "\n"
            "Network Information:\n"
            f"\tWorkstation Name:\t{host.hostname}\n"
            f"\tSource Network Address:\t{src_ip}\n"
            f"\tSource Port:\t\t{self.topo.random_ephemeral_port()}\n"
            "\n"
            "Detailed Authentication Information:\n"
            "\tLogon Process:\t\tNtLmSsp\n"
            "\tAuthentication Package:\tNTLM\n"
            "\tTransited Services:\t-\n"
            "\tPackage Name (NTLM only):\t-\n"
            "\tKey Length:\t\t0"
        )

    def _scenario_special_logon(self, scenario: dict[str, Any]) -> str:
        user = self.topo.random_admin_user()
        logon_id = self.topo.random_logon_id()
        scenario_privs = scenario.get("privileges") or []
        clean_privs = [str(p)[:64] for p in scenario_privs if isinstance(p, str)][:8]
        if not clean_privs:
            clean_privs = self.rng.sample(PRIVILEGES, k=self.rng.randint(2, 5))
        priv_list = "\n\t\t\t".join(clean_privs)
        return (
            "Special privileges assigned to new logon.\n"
            "\n"
            "Subject:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            "\n"
            f"Privileges:\t\t\t{priv_list}"
        )

    def _scenario_process_create(self, scenario: dict[str, Any], host) -> str:
        user = self.topo.random_user()
        proc = str(scenario.get("process_path") or self.rng.choice(PROCESS_PATHS))[:260]
        parent = str(scenario.get("parent_process_path") or self.rng.choice(PROCESS_PATHS))[:260]
        command_line = str(scenario.get("command_line") or proc)[:1024]
        command_line = _replace_placeholders(command_line, user=user.username)
        proc = _replace_placeholders(proc, user=user.username)
        parent = _replace_placeholders(parent, user=user.username)
        pid = self.topo.random_process_id()
        ppid = self.topo.random_process_id()
        logon_id = self.topo.random_logon_id()
        token_type = str(scenario.get("token_elevation") or self.rng.choice(["%%1936", "%%1937", "%%1938"]))
        if token_type not in ("%%1936", "%%1937", "%%1938"):
            token_type = "%%1938"
        return (
            "A new process has been created.\n"
            "\n"
            "Creator Subject:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            "\n"
            "Target Subject:\n"
            "\tSecurity ID:\t\tS-1-0-0\n"
            "\tAccount Name:\t\t-\n"
            "\tAccount Domain:\t\t-\n"
            "\tLogon ID:\t\t0x0\n"
            "\n"
            "Process Information:\n"
            f"\tNew Process ID:\t\t0x{pid:X}\n"
            f"\tNew Process Name:\t{proc}\n"
            f"\tToken Elevation Type:\t{token_type}\n"
            f"\tMandatory Label:\tS-1-16-8192\n"
            f"\tCreator Process ID:\t0x{ppid:X}\n"
            f"\tCreator Process Name:\t{parent}\n"
            f"\tProcess Command Line:\t{command_line}"
        )


def _replace_placeholders(value: str, *, user: str) -> str:
    if not isinstance(value, str):
        return str(value)
    return (
        value.replace("<USER>", user)
        .replace("<user>", user)
        .replace("{user}", user)
    )
