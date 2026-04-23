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
    (4768, 8, "Kerberos Authentication Service", "Audit Success"),
    (4769, 10, "Kerberos Service Ticket Operations", "Audit Success"),
    (5140, 6, "File Share", "Audit Success"),
    (5145, 4, "Detailed File Share", "Audit Success"),
]

DC_EVENT_IDS = {4768, 4769}
FILE_SERVER_EVENT_IDS = {5140, 5145}

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

    def _emit(
        self,
        ts: datetime,
        event_id: int,
        host,
        message: str,
        entities: dict[str, Any],
    ) -> list[str]:
        task_category, keywords = EVENT_MAP[event_id]
        computer = self.topo.fqdn(host.hostname)
        line = self.fmt.format(
            ts,
            event_code=event_id,
            computer=computer,
            task_category=task_category,
            keywords=keywords,
            message=message,
            record_number=self._next_record(),
            nt_host=host.hostname,
            dest_nt_host=host.hostname,
            mac=getattr(host, "mac", None),
            dest_ip=host.ip,
            **entities,
        )
        return [line]

    def _generate_pattern(self, ts: datetime) -> list[str]:
        event_id = self.rng.choices(EVENT_IDS, weights=EVENT_WEIGHTS, k=1)[0]
        host = self._host_for_event(event_id)

        if event_id == 4624:
            msg, entities = self._logon(ts, host)
        elif event_id == 4625:
            msg, entities = self._failed_logon(ts, host)
        elif event_id == 4634:
            msg, entities = self._logoff(ts, host)
        elif event_id == 4672:
            msg, entities = self._special_logon(ts, host)
        elif event_id == 4688:
            msg, entities = self._process_create(ts, host)
        elif event_id == 4738:
            msg, entities = self._account_changed(ts, host)
        elif event_id == 4768:
            msg, entities = self._kerberos_tgt(ts, host)
        elif event_id == 4769:
            msg, entities = self._kerberos_service(ts, host)
        elif event_id == 5140:
            msg, entities = self._share_access(ts, host)
        else:
            msg, entities = self._share_detail(ts, host)

        return self._emit(ts, event_id, host, msg, entities)

    def _host_for_event(self, event_id: int):
        """Pick a host whose role matches the event.

        Kerberos events (4768/4769) must originate on a domain controller and
        SMB share events (5140/5145) must originate on a file server so that
        Exposure Analytics discovers those asset classes via nt_host. All other
        Security events come from regular Windows workstations.
        """
        if event_id in DC_EVENT_IDS:
            return self.topo.random_domain_controller()
        if event_id in FILE_SERVER_EVENT_IDS:
            return self.topo.random_file_server()
        return self.topo.random_windows_host()

    def _logon(self, ts: datetime, host) -> tuple[str, dict[str, Any]]:
        user = self.topo.random_user()
        logon_type = self.rng.choice(list(LOGON_TYPES.keys()))
        src_ip = self.topo.random_external_ip() if logon_type == 10 else host.ip
        logon_id = self.topo.random_logon_id()
        logon_process = self.rng.choice(LOGON_PROCESSES)
        auth_package = self.rng.choice(AUTH_PACKAGES)
        msg = (
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
        return msg, {"user": user.username, "user_id": user.username, "src_ip": src_ip}

    def _failed_logon(self, ts: datetime, host) -> tuple[str, dict[str, Any]]:
        user = self.topo.random_user()
        src_ip = self.topo.random_external_ip()
        caller_pid = self.topo.random_process_id()
        msg = (
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
        return msg, {"user": user.username, "user_id": user.username, "src_ip": src_ip}

    def _logoff(self, ts: datetime, host) -> tuple[str, dict[str, Any]]:
        user = self.topo.random_user()
        logon_type = self.rng.choice([2, 3, 7])
        logon_id = self.topo.random_logon_id()
        msg = (
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
        return msg, {"user": user.username, "user_id": user.username}

    def _special_logon(self, ts: datetime, host) -> tuple[str, dict[str, Any]]:
        user = self.topo.random_admin_user()
        logon_id = self.topo.random_logon_id()
        privs = self.rng.sample(PRIVILEGES, k=self.rng.randint(2, 5))
        priv_list = "\n\t\t\t".join(privs)
        msg = (
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
        return msg, {"user": user.username, "user_id": user.username}

    def _process_create(self, ts: datetime, host) -> tuple[str, dict[str, Any]]:
        user = self.topo.random_user()
        proc = self.rng.choice(PROCESS_PATHS)
        parent = self.rng.choice(PROCESS_PATHS)
        pid = self.topo.random_process_id()
        ppid = self.topo.random_process_id()
        logon_id = self.topo.random_logon_id()
        token_type = self.rng.choice(["%%1936", "%%1937", "%%1938"])
        msg = (
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
        return msg, {"user": user.username, "user_id": user.username}

    def _account_changed(self, ts: datetime, host) -> tuple[str, dict[str, Any]]:
        admin = self.topo.random_admin_user()
        target = self.topo.random_user()
        logon_id = self.topo.random_logon_id()
        msg = (
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
        return msg, {"user": admin.username, "user_id": admin.username}

    def _kerberos_tgt(self, ts: datetime, host) -> tuple[str, dict[str, Any]]:
        """4768: Kerberos TGT request, logged on the domain controller."""
        user = self.topo.random_user()
        client_host = self.topo.random_windows_host()
        src_ip = client_host.ip
        ticket_options = "0x40810010"
        ticket_encryption = self.rng.choice(["0x12", "0x17"])
        msg = (
            "A Kerberos authentication ticket (TGT) was requested.\n"
            "\n"
            "Account Information:\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tSupplied Realm Name:\t{user.domain}\n"
            f"\tUser ID:\t\t\t{user.sid}\n"
            "\n"
            "Service Information:\n"
            "\tService Name:\t\tkrbtgt\n"
            f"\tService ID:\t\tS-1-5-21-3623811015-3361044348-30300820-502\n"
            "\n"
            "Network Information:\n"
            f"\tClient Address:\t\t::ffff:{src_ip}\n"
            f"\tClient Port:\t\t{self.topo.random_ephemeral_port()}\n"
            "\n"
            "Additional Information:\n"
            f"\tTicket Options:\t\t{ticket_options}\n"
            "\tResult Code:\t\t0x0\n"
            f"\tTicket Encryption Type:\t{ticket_encryption}\n"
            "\tPre-Authentication Type:\t2\n"
        )
        return msg, {
            "user": user.username,
            "user_id": user.username,
            "src_ip": src_ip,
            "src_nt_host": client_host.hostname,
        }

    def _kerberos_service(self, ts: datetime, host) -> tuple[str, dict[str, Any]]:
        """4769: Kerberos service ticket request, logged on the domain controller."""
        user = self.topo.random_user()
        client_host = self.topo.random_windows_host()
        target_host = self.topo.random_file_server()
        src_ip = client_host.ip
        ticket_options = "0x40810000"
        ticket_encryption = self.rng.choice(["0x12", "0x17"])
        service_name = f"cifs/{target_host.hostname}.{self.topo.dns_fqdn}"
        msg = (
            "A Kerberos service ticket was requested.\n"
            "\n"
            "Account Information:\n"
            f"\tAccount Name:\t\t{user.username}@{user.domain.upper()}\n"
            f"\tAccount Domain:\t\t{user.domain.upper()}\n"
            f"\tLogon GUID:\t\t{self.topo.random_guid()}\n"
            "\n"
            "Service Information:\n"
            f"\tService Name:\t\t{service_name}\n"
            f"\tService ID:\t\t{user.sid}\n"
            "\n"
            "Network Information:\n"
            f"\tClient Address:\t\t::ffff:{src_ip}\n"
            f"\tClient Port:\t\t{self.topo.random_ephemeral_port()}\n"
            "\n"
            "Additional Information:\n"
            f"\tTicket Options:\t\t{ticket_options}\n"
            f"\tTicket Encryption Type:\t{ticket_encryption}\n"
            "\tFailure Code:\t\t0x0\n"
            "\tTransited Services:\t-"
        )
        return msg, {
            "user": user.username,
            "user_id": user.username,
            "src_ip": src_ip,
            "src_nt_host": client_host.hostname,
        }

    def _share_access(self, ts: datetime, host) -> tuple[str, dict[str, Any]]:
        """5140: A network share object was accessed, logged on the file server."""
        user = self.topo.random_user()
        client_host = self.topo.random_windows_host()
        share_name = self.rng.choice([
            r"\\\\*\\IPC$",
            r"\\\\*\\ADMIN$",
            r"\\\\*\\Finance",
            r"\\\\*\\HR",
            r"\\\\*\\Engineering",
            r"\\\\*\\Shared",
        ])
        share_path = self.rng.choice([
            r"C:\\Windows",
            r"C:\\Shares\\Finance",
            r"C:\\Shares\\HR",
            r"C:\\Shares\\Engineering",
            r"C:\\Shares\\Shared",
        ])
        logon_id = self.topo.random_logon_id()
        access_mask = self.rng.choice(["0x1", "0x100001", "0x120089"])
        msg = (
            "A network share object was accessed.\n"
            "\n"
            "Subject:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            "\n"
            "Network Information:\n"
            f"\tObject Type:\t\tFile\n"
            f"\tSource Address:\t\t{client_host.ip}\n"
            f"\tSource Port:\t\t{self.topo.random_ephemeral_port()}\n"
            "\n"
            "Share Information:\n"
            f"\tShare Name:\t\t{share_name}\n"
            f"\tShare Path:\t\t{share_path}\n"
            f"\tAccess Mask:\t\t{access_mask}\n"
            "\tAccesses:\t\tReadData (or ListDirectory)"
        )
        return msg, {
            "user": user.username,
            "user_id": user.username,
            "src_ip": client_host.ip,
            "src_nt_host": client_host.hostname,
        }

    def _share_detail(self, ts: datetime, host) -> tuple[str, dict[str, Any]]:
        """5145: Detailed file share access check, logged on the file server."""
        user = self.topo.random_user()
        client_host = self.topo.random_windows_host()
        share_name = self.rng.choice([
            r"\\\\*\\Finance",
            r"\\\\*\\HR",
            r"\\\\*\\Engineering",
            r"\\\\*\\Shared",
        ])
        relative_path = self.rng.choice([
            "Reports\\Q4.xlsx",
            "Payroll\\roster.csv",
            "Policies\\handbook.docx",
            "Projects\\roadmap.pptx",
        ])
        logon_id = self.topo.random_logon_id()
        msg = (
            "A network share object was checked to see whether client can be granted desired access.\n"
            "\n"
            "Subject:\n"
            f"\tSecurity ID:\t\t{user.sid}\n"
            f"\tAccount Name:\t\t{user.username}\n"
            f"\tAccount Domain:\t\t{user.domain}\n"
            f"\tLogon ID:\t\t{logon_id}\n"
            "\n"
            "Network Information:\n"
            f"\tObject Type:\t\tFile\n"
            f"\tSource Address:\t\t{client_host.ip}\n"
            f"\tSource Port:\t\t{self.topo.random_ephemeral_port()}\n"
            "\n"
            "Share Information:\n"
            f"\tShare Name:\t\t{share_name}\n"
            f"\tShare Path:\t\t\\\\??\\C:\\Shares\n"
            f"\tRelative Target Name:\t{relative_path}\n"
            "\n"
            "Access Request Information:\n"
            "\tAccess Mask:\t\t0x120089\n"
            "\tAccesses:\t\tReadData (or ListDirectory)\n"
            "\t\t\t\tReadAttributes\n"
            "\tAccess Reasons:\t\t-\n"
            "\tAccess Check Results:\tREAD_CONTROL: Granted by Ownership"
        )
        return msg, {
            "user": user.username,
            "user_id": user.username,
            "src_ip": client_host.ip,
            "src_nt_host": client_host.hostname,
        }

    def render_from_scenario(self, scenario: dict[str, Any], ts: datetime) -> list[str]:
        event_id = int(scenario.get("event_code", 4624))
        if event_id not in EVENT_MAP:
            event_id = 4624

        host = self._host_for_event(event_id)

        if event_id == 4624:
            msg, entities = self._scenario_logon(scenario, host)
        elif event_id == 4625:
            msg, entities = self._scenario_failed_logon(scenario, host)
        elif event_id == 4634:
            msg, entities = self._logoff(ts, host)
        elif event_id == 4672:
            msg, entities = self._scenario_special_logon(scenario)
        elif event_id == 4688:
            msg, entities = self._scenario_process_create(scenario, host)
        elif event_id == 4738:
            msg, entities = self._account_changed(ts, host)
        elif event_id == 4768:
            msg, entities = self._kerberos_tgt(ts, host)
        elif event_id == 4769:
            msg, entities = self._kerberos_service(ts, host)
        elif event_id == 5140:
            msg, entities = self._share_access(ts, host)
        elif event_id == 5145:
            msg, entities = self._share_detail(ts, host)
        else:
            msg, entities = self._logon(ts, host)

        return self._emit(ts, event_id, host, msg, entities)

    def _scenario_logon(self, scenario: dict[str, Any], host) -> tuple[str, dict[str, Any]]:
        user = self.topo.random_admin_user() if scenario.get("use_admin_user") else self.topo.random_user()
        logon_type = int(scenario.get("logon_type", self.rng.choice(list(LOGON_TYPES.keys()))))
        if logon_type not in LOGON_TYPES:
            logon_type = 3
        use_external = bool(scenario.get("external_source")) or logon_type == 10
        src_ip = self.topo.random_external_ip() if use_external else host.ip
        logon_id = self.topo.random_logon_id()
        logon_process = str(scenario.get("logon_process") or self.rng.choice(LOGON_PROCESSES))[:32]
        auth_package = str(scenario.get("auth_package") or self.rng.choice(AUTH_PACKAGES))[:32]
        msg = (
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
        return msg, {"user": user.username, "user_id": user.username, "src_ip": src_ip}

    def _scenario_failed_logon(self, scenario: dict[str, Any], host) -> tuple[str, dict[str, Any]]:
        user = self.topo.random_user()
        use_external = scenario.get("external_source", True)
        src_ip = self.topo.random_external_ip() if use_external else host.ip
        caller_pid = self.topo.random_process_id()
        reason = str(scenario.get("failure_reason") or "Unknown user name or bad password.")[:128]
        msg = (
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
        return msg, {"user": user.username, "user_id": user.username, "src_ip": src_ip}

    def _scenario_special_logon(self, scenario: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        user = self.topo.random_admin_user()
        logon_id = self.topo.random_logon_id()
        scenario_privs = scenario.get("privileges") or []
        clean_privs = [str(p)[:64] for p in scenario_privs if isinstance(p, str)][:8]
        if not clean_privs:
            clean_privs = self.rng.sample(PRIVILEGES, k=self.rng.randint(2, 5))
        priv_list = "\n\t\t\t".join(clean_privs)
        msg = (
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
        return msg, {"user": user.username, "user_id": user.username}

    def _scenario_process_create(self, scenario: dict[str, Any], host) -> tuple[str, dict[str, Any]]:
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
        msg = (
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
        return msg, {"user": user.username, "user_id": user.username}


def _replace_placeholders(value: str, *, user: str) -> str:
    if not isinstance(value, str):
        return str(value)
    return (
        value.replace("<USER>", user)
        .replace("<user>", user)
        .replace("{user}", user)
    )
