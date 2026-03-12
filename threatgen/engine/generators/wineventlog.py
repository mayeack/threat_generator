from __future__ import annotations

from datetime import datetime

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


class WinEventLogGenerator(BaseGenerator):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.fmt = WinEventLogFormatter()

    def generate(self, ts: datetime) -> list[str]:
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
        )
        return [line]

    def _logon(self, ts: datetime, host) -> str:
        user = self.topo.random_user()
        logon_type = self.rng.choice(list(LOGON_TYPES.keys()))
        src_ip = self.topo.random_external_ip() if logon_type == 10 else host.ip
        logon_id = self.topo.random_logon_id()
        return (
            f"An account was successfully logged on.\n"
            f"Subject:\n"
            f"  Security ID: {user.sid}\n"
            f"  Account Name: {user.username}\n"
            f"  Account Domain: {user.domain}\n"
            f"  Logon ID: {logon_id}\n"
            f"Logon Type: {logon_type}\n"
            f"New Logon:\n"
            f"  Security ID: {user.sid}\n"
            f"  Account Name: {user.username}\n"
            f"  Account Domain: {user.domain}\n"
            f"  Logon ID: {logon_id}\n"
            f"Network Information:\n"
            f"  Source Network Address: {src_ip}\n"
            f"  Source Port: {self.topo.random_ephemeral_port()}\n"
            f"Authentication Package: Negotiate"
        )

    def _failed_logon(self, ts: datetime, host) -> str:
        user = self.topo.random_user()
        src_ip = self.topo.random_external_ip()
        return (
            f"An account failed to log on.\n"
            f"Subject:\n"
            f"  Security ID: S-1-0-0\n"
            f"  Account Name: -\n"
            f"  Account Domain: -\n"
            f"Logon Type: 3\n"
            f"Account For Which Logon Failed:\n"
            f"  Account Name: {user.username}\n"
            f"  Account Domain: {user.domain}\n"
            f"Failure Information:\n"
            f"  Failure Reason: Unknown user name or bad password.\n"
            f"  Status: 0xC000006D\n"
            f"  Sub Status: 0xC000006A\n"
            f"Network Information:\n"
            f"  Source Network Address: {src_ip}\n"
            f"  Source Port: {self.topo.random_ephemeral_port()}"
        )

    def _logoff(self, ts: datetime, host) -> str:
        user = self.topo.random_user()
        logon_type = self.rng.choice([2, 3, 7])
        logon_id = self.topo.random_logon_id()
        return (
            f"An account was logged off.\n"
            f"Subject:\n"
            f"  Security ID: {user.sid}\n"
            f"  Account Name: {user.username}\n"
            f"  Account Domain: {user.domain}\n"
            f"  Logon ID: {logon_id}\n"
            f"Logon Type: {logon_type}"
        )

    def _special_logon(self, ts: datetime, host) -> str:
        user = self.topo.random_admin_user()
        logon_id = self.topo.random_logon_id()
        privs = self.rng.sample(PRIVILEGES, k=self.rng.randint(2, 5))
        priv_list = "\n\t\t\t".join(privs)
        return (
            f"Special privileges assigned to new logon.\n"
            f"Subject:\n"
            f"  Security ID: {user.sid}\n"
            f"  Account Name: {user.username}\n"
            f"  Account Domain: {user.domain}\n"
            f"  Logon ID: {logon_id}\n"
            f"Privileges: {priv_list}"
        )

    def _process_create(self, ts: datetime, host) -> str:
        user = self.topo.random_user()
        proc = self.rng.choice(PROCESS_PATHS)
        parent = self.rng.choice(PROCESS_PATHS)
        pid = self.topo.random_process_id()
        ppid = self.topo.random_process_id()
        logon_id = self.topo.random_logon_id()
        return (
            f"A new process has been created.\n"
            f"Creator Subject:\n"
            f"  Security ID: {user.sid}\n"
            f"  Account Name: {user.username}\n"
            f"  Account Domain: {user.domain}\n"
            f"  Logon ID: {logon_id}\n"
            f"Process Information:\n"
            f"  New Process ID: 0x{pid:X}\n"
            f"  New Process Name: {proc}\n"
            f"  Creator Process ID: 0x{ppid:X}\n"
            f"  Creator Process Name: {parent}"
        )

    def _account_changed(self, ts: datetime, host) -> str:
        admin = self.topo.random_admin_user()
        target = self.topo.random_user()
        logon_id = self.topo.random_logon_id()
        return (
            f"A user account was changed.\n"
            f"Subject:\n"
            f"  Security ID: {admin.sid}\n"
            f"  Account Name: {admin.username}\n"
            f"  Account Domain: {admin.domain}\n"
            f"  Logon ID: {logon_id}\n"
            f"Target Account:\n"
            f"  Security ID: {target.sid}\n"
            f"  Account Name: {target.username}\n"
            f"  Account Domain: {target.domain}"
        )
