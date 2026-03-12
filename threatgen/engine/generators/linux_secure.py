from __future__ import annotations

from datetime import datetime

from ..formatters.syslog_fmt import SyslogFormatter
from ..topology import Topology
from .base import BaseGenerator

EVENTS = [
    ("ssh_accept", 40),
    ("ssh_fail", 10),
    ("ssh_disconnect", 20),
    ("sudo", 15),
    ("pam_session", 15),
]

EVENT_TYPES = [e[0] for e in EVENTS]
EVENT_WEIGHTS = [e[1] for e in EVENTS]

SUDO_COMMANDS = [
    "/usr/bin/apt update", "/usr/bin/systemctl restart nginx",
    "/usr/bin/tail -f /var/log/syslog", "/usr/bin/journalctl -xe",
    "/usr/bin/ls /root", "/usr/sbin/service docker restart",
    "/usr/bin/cat /etc/shadow", "/usr/bin/netstat -tulnp",
]


class LinuxSecureGenerator(BaseGenerator):
    def __init__(self, topology: Topology) -> None:
        super().__init__(topology)
        self.fmt = SyslogFormatter()

    def generate(self, ts: datetime) -> list[str]:
        event_type = self.rng.choices(EVENT_TYPES, weights=EVENT_WEIGHTS, k=1)[0]
        host = self.topo.random_linux_host()
        user = self.topo.random_user()
        src_ip = self.topo.random_external_ip()
        port = self.topo.random_ephemeral_port()
        pid = self.rng.randint(1000, 65000)

        if event_type == "ssh_accept":
            method = self.rng.choice(["publickey", "password"])
            msg = f"Accepted {method} for {user.username} from {src_ip} port {port} ssh2"
            proc = "sshd"
        elif event_type == "ssh_fail":
            msg = f"Failed password for {user.username} from {src_ip} port {port} ssh2"
            proc = "sshd"
        elif event_type == "ssh_disconnect":
            msg = f"Received disconnect from {src_ip} port {port}:11: disconnected by user"
            proc = "sshd"
        elif event_type == "sudo":
            cmd = self.rng.choice(SUDO_COMMANDS)
            tty_num = self.rng.randint(0, 5)
            msg = f"{user.username} : TTY=pts/{tty_num} ; PWD=/home/{user.username} ; USER=root ; COMMAND={cmd}"
            proc = "sudo"
        else:
            action = self.rng.choice(["opened", "closed"])
            msg = f"pam_unix(sshd:session): session {action} for user {user.username}"
            proc = "sshd"

        line = self.fmt.format(ts, hostname=host.hostname, process=proc, pid=pid, message=msg)
        return [line]
