from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from threatgen.engine.llm.cache import VariationCache

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
    sourcetype = "linux_secure"

    def __init__(self, topology: Topology, cache: Optional[VariationCache] = None) -> None:
        super().__init__(topology, cache)
        self.fmt = SyslogFormatter()

    def _generate_pattern(self, ts: datetime) -> list[str]:
        event_type = self.rng.choices(EVENT_TYPES, weights=EVENT_WEIGHTS, k=1)[0]
        return self._render(ts, event_type, {})

    def render_from_scenario(self, scenario: dict[str, Any], ts: datetime) -> list[str]:
        event_type = str(scenario.get("event_type") or "").strip()
        if event_type not in EVENT_TYPES:
            event_type = self.rng.choices(EVENT_TYPES, weights=EVENT_WEIGHTS, k=1)[0]
        return self._render(ts, event_type, scenario)

    def _render(self, ts: datetime, event_type: str, scenario: dict[str, Any]) -> list[str]:
        host = self.topo.random_linux_host()
        user = self.topo.random_user()
        use_external = bool(scenario.get("use_external_source", True))
        src_ip = self.topo.random_external_ip() if use_external else self.topo.random_linux_host().ip
        port = self.topo.random_ephemeral_port()
        pid = self.rng.randint(1000, 65000)

        if event_type == "ssh_accept":
            method = str(scenario.get("auth_method") or self.rng.choice(["publickey", "password"]))
            if method not in ("publickey", "password", "keyboard-interactive"):
                method = "publickey"
            msg = f"Accepted {method} for {user.username} from {src_ip} port {port} ssh2"
            proc = "sshd"
        elif event_type == "ssh_fail":
            msg = f"Failed password for {user.username} from {src_ip} port {port} ssh2"
            proc = "sshd"
        elif event_type == "ssh_disconnect":
            reason = str(scenario.get("disconnect_reason") or "disconnected by user")[:128]
            msg = f"Received disconnect from {src_ip} port {port}:11: {reason}"
            proc = "sshd"
        elif event_type == "sudo":
            cmd = str(scenario.get("sudo_command") or self.rng.choice(SUDO_COMMANDS))[:256]
            tty_num = self.rng.randint(0, 5)
            msg = f"{user.username} : TTY=pts/{tty_num} ; PWD=/home/{user.username} ; USER=root ; COMMAND={cmd}"
            proc = "sudo"
        else:
            action = str(scenario.get("session_action") or self.rng.choice(["opened", "closed"]))
            if action not in ("opened", "closed"):
                action = "opened"
            msg = f"pam_unix(sshd:session): session {action} for user {user.username}"
            proc = "sshd"

        line = self.fmt.format(ts, hostname=host.hostname, process=proc, pid=pid, message=msg)
        return [line]
