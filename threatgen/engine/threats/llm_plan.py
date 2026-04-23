from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from ..generators.dns import DNSGenerator
from ..generators.firewall import FirewallGenerator
from ..generators.http import HTTPGenerator
from ..generators.linux_secure import LinuxSecureGenerator
from ..generators.sysmon import SysmonGenerator
from ..generators.wineventlog import WinEventLogGenerator
from ..topology import Topology
from .base import BaseCampaign

logger = logging.getLogger(__name__)


class LLMPlanCampaign(BaseCampaign):
    """One-shot campaign that renders a validated LLM plan across sourcetypes.

    Each step in the plan references a sourcetype and a scenario dict. We
    substitute trusted topology values (configured C2 IPs/domains, victim
    host) into the scenarios before handing them to the corresponding
    generator's render_from_scenario method. The model never produces our
    real IPs/hostnames directly (input validation / prompt injection
    hardening per codeguard-0-mcp-security).
    """

    _GEN_CLASSES: dict[str, Any] = {
        "wineventlog": WinEventLogGenerator,
        "sysmon": SysmonGenerator,
        "linux_secure": LinuxSecureGenerator,
        "stream:dns": DNSGenerator,
        "stream:http": HTTPGenerator,
        "cisco:asa": FirewallGenerator,
    }

    def __init__(self, topology: Topology, plan: dict[str, Any], iocs: dict[str, Any]) -> None:
        super().__init__(topology)
        self._plan = plan
        self._iocs = iocs or {}
        self._victim_host = topology.random_windows_host()

    @property
    def total_phases(self) -> int:
        return 1

    def generate(self, ts: datetime) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        steps = self._plan.get("steps") or []
        for step in steps:
            if not isinstance(step, dict):
                continue
            sourcetype = step.get("sourcetype")
            gen_cls = self._GEN_CLASSES.get(sourcetype)
            if gen_cls is None:
                continue
            scenario = step.get("scenario") or {}
            if not isinstance(scenario, dict):
                continue
            scenario = self._materialize_iocs(scenario, step)
            try:
                gen = gen_cls(self.topo)
                lines = gen.render_from_scenario(scenario, ts)
            except Exception:
                logger.warning(
                    "llm_plan_step_failed",
                    extra={"sourcetype": sourcetype},
                    exc_info=True,
                )
                continue
            out.setdefault(sourcetype, []).extend(lines)
        return out

    def _materialize_iocs(self, scenario: dict[str, Any], step: dict[str, Any]) -> dict[str, Any]:
        """Replace use_c2_ip / use_c2_domain flags with real, configured IOCs.

        Leaves unknown fields untouched. Never trusts domain/IP strings the
        model produced for these slots.
        """
        merged = dict(scenario)
        if step.get("use_c2_ip"):
            ip = self._pick("c2_ips") or self._pick("orb_ips") or self._pick("mining_pools")
            if ip:
                merged.setdefault("destination_ip", ip)
                if "destination_domain" not in merged:
                    merged["destination_domain"] = ip
        if step.get("use_c2_domain"):
            domain = (
                self._pick("c2_domains")
                or self._pick("domains")
                or self._pick("phish_domains")
            )
            if domain:
                merged["domain"] = domain
                merged.setdefault("destination_domain", domain)
                if "site" not in merged:
                    merged["site"] = domain
        return merged

    def _pick(self, key: str) -> Any:
        value = self._iocs.get(key)
        if isinstance(value, list) and value:
            return self.rng.choice(value)
        if isinstance(value, str) and value:
            return value
        return None
