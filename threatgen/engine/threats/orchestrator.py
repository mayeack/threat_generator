from __future__ import annotations

import logging
import random
from datetime import datetime
from typing import Any, Optional

from ..config import CampaignConfig
from ..llm.planner import LLMCampaignPlanner
from ..topology import Topology
from .base import BaseCampaign
from .bruteentry import BruteEntryCampaign
from .cobaltstrike import CobaltStrikeCampaign
from .cryptojack import CryptoJackCampaign
from .darkgate import DarkGateCampaign
from .peertime import PeerTimeCampaign
from .phishkit import PhishKitCampaign
from .ransomsim import RansomSimCampaign
from .snakebyte import SnakeByteCampaign
from .terndoor import TernDoorCampaign
from .llm_plan import LLMPlanCampaign

logger = logging.getLogger(__name__)

CAMPAIGN_CLASSES: dict[str, type[BaseCampaign]] = {
    "terndoor": TernDoorCampaign,
    "bruteentry": BruteEntryCampaign,
    "peertime": PeerTimeCampaign,
    "cobaltstrike": CobaltStrikeCampaign,
    "darkgate": DarkGateCampaign,
    "cryptojack": CryptoJackCampaign,
    "ransomsim": RansomSimCampaign,
    "phishkit": PhishKitCampaign,
    "snakebyte": SnakeByteCampaign,
}


class CampaignTimer:
    def __init__(self, campaign: BaseCampaign, interval_min: int, interval_max: int, rng: random.Random) -> None:
        self.campaign = campaign
        self.interval_min = interval_min
        self.interval_max = interval_max
        self.rng = rng
        self._next_fire: float = 0
        self._schedule_next(0)

    def _schedule_next(self, current_tick: float) -> None:
        delay_seconds = self.rng.randint(self.interval_min * 60, self.interval_max * 60)
        self._next_fire = current_tick + delay_seconds

    def check(self, tick: float) -> bool:
        if tick >= self._next_fire:
            self._schedule_next(tick)
            return True
        return False


class ThreatOrchestrator:
    def __init__(
        self,
        topology: Topology,
        campaigns_cfg: dict[str, CampaignConfig],
        planner: Optional[LLMCampaignPlanner] = None,
    ) -> None:
        self.topology = topology
        self.rng = topology.rng
        self.timers: dict[str, CampaignTimer] = {}
        self.campaigns: dict[str, BaseCampaign] = {}
        self.enabled: dict[str, bool] = {}
        self.iocs: dict[str, dict[str, Any]] = {}
        self.planner = planner

        for name, cfg in campaigns_cfg.items():
            if name in CAMPAIGN_CLASSES:
                campaign = CAMPAIGN_CLASSES[name](topology)
                self.campaigns[name] = campaign
                self.enabled[name] = cfg.enabled
                self.iocs[name] = dict(cfg.extra or {})
                mn, mx = cfg.interval_minutes
                self.timers[name] = CampaignTimer(campaign, mn, mx, self.rng)

    async def tick(self, ts: datetime, elapsed_seconds: float) -> dict[str, list[str]]:
        merged: dict[str, list[str]] = {}
        for name, timer in self.timers.items():
            if not self.enabled.get(name, False):
                continue
            if timer.check(elapsed_seconds):
                events = await self._fire(name, ts)
                for st, lines in events.items():
                    merged.setdefault(st, []).extend(lines)
        return merged

    async def trigger(self, campaign_id: str, ts: datetime) -> dict[str, list[str]]:
        if campaign_id not in self.campaigns:
            return {}
        return await self._fire(campaign_id, ts)

    async def _fire(self, name: str, ts: datetime) -> dict[str, list[str]]:
        plan = None
        if self.planner is not None and self.planner.enabled:
            try:
                plan = await self.planner.plan(name, self.iocs.get(name, {}))
            except Exception:
                logger.warning("planner_plan_raised", extra={"campaign": name}, exc_info=True)
                plan = None

        if plan is not None:
            try:
                llm_campaign = LLMPlanCampaign(self.topology, plan, self.iocs.get(name, {}))
                return llm_campaign.generate(ts)
            except Exception:
                logger.warning("llm_plan_render_failed", extra={"campaign": name}, exc_info=True)

        campaign = self.campaigns[name]
        return campaign.generate(ts)

    def set_enabled(self, campaign_id: str, enabled: bool) -> None:
        if campaign_id in self.enabled:
            self.enabled[campaign_id] = enabled
