from __future__ import annotations

import random
from datetime import datetime

from ..config import CampaignConfig
from ..topology import Topology
from .base import BaseCampaign
from .bruteentry import BruteEntryCampaign
from .peertime import PeerTimeCampaign
from .terndoor import TernDoorCampaign

CAMPAIGN_CLASSES: dict[str, type[BaseCampaign]] = {
    "terndoor": TernDoorCampaign,
    "bruteentry": BruteEntryCampaign,
    "peertime": PeerTimeCampaign,
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
    def __init__(self, topology: Topology, campaigns_cfg: dict[str, CampaignConfig]) -> None:
        self.topology = topology
        self.rng = topology.rng
        self.timers: dict[str, CampaignTimer] = {}
        self.campaigns: dict[str, BaseCampaign] = {}
        self.enabled: dict[str, bool] = {}

        for name, cfg in campaigns_cfg.items():
            if name in CAMPAIGN_CLASSES:
                campaign = CAMPAIGN_CLASSES[name](topology)
                self.campaigns[name] = campaign
                self.enabled[name] = cfg.enabled
                mn, mx = cfg.interval_minutes
                self.timers[name] = CampaignTimer(campaign, mn, mx, self.rng)

    def tick(self, ts: datetime, elapsed_seconds: float) -> dict[str, list[str]]:
        merged: dict[str, list[str]] = {}
        for name, timer in self.timers.items():
            if not self.enabled.get(name, False):
                continue
            if timer.check(elapsed_seconds):
                events = timer.campaign.generate(ts)
                for st, lines in events.items():
                    merged.setdefault(st, []).extend(lines)
        return merged

    def trigger(self, campaign_id: str, ts: datetime) -> dict[str, list[str]]:
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return {}
        return campaign.generate(ts)

    def set_enabled(self, campaign_id: str, enabled: bool) -> None:
        if campaign_id in self.enabled:
            self.enabled[campaign_id] = enabled
