from __future__ import annotations

import asyncio
import logging
import math
import os
import random
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from threatgen.models import GeneratorStatus, RunState, StatsResponse

from .config import EngineConfig, parse_config
from .generators.base import BaseGenerator
from .generators.dns import DNSGenerator
from .generators.firewall import FirewallGenerator
from .generators.http import HTTPGenerator
from .generators.linux_secure import LinuxSecureGenerator
from .generators.sysmon import SysmonGenerator
from .generators.wineventlog import WinEventLogGenerator
from .threats.orchestrator import ThreatOrchestrator
from .topology import Topology

logger = logging.getLogger(__name__)

GENERATOR_CLASSES: dict[str, type[BaseGenerator]] = {
    "wineventlog": WinEventLogGenerator,
    "sysmon": SysmonGenerator,
    "linux_secure": LinuxSecureGenerator,
    "dns": DNSGenerator,
    "http": HTTPGenerator,
    "firewall": FirewallGenerator,
}

MULTILINE_SOURCETYPES: set[str] = set()


class EngineState:
    def __init__(self) -> None:
        self.state: RunState = RunState.IDLE
        self.run_id: Optional[int] = None
        self.started_at: float = 0
        self.total_events: int = 0
        self.events_by_sourcetype: dict[str, int] = defaultdict(int)
        self.threat_events: int = 0
        self._recent_events: list[float] = []
        self._lock = asyncio.Lock()

    async def record_events(self, sourcetype: str, count: int, is_threat: bool = False) -> None:
        async with self._lock:
            self.total_events += count
            self.events_by_sourcetype[sourcetype] += count
            if is_threat:
                self.threat_events += count
            now = time.monotonic()
            self._recent_events.extend([now] * count)

    @property
    def current_eps(self) -> float:
        now = time.monotonic()
        cutoff = now - 10.0
        self._recent_events = [t for t in self._recent_events if t > cutoff]
        if not self._recent_events:
            return 0.0
        span = now - self._recent_events[0]
        return len(self._recent_events) / max(span, 1.0)

    @property
    def uptime(self) -> float:
        if self.state == RunState.IDLE:
            return 0.0
        return time.monotonic() - self.started_at

    def reset(self) -> None:
        self.total_events = 0
        self.events_by_sourcetype = defaultdict(int)
        self.threat_events = 0
        self._recent_events = []
        self.started_at = time.monotonic()

    def to_status(self) -> GeneratorStatus:
        return GeneratorStatus(
            state=self.state,
            run_id=self.run_id,
            uptime_seconds=round(self.uptime, 1),
            total_events=self.total_events,
        )

    def to_stats(self) -> StatsResponse:
        return StatsResponse(
            state=self.state,
            uptime_seconds=round(self.uptime, 1),
            total_events=self.total_events,
            events_by_sourcetype=dict(self.events_by_sourcetype),
            threat_events=self.threat_events,
            current_eps=round(self.current_eps, 2),
        )


engine_state = EngineState()
_task: Optional[asyncio.Task] = None
_pause_event = asyncio.Event()
_stop_event = asyncio.Event()
_orchestrator: Optional[ThreatOrchestrator] = None
_file_handles: dict[str, Any] = {}


def _diurnal_multiplier(ts: datetime, cfg: EngineConfig) -> float:
    if not cfg.diurnal.enabled:
        return 1.0

    hour = ts.hour + ts.minute / 60.0
    peak_start, peak_end = cfg.diurnal.peak_hours
    mid_peak = (peak_start + peak_end) / 2.0
    peak = cfg.diurnal.peak_multiplier
    trough = cfg.diurnal.trough_multiplier

    multiplier = trough + ((math.cos(2 * math.pi * (hour - mid_peak) / 24.0) + 1) / 2.0) * (peak - trough)

    if ts.weekday() >= 5:
        multiplier *= 0.4

    return multiplier


async def _run_engine(cfg: EngineConfig) -> None:
    global _orchestrator

    rng = random.Random(cfg.seed)
    topology = Topology(cfg.topology_data, rng)
    topology.set_iocs(
        {name: c.extra for name, c in cfg.campaigns.items()}
    )

    generators: dict[str, BaseGenerator] = {}
    for name in cfg.sourcetypes:
        if name in GENERATOR_CLASSES:
            generators[name] = GENERATOR_CLASSES[name](topology)

    _orchestrator = ThreatOrchestrator(topology, cfg.campaigns)

    output_dir = Path(cfg.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    global _file_handles
    _file_handles = {}
    for name, st_cfg in cfg.sourcetypes.items():
        _file_handles[name] = open(output_dir / st_cfg.file, "w", buffering=1, encoding="utf-8")

    from threatgen.websocket_manager import ws_manager

    st_names = list(cfg.sourcetypes.keys())
    st_weights = [cfg.sourcetypes[n].weight for n in st_names]

    _pause_event.set()
    _stop_event.clear()
    event_debt = 0.0
    elapsed = 0.0

    try:
        while not _stop_event.is_set():
            await _pause_event.wait()

            tick_start = time.monotonic()
            ts = datetime.now(timezone.utc)

            multiplier = _diurnal_multiplier(ts, cfg)
            event_debt += cfg.eps * multiplier

            normal_count = int(event_debt * (1.0 - cfg.threat_ratio))
            event_debt -= normal_count

            for _ in range(normal_count):
                st = rng.choices(st_names, weights=st_weights, k=1)[0]
                gen = generators.get(st)
                if not gen:
                    continue
                lines = gen.generate(ts)
                fh = _file_handles.get(st)
                sep = "\n\n" if st in MULTILINE_SOURCETYPES else "\n"
                for line in lines:
                    if fh:
                        fh.write(line + sep)
                    try:
                        await ws_manager.broadcast(st, line)
                    except Exception:
                        pass
                await engine_state.record_events(st, len(lines))

            threat_events = _orchestrator.tick(ts, elapsed)
            for st, lines in threat_events.items():
                fh = _file_handles.get(st)
                sep = "\n\n" if st in MULTILINE_SOURCETYPES else "\n"
                for line in lines:
                    if fh:
                        fh.write(line + sep)
                    try:
                        await ws_manager.broadcast(st, line)
                    except Exception:
                        pass
                await engine_state.record_events(st, len(lines), is_threat=True)

            elapsed += 1.0

            tick_duration = time.monotonic() - tick_start
            sleep_time = max(0, 1.0 - tick_duration)
            try:
                await asyncio.wait_for(_stop_event.wait(), timeout=sleep_time)
                break
            except asyncio.TimeoutError:
                pass

    finally:
        for fh in _file_handles.values():
            fh.close()
        _file_handles.clear()


async def start_engine() -> None:
    global _task

    from threatgen.database import get_active_config, create_run

    raw_cfg = await get_active_config()
    cfg = parse_config(raw_cfg)

    rows = await _get_active_config_id()
    run_id = await create_run(rows)

    engine_state.reset()
    engine_state.state = RunState.RUNNING
    engine_state.run_id = run_id

    _stop_event.clear()
    _pause_event.set()
    _task = asyncio.create_task(_run_engine(cfg))

    async def _on_done(task: asyncio.Task):
        from threatgen.database import finish_run
        engine_state.state = RunState.IDLE
        if engine_state.run_id:
            await finish_run(engine_state.run_id, engine_state.total_events)

    _task.add_done_callback(lambda t: asyncio.create_task(_on_done(t)))


async def _get_active_config_id() -> int:
    from threatgen.database import get_db
    db = await get_db()
    rows = await db.execute_fetchall("SELECT id FROM configs WHERE is_active = 1 LIMIT 1")
    return rows[0]["id"] if rows else 1


async def stop_engine() -> None:
    global _task
    _stop_event.set()
    _pause_event.set()
    if _task:
        try:
            await asyncio.wait_for(_task, timeout=5.0)
        except asyncio.TimeoutError:
            _task.cancel()
        _task = None


async def pause_engine() -> None:
    if engine_state.state == RunState.RUNNING:
        _pause_event.clear()
        engine_state.state = RunState.PAUSED
    elif engine_state.state == RunState.PAUSED:
        _pause_event.set()
        engine_state.state = RunState.RUNNING


async def trigger_campaign(campaign_id: str) -> int:
    if not _orchestrator:
        return 0
    ts = datetime.now(timezone.utc)
    events = _orchestrator.trigger(campaign_id, ts)
    total = 0
    from threatgen.websocket_manager import ws_manager
    for st, lines in events.items():
        total += len(lines)
        fh = _file_handles.get(st)
        sep = "\n\n" if st in MULTILINE_SOURCETYPES else "\n"
        for line in lines:
            if fh:
                fh.write(line + sep)
            try:
                await ws_manager.broadcast(st, line)
            except Exception:
                pass
        await engine_state.record_events(st, len(lines), is_threat=True)
    return total
