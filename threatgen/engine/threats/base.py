from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from threatgen.engine.topology import Topology


class BaseCampaign(ABC):
    def __init__(self, topology: Topology) -> None:
        self.topo = topology
        self.rng = topology.rng
        self._phase: int = 0

    @property
    @abstractmethod
    def total_phases(self) -> int: ...

    @abstractmethod
    def generate(self, ts: datetime) -> dict[str, list[str]]:
        """Return dict mapping sourcetype internal names to formatted log lines."""
        ...

    def advance_phase(self) -> int:
        current = self._phase
        self._phase = (self._phase + 1) % self.total_phases
        return current
