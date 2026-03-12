from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from threatgen.engine.topology import Topology


class BaseGenerator(ABC):
    def __init__(self, topology: Topology) -> None:
        self.topo = topology
        self.rng = topology.rng

    @abstractmethod
    def generate(self, ts: datetime) -> list[str]:
        """Return one or more formatted log lines for a single event."""
        ...
