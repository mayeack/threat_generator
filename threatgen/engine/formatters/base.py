from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime


class BaseFormatter(ABC):
    @abstractmethod
    def format(self, ts: datetime, **fields) -> str: ...
