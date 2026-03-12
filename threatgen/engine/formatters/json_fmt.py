from __future__ import annotations

import json
from datetime import datetime

from .base import BaseFormatter


class JSONFormatter(BaseFormatter):
    def format(self, ts: datetime, **fields) -> str:
        data = fields.get("data", {})
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        data.setdefault("timestamp", ts_str)
        data.setdefault("endtime", ts_str)
        return json.dumps(data, separators=(",", ":"))
