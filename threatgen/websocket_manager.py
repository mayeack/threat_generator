from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, sourcetype: str, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._subscribers[sourcetype].add(ws)
        logger.info("WS client connected for %s (total=%d)", sourcetype, len(self._subscribers[sourcetype]))

    async def disconnect(self, sourcetype: str, ws: WebSocket) -> None:
        async with self._lock:
            self._subscribers[sourcetype].discard(ws)

    async def broadcast(self, sourcetype: str, line: str) -> None:
        targets = set()
        async with self._lock:
            targets.update(self._subscribers.get(sourcetype, set()))
            targets.update(self._subscribers.get("all", set()))

        stale: list[tuple[str, WebSocket]] = []
        for ws in targets:
            try:
                await asyncio.wait_for(ws.send_text(f"{sourcetype}|{line}"), timeout=2.0)
            except Exception:
                for key in (sourcetype, "all"):
                    stale.append((key, ws))

        if stale:
            async with self._lock:
                for key, ws in stale:
                    self._subscribers[key].discard(ws)


ws_manager = WebSocketManager()
