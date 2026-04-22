from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from threatgen.websocket_manager import ws_manager

router = APIRouter()

VALID_SOURCETYPES = {"wineventlog", "sysmon", "linux_secure", "dns", "http", "cisco:asa", "all"}


@router.websocket("/ws/logs/{sourcetype}")
async def logs_ws(websocket: WebSocket, sourcetype: str):
    if sourcetype not in VALID_SOURCETYPES:
        await websocket.close(code=4000)
        return
    await ws_manager.connect(sourcetype, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(sourcetype, websocket)
