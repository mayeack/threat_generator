from __future__ import annotations

from fastapi import APIRouter, HTTPException

from threatgen.models import GeneratorStatus, RunState
from threatgen.engine.scheduler import engine_state, start_engine, stop_engine, pause_engine

router = APIRouter()


@router.post("/start")
async def start_generation():
    if engine_state.state == RunState.RUNNING:
        raise HTTPException(400, "Generator already running")
    await start_engine()
    return {"status": "started"}


@router.post("/stop")
async def stop_generation():
    if engine_state.state == RunState.IDLE:
        raise HTTPException(400, "Generator not running")
    await stop_engine()
    return {"status": "stopped"}


@router.post("/pause")
async def pause_generation():
    if engine_state.state == RunState.IDLE:
        raise HTTPException(400, "Generator not running")
    await pause_engine()
    return {"status": "paused" if engine_state.state == RunState.PAUSED else "running"}


@router.get("/status", response_model=GeneratorStatus)
async def get_status():
    return engine_state.to_status()
