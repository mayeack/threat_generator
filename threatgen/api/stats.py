from __future__ import annotations

from fastapi import APIRouter

from threatgen.engine.scheduler import engine_state
from threatgen.models import StatsResponse

router = APIRouter()


@router.get("/stats", response_model=StatsResponse)
async def get_stats():
    return engine_state.to_stats()
