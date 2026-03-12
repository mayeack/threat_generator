from __future__ import annotations

from fastapi import APIRouter

from threatgen import database as db
from threatgen.models import TopologyUpdate

router = APIRouter()


@router.get("/topology")
async def get_topology():
    cfg = await db.get_active_config()
    return cfg.get("topology", {})


@router.put("/topology")
async def update_topology(update: TopologyUpdate):
    cfg = await db.update_active_config({"topology": update.topology})
    return cfg.get("topology", {})
