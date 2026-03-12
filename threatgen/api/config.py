from __future__ import annotations

from fastapi import APIRouter, HTTPException

from threatgen import database as db
from threatgen.models import ConfigUpdate

router = APIRouter()


@router.get("/config")
async def get_config():
    return await db.get_active_config()


@router.put("/config")
async def update_config(update: ConfigUpdate):
    patch = update.model_dump(exclude_none=True)
    if not patch:
        raise HTTPException(400, "No fields to update")
    cfg = await db.update_active_config(patch)
    return cfg


@router.get("/configs")
async def list_configs():
    return await db.list_configs()


@router.post("/configs")
async def save_config(body: dict):
    name = body.get("name", "Untitled")
    current = await db.get_active_config()
    cfg_id = await db.save_config(name, current)
    return {"id": cfg_id, "name": name}
