from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from threatgen.database import init_db, close_db

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await close_db()


app = FastAPI(title="ThreatGen", version="1.0.0", lifespan=lifespan)

from threatgen.api.generator import router as generator_router
from threatgen.api.config import router as config_router
from threatgen.api.topology import router as topology_router
from threatgen.api.campaigns import router as campaigns_router
from threatgen.api.stats import router as stats_router
from threatgen.api.websocket import router as ws_router

app.include_router(generator_router, prefix="/api/generator", tags=["generator"])
app.include_router(config_router, prefix="/api", tags=["config"])
app.include_router(topology_router, prefix="/api", tags=["topology"])
app.include_router(campaigns_router, prefix="/api/campaigns", tags=["campaigns"])
app.include_router(stats_router, prefix="/api", tags=["stats"])
app.include_router(ws_router)

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
