from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from threatgen.database import close_db, get_active_config, init_db
from threatgen.engine.config import parse_config
from threatgen.engine.hec.runtime import hec_runtime
from threatgen.engine.llm.runtime import runtime as llm_runtime

STATIC_DIR = Path(__file__).parent / "static"

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    try:
        raw_cfg = await get_active_config()
        cfg = parse_config(raw_cfg)
        llm_runtime.configure(cfg.llm)
        if llm_runtime.worker:
            await llm_runtime.worker.start()
            if llm_runtime.worker.running:
                logger.info("llm_worker_started")
            else:
                logger.info("llm_worker_not_started_fallback_active")
        hec_runtime.configure(cfg.hec)
        if cfg.hec.enabled:
            try:
                await hec_runtime.start()
            except Exception:
                logger.exception("hec_runtime_start_failed")
    except Exception:
        logger.exception("runtime_init_failed")
    yield
    try:
        if llm_runtime.worker:
            await llm_runtime.worker.stop()
    except Exception:
        logger.exception("llm_worker_stop_failed")
    try:
        await hec_runtime.stop()
    except Exception:
        logger.exception("hec_runtime_stop_failed")
    await close_db()


app = FastAPI(title="ThreatGen", version="1.0.0", lifespan=lifespan)

from threatgen.api.generator import router as generator_router
from threatgen.api.config import router as config_router
from threatgen.api.topology import router as topology_router
from threatgen.api.campaigns import router as campaigns_router
from threatgen.api.stats import router as stats_router
from threatgen.api.websocket import router as ws_router
from threatgen.api.llm import router as llm_router
from threatgen.api.hec import router as hec_router

app.include_router(generator_router, prefix="/api/generator", tags=["generator"])
app.include_router(config_router, prefix="/api", tags=["config"])
app.include_router(topology_router, prefix="/api", tags=["topology"])
app.include_router(campaigns_router, prefix="/api/campaigns", tags=["campaigns"])
app.include_router(stats_router, prefix="/api", tags=["stats"])
app.include_router(llm_router, prefix="/api/llm", tags=["llm"])
app.include_router(hec_router, prefix="/api/hec", tags=["hec"])
app.include_router(ws_router)

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
