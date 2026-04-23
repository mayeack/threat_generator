from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typing import Optional

import aiosqlite
import yaml

from threatgen.engine.config import (
    _CANONICAL_HEC_SOURCE_MAP,
    _CANONICAL_HEC_SOURCETYPE_MAP,
)

_DB_PATH = Path(__file__).parent.parent / "threatgen.db"
_DEFAULT_CFG = Path(__file__).parent / "default_config.yaml"
_db: Optional[aiosqlite.Connection] = None


async def get_db() -> aiosqlite.Connection:
    assert _db is not None, "Database not initialised"
    return _db


async def init_db() -> None:
    global _db
    _db = await aiosqlite.connect(str(_DB_PATH))
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA journal_mode=WAL")

    await _db.executescript("""
        CREATE TABLE IF NOT EXISTS configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config_id INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            stopped_at TEXT,
            total_events INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'running',
            FOREIGN KEY (config_id) REFERENCES configs(id)
        );
    """)
    await _db.commit()

    row = await _db.execute_fetchall("SELECT id FROM configs LIMIT 1")
    if not row:
        await _seed_default()

    await _migrate_sourcetype_keys()
    await _migrate_hec_sourcetype_map()
    await _migrate_hec_source_map()


# Historical internal sourcetype keys that must be renamed in stored
# configs to match the generator/cache keys the engine uses today.
# Migrations are idempotent: running twice is a no-op.
_SOURCETYPE_KEY_RENAMES: dict[str, str] = {
    "firewall": "cisco:asa",
    "dns": "stream:dns",
    "http": "stream:http",
}


async def _migrate_sourcetype_keys() -> None:
    """Rename legacy sourcetype keys inside every persisted config.

    Runs on every startup; each rename is idempotent because we only
    rewrite rows whose JSON actually changes. This keeps existing DBs
    usable after an internal-key rename without requiring users to
    delete threatgen.db.
    """
    assert _db is not None
    rows = await _db.execute_fetchall("SELECT id, data FROM configs")
    for row in rows:
        try:
            cfg = json.loads(row["data"])
        except (TypeError, ValueError):
            continue
        if not isinstance(cfg, dict):
            continue

        changed = False

        st = cfg.get("sourcetypes")
        if isinstance(st, dict):
            for old_key, new_key in _SOURCETYPE_KEY_RENAMES.items():
                if old_key in st and new_key not in st:
                    st[new_key] = st.pop(old_key)
                    changed = True

        hec = cfg.get("hec")
        if isinstance(hec, dict):
            stm = hec.get("sourcetype_map")
            if isinstance(stm, dict):
                for old_key, new_key in _SOURCETYPE_KEY_RENAMES.items():
                    if old_key in stm and new_key not in stm:
                        stm[new_key] = stm.pop(old_key)
                        changed = True

        if changed:
            await _db.execute(
                "UPDATE configs SET data = ? WHERE id = ?",
                (json.dumps(cfg), row["id"]),
            )
    await _db.commit()


async def _migrate_hec_sourcetype_map() -> None:
    """Backfill canonical Splunk sourcetype mappings into every persisted
    config.

    The ``hec.sourcetype_map`` was added after initial installs, so existing
    databases have no mapping and therefore emit HEC events under the raw
    internal names (e.g. ``wineventlog``, ``sysmon``) instead of the
    canonical Splunk sourcetypes (``WinEventLog:Security``,
    ``XmlWinEventLog:Microsoft-Windows-Sysmon/Operational``) that Exposure
    Analytics entity templates, CIM datamodels, and every bundled hunt
    guide expect.

    This migration is additive and idempotent: it only inserts canonical
    entries whose internal key is not already present, never overwrites a
    user-set mapping. Safe to run on every startup.
    """
    assert _db is not None
    rows = await _db.execute_fetchall("SELECT id, data FROM configs")
    for row in rows:
        try:
            cfg = json.loads(row["data"])
        except (TypeError, ValueError):
            continue
        if not isinstance(cfg, dict):
            continue

        hec = cfg.get("hec")
        if not isinstance(hec, dict):
            hec = {}
            cfg["hec"] = hec

        stm = hec.get("sourcetype_map")
        if not isinstance(stm, dict):
            stm = {}
            hec["sourcetype_map"] = stm

        changed = False
        for key, value in _CANONICAL_HEC_SOURCETYPE_MAP.items():
            if key not in stm:
                stm[key] = value
                changed = True

        if changed:
            await _db.execute(
                "UPDATE configs SET data = ? WHERE id = ?",
                (json.dumps(cfg), row["id"]),
            )
    await _db.commit()


async def _migrate_hec_source_map() -> None:
    """Backfill canonical Splunk ``source`` values into every persisted
    config.

    The ``hec.source_map`` field was introduced after
    ``hec.sourcetype_map``; existing installs therefore have no entry and
    the HEC forwarder would fall back to ``threatgen:<family>`` paths that
    do not match Exposure Analytics OOTB discovery source filters for the
    Linux_sshd, WinSysmon, and WinSecurity templates (each of which
    includes ``source="..."`` in its search).

    Like the sourcetype-map migration above, this is additive and
    idempotent: it only inserts canonical entries whose internal key is
    not already present, never overwrites a user-set mapping. Safe to
    run on every startup.
    """
    assert _db is not None
    rows = await _db.execute_fetchall("SELECT id, data FROM configs")
    for row in rows:
        try:
            cfg = json.loads(row["data"])
        except (TypeError, ValueError):
            continue
        if not isinstance(cfg, dict):
            continue

        hec = cfg.get("hec")
        if not isinstance(hec, dict):
            hec = {}
            cfg["hec"] = hec

        sm = hec.get("source_map")
        if not isinstance(sm, dict):
            sm = {}
            hec["source_map"] = sm

        changed = False
        for key, value in _CANONICAL_HEC_SOURCE_MAP.items():
            if key not in sm:
                sm[key] = value
                changed = True

        if changed:
            await _db.execute(
                "UPDATE configs SET data = ? WHERE id = ?",
                (json.dumps(cfg), row["id"]),
            )
    await _db.commit()


async def _seed_default() -> None:
    assert _db is not None
    with open(_DEFAULT_CFG) as f:
        data = yaml.safe_load(f)
    now = datetime.now(timezone.utc).isoformat()
    await _db.execute(
        "INSERT INTO configs (name, data, created_at, is_active) VALUES (?, ?, ?, 1)",
        ("Default", json.dumps(data), now),
    )
    await _db.commit()


async def get_active_config() -> dict:
    db = await get_db()
    row = await db.execute_fetchall(
        "SELECT data FROM configs WHERE is_active = 1 LIMIT 1"
    )
    if not row:
        return {}
    return json.loads(row[0]["data"])


async def update_active_config(patch: dict) -> dict:
    db = await get_db()
    current = await get_active_config()
    _deep_merge(current, patch)
    data_str = json.dumps(current)
    await db.execute(
        "UPDATE configs SET data = ? WHERE is_active = 1", (data_str,)
    )
    await db.commit()
    return current


def _deep_merge(base: dict, override: dict) -> None:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


async def save_config(name: str, data: dict) -> int:
    db = await get_db()
    now = datetime.now(timezone.utc).isoformat()
    cur = await db.execute(
        "INSERT INTO configs (name, data, created_at, is_active) VALUES (?, ?, ?, 0)",
        (name, json.dumps(data), now),
    )
    await db.commit()
    return cur.lastrowid  # type: ignore[return-value]


async def list_configs() -> list[dict]:
    db = await get_db()
    rows = await db.execute_fetchall(
        "SELECT id, name, created_at, is_active FROM configs ORDER BY created_at DESC"
    )
    return [dict(r) for r in rows]


async def activate_config(config_id: int) -> None:
    db = await get_db()
    await db.execute("UPDATE configs SET is_active = 0")
    await db.execute("UPDATE configs SET is_active = 1 WHERE id = ?", (config_id,))
    await db.commit()


async def create_run(config_id: int) -> int:
    db = await get_db()
    now = datetime.now(timezone.utc).isoformat()
    cur = await db.execute(
        "INSERT INTO runs (config_id, started_at, status) VALUES (?, ?, 'running')",
        (config_id, now),
    )
    await db.commit()
    return cur.lastrowid  # type: ignore[return-value]


async def finish_run(run_id: int, total_events: int) -> None:
    db = await get_db()
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "UPDATE runs SET stopped_at = ?, total_events = ?, status = 'stopped' WHERE id = ?",
        (now, total_events, run_id),
    )
    await db.commit()


async def close_db() -> None:
    global _db
    if _db:
        await _db.close()
        _db = None
