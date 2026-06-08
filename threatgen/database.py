from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typing import Optional

import aiosqlite
import yaml

from threatgen.engine.config import (
    DEFAULT_HEC_DEST_ID,
    DEFAULT_HEC_DEST_NAME,
    _CANONICAL_HEC_SOURCE_MAP,
    _CANONICAL_HEC_SOURCETYPE_MAP,
    is_valid_dest_id,
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
    # Promote a legacy single-destination ``hec`` block into the
    # ``hec_destinations`` list BEFORE the sourcetype/source map migrations
    # run, so those migrations only need to know about the new shape.
    await _migrate_hec_to_destinations()
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

        # Rename inside every HEC destination's sourcetype_map. We also
        # check the legacy ``hec`` block in case the destinations
        # migration has not run yet (defensive: makes ordering-free).
        hec_destinations = cfg.get("hec_destinations")
        targets: list[dict] = []
        if isinstance(hec_destinations, list):
            targets.extend(d for d in hec_destinations if isinstance(d, dict))
        legacy_hec = cfg.get("hec")
        if isinstance(legacy_hec, dict):
            targets.append(legacy_hec)
        for hec in targets:
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


async def _migrate_hec_to_destinations() -> None:
    """Promote a legacy single-destination ``hec`` block into the
    ``hec_destinations`` list.

    Pre-multi-HEC installs persisted HEC configuration as a single top-
    level ``hec`` dict. The runtime now reads from ``hec_destinations``
    (a list of fully-independent destinations). To preserve existing
    deployments without forcing users to delete ``threatgen.db``, we:

      * copy the legacy ``hec`` block into the first entry of
        ``hec_destinations`` (with id ``default`` / name ``Primary``);
      * leave the legacy ``hec`` block in place as a read-only mirror so
        any rollback or out-of-band reader keeps working.

    Idempotent: it never overwrites an existing ``hec_destinations``
    list, and it never overwrites a destination whose id matches the
    one we would inject.
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

        # Already migrated: leave alone.
        if isinstance(cfg.get("hec_destinations"), list) and cfg["hec_destinations"]:
            continue

        legacy = cfg.get("hec")
        if not isinstance(legacy, dict):
            continue

        # Shallow-copy is enough; nested dicts (sourcetype_map / source_map)
        # are only read, then the destination is the new source of truth.
        promoted = dict(legacy)
        promoted["id"] = DEFAULT_HEC_DEST_ID
        promoted["name"] = legacy.get("name") or DEFAULT_HEC_DEST_NAME
        cfg["hec_destinations"] = [promoted]

        await _db.execute(
            "UPDATE configs SET data = ? WHERE id = ?",
            (json.dumps(cfg), row["id"]),
        )
    await _db.commit()


def _iter_hec_destination_targets(cfg: dict) -> list[dict]:
    """Return mutable destination dicts inside ``cfg`` plus the legacy
    ``hec`` block (if any) so map-migrations stay backward-compatible
    even on configs the destinations-migration could not promote."""
    out: list[dict] = []
    destinations = cfg.get("hec_destinations")
    if isinstance(destinations, list):
        out.extend(d for d in destinations if isinstance(d, dict))
    legacy = cfg.get("hec")
    if isinstance(legacy, dict):
        out.append(legacy)
    return out


async def _migrate_hec_sourcetype_map() -> None:
    """Backfill canonical Splunk sourcetype mappings into every HEC
    destination of every persisted config.

    The ``sourcetype_map`` was added after initial installs, so existing
    databases have no mapping and therefore emit HEC events under the raw
    internal names (e.g. ``wineventlog``, ``sysmon``) instead of the
    canonical Splunk sourcetypes (``WinEventLog:Security``,
    ``XmlWinEventLog:Microsoft-Windows-Sysmon/Operational``) that Exposure
    Analytics entity templates, CIM datamodels, and every bundled hunt
    guide expect.

    Additive and idempotent per destination: only inserts canonical
    entries whose internal key is not already present, never overwrites
    a user-set mapping. Safe to run on every startup.
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
        for hec in _iter_hec_destination_targets(cfg):
            stm = hec.get("sourcetype_map")
            if not isinstance(stm, dict):
                stm = {}
                hec["sourcetype_map"] = stm
                changed = True
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
    """Backfill canonical Splunk ``source`` values into every HEC
    destination of every persisted config.

    The ``source_map`` field was introduced after ``sourcetype_map``;
    existing installs therefore have no entry and the HEC forwarder
    would fall back to ``threatgen:<family>`` paths that do not match
    Exposure Analytics OOTB discovery source filters for the
    Linux_sshd, WinSysmon, and WinSecurity templates (each of which
    includes ``source="..."`` in its search).

    Like the sourcetype-map migration above, this is additive and
    idempotent per destination. Safe to run on every startup.
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
        for hec in _iter_hec_destination_targets(cfg):
            sm = hec.get("source_map")
            if not isinstance(sm, dict):
                sm = {}
                hec["source_map"] = sm
                changed = True
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


# ---------------------------------------------------------------------------
# HEC destination CRUD helpers
#
# These wrap the JSON active-config and operate on the ``hec_destinations``
# list directly (the ``_deep_merge`` strategy used elsewhere is unsafe for
# lists: it would replace the whole list rather than splicing).
# ---------------------------------------------------------------------------


async def _write_active_config(cfg: dict) -> None:
    db = await get_db()
    await db.execute(
        "UPDATE configs SET data = ? WHERE is_active = 1", (json.dumps(cfg),)
    )
    await db.commit()


def _ensure_destinations(cfg: dict) -> list[dict]:
    """Return a mutable reference to ``cfg['hec_destinations']``,
    creating it if missing. Safe to use inside the CRUD helpers."""
    destinations = cfg.get("hec_destinations")
    if not isinstance(destinations, list):
        destinations = []
        cfg["hec_destinations"] = destinations
    return destinations


async def list_hec_destinations() -> list[dict]:
    """Return the persisted list of HEC destination dicts (raw, not
    parsed). Callers that need a typed view should use
    ``parse_config(...).hec_destinations``."""
    cfg = await get_active_config()
    destinations = cfg.get("hec_destinations")
    if isinstance(destinations, list):
        return [d for d in destinations if isinstance(d, dict)]
    return []


async def get_hec_destination(dest_id: str) -> Optional[dict]:
    if not is_valid_dest_id(dest_id):
        return None
    for d in await list_hec_destinations():
        if d.get("id") == dest_id:
            return d
    return None


async def add_hec_destination(record: dict) -> dict:
    """Append a new destination to the active config.

    The caller is responsible for validating fields (Pydantic at the API
    layer); this helper only guarantees uniqueness of ``id`` so the
    keychain and runtime layers have a safe handle to key on.
    """
    cfg = await get_active_config()
    destinations = _ensure_destinations(cfg)

    rec = dict(record)
    desired = str(rec.get("id") or "").strip().lower()
    if not is_valid_dest_id(desired):
        desired = "dest-" + _new_dest_suffix()
    existing_ids = {d.get("id") for d in destinations if isinstance(d, dict)}
    # Guarantee uniqueness even if the caller passed a colliding id.
    if desired in existing_ids:
        base = desired
        suffix = 1
        while f"{base}-{suffix}" in existing_ids:
            suffix += 1
        desired = f"{base}-{suffix}"
        if not is_valid_dest_id(desired):
            desired = "dest-" + _new_dest_suffix()
    rec["id"] = desired
    if not rec.get("name"):
        rec["name"] = f"Destination {len(destinations) + 1}"

    destinations.append(rec)
    await _write_active_config(cfg)
    return rec


async def update_hec_destination(dest_id: str, patch: dict) -> Optional[dict]:
    """Apply a patch to a single destination by id. Returns the updated
    record (or None when the id does not exist). Lists/dicts in the patch
    REPLACE the existing value (e.g. ``sourcetype_map``)."""
    if not is_valid_dest_id(dest_id):
        return None
    cfg = await get_active_config()
    destinations = _ensure_destinations(cfg)
    for idx, dest in enumerate(destinations):
        if not isinstance(dest, dict) or dest.get("id") != dest_id:
            continue
        for k, v in patch.items():
            if k == "id":
                # Disallow id mutation through the patch path; ids are
                # the keychain handle and would orphan the stored token.
                continue
            dest[k] = v
        destinations[idx] = dest
        await _write_active_config(cfg)
        return dest
    return None


async def delete_hec_destination(dest_id: str) -> bool:
    """Remove the destination with the given id. Returns True when a
    destination was removed."""
    if not is_valid_dest_id(dest_id):
        return False
    cfg = await get_active_config()
    destinations = _ensure_destinations(cfg)
    before = len(destinations)
    cfg["hec_destinations"] = [
        d for d in destinations
        if not (isinstance(d, dict) and d.get("id") == dest_id)
    ]
    if len(cfg["hec_destinations"]) == before:
        return False
    await _write_active_config(cfg)
    return True


def _new_dest_suffix() -> str:
    """Return an 8-char hex suffix used to build a fresh destination id.
    Uses ``secrets`` for non-predictability so concurrent additions
    rarely collide in practice."""
    import secrets

    return secrets.token_hex(4)


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
