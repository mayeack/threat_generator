from __future__ import annotations

from fastapi import APIRouter, HTTPException

from threatgen import database as db
from threatgen.models import CampaignInfo, CampaignToggle
from threatgen.engine.scheduler import engine_state, trigger_campaign

router = APIRouter()

CAMPAIGN_META = {
    "terndoor": {
        "name": "TernDoor",
        "description": "China-nexus APT backdoor using DLL side-loading, msiexec injection, scheduled task persistence, kernel driver, and C2 beaconing on port 443.",
        "mitre_techniques": ["T1574.002", "T1055", "T1547.001", "T1053.005", "T1014", "T1543.003", "T1071.001"],
        "ioc_keys": ["c2_ips"],
    },
    "bruteentry": {
        "name": "BruteEntry",
        "description": "ORB-based brute-force scanner targeting SSH, Postgres, and Tomcat from compromised edge devices.",
        "mitre_techniques": ["T1110.001", "T1110.003", "T1595.002"],
        "ioc_keys": ["orb_ips"],
    },
    "peertime": {
        "name": "PeerTime",
        "description": "ELF backdoor using BitTorrent P2P protocol for C2, deployed via shell scripts, Docker, and BusyBox with process masquerading.",
        "mitre_techniques": ["T1071.001", "T1059.004", "T1036.004", "T1610"],
        "ioc_keys": ["domains", "c2_ips"],
    },
}


@router.get("")
async def list_campaigns():
    cfg = await db.get_active_config()
    tc = cfg.get("threat_campaigns", {})
    result = []
    for cid, meta in CAMPAIGN_META.items():
        camp_cfg = tc.get(cid, {})
        iocs = {k: camp_cfg.get(k, []) for k in meta["ioc_keys"]}
        result.append(CampaignInfo(
            id=cid,
            name=meta["name"],
            enabled=camp_cfg.get("enabled", False),
            interval_minutes=camp_cfg.get("interval_minutes", [10, 30]),
            description=meta["description"],
            mitre_techniques=meta["mitre_techniques"],
            iocs=iocs,
        ))
    return result


@router.put("/{campaign_id}")
async def toggle_campaign(campaign_id: str, body: CampaignToggle):
    if campaign_id not in CAMPAIGN_META:
        raise HTTPException(404, "Unknown campaign")
    cfg = await db.get_active_config()
    tc = cfg.get("threat_campaigns", {})
    if campaign_id not in tc:
        tc[campaign_id] = {}
    tc[campaign_id]["enabled"] = body.enabled
    await db.update_active_config({"threat_campaigns": tc})
    return {"id": campaign_id, "enabled": body.enabled}


@router.post("/{campaign_id}/trigger")
async def manual_trigger(campaign_id: str):
    if campaign_id not in CAMPAIGN_META:
        raise HTTPException(404, "Unknown campaign")
    count = await trigger_campaign(campaign_id)
    return {"id": campaign_id, "events_generated": count}
