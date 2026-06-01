"""
System-Status / Healthcheck-Routen.

GET  /admin/api/health/tier1          — billige Continuous-Checks
GET  /admin/api/health/anomalies      — Stuck-Pending, Failed-Logins, etc.
POST /admin/api/health/probe-build    — Builder-Selftest (~30s)
POST /admin/api/health/db-integrity   — PRAGMA integrity_check
POST /admin/api/health/tactical-rt    — End-to-End run_command an Test-Agent
"""
from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

import database
import health_checks
from routes.admin import _require_admin
from rmm import get_rmm_client

logger = logging.getLogger("softshelf.health")
router = APIRouter()


@router.get("/admin/api/health/tier1", dependencies=[Depends(_require_admin)])
async def health_tier1() -> dict:
    """Alle Tier-1-Checks parallel ausfuehren."""
    results = await health_checks.run_all_tier1()
    return {"checks": results, "generated_at": int(time.time())}


@router.get("/admin/api/health/anomalies", dependencies=[Depends(_require_admin)])
async def health_anomalies() -> dict:
    results = await health_checks.run_all_anomalies()
    return {"checks": results, "generated_at": int(time.time())}


@router.post("/admin/api/health/probe-build", dependencies=[Depends(_require_admin)])
async def health_probe_build() -> dict:
    """Builder-Selftest. Sequentiell, kein Concurrent Probe."""
    result = await health_checks.probe_build()
    return result


@router.post("/admin/api/health/db-integrity", dependencies=[Depends(_require_admin)])
async def health_db_integrity() -> dict:
    result = await health_checks.db_integrity_check()
    return result


class TacticalRtRequest(BaseModel):
    agent_id: str = Field(min_length=10, max_length=64)

    @field_validator("agent_id")
    @classmethod
    def _check(cls, v: str) -> str:
        import re
        if not re.fullmatch(r"[A-Za-z0-9]+", v):
            raise ValueError("agent_id muss alphanumerisch sein")
        return v


@router.post("/admin/api/health/tactical-rt", dependencies=[Depends(_require_admin)])
async def health_tactical_rt(body: TacticalRtRequest) -> dict:
    """Tactical-Connectivity-Probe: prueft Online-Status des angegebenen
    Test-Agents via Tactical-API. Damit ist die Kette
    Proxy → Tactical → Agent-Heartbeat bestaetigt — ohne echten
    run_command (der waere fire-and-forget und ohne unmittelbares Result).
    """
    agent = await database.get_agent(body.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent unbekannt")
    rmm = get_rmm_client()
    t0 = time.perf_counter()
    try:
        status = await rmm.check_agent_status(body.agent_id)
    except Exception as e:
        return {
            "status": "error",
            "message": f"Fehler: {e}",
            "latency_ms": int((time.perf_counter() - t0) * 1000),
        }
    ms = int((time.perf_counter() - t0) * 1000)
    online = bool(status.get("online"))
    last_seen = status.get("last_seen") or "?"
    return {
        "status": "ok" if online else "warn",
        "message": (
            f"Online ({ms} ms)" if online
            else f"Agent offline — last_seen={last_seen}"
        ),
        "latency_ms": ms,
        "online": online,
        "last_seen": last_seen,
        "hostname": agent.get("hostname", ""),
    }
