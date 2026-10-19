"""
Installations-Warteschlange: zentrale Einreihung und Zustellung.

Jeder Pfad, der eine Installer-Operation auf einem Agent ausloesen will, ruft
`enqueue()`. Zugestellt wird ausschliesslich ueber `kick()`:

    kick(agent) → je Lane: claim_next (CAS queued → pending)
                → bestehende dispatch_*_for_agent(existing_log_id=...)
                → Script bauen + fire-and-forget-Bootstrap wie bisher

Die Datenbank erzwingt hoechstens einen Eintrag in Arbeit pro Agent und Lane
(partieller UNIQUE-Index uq_action_log_lane + NOT-EXISTS-Guard in
claim_next). Der Lock hier verhindert nur unnoetige Doppel-Drains innerhalb
des einen Prozesses, er ist NICHT die Sicherheitsgarantie.

Wann wird gekickt?
- direkt nach enqueue (freier Agent startet sofort)
- nach jedem Final-Callback (der Naechste startet ohne Tick-Verzug)
- nach Zustellfehlern
- alle 60 s ueber tick() als Netz
"""
import asyncio
import json
import logging
import time

import database

logger = logging.getLogger("softshelf.queue")

_agent_locks: dict[str, asyncio.Lock] = {}
_status_cache: dict[str, tuple[float, str]] = {}
_STATUS_TTL = 30.0          # Sekunden, wie lange ein Online-Check gilt
_MAX_CLAIMS_PER_LANE = 5    # Schutz gegen Endlosschleifen bei kaputten Eintraegen

_bg_tasks: set = set()


def _spawn_bg(coro) -> asyncio.Task:
    t = asyncio.create_task(coro)
    _bg_tasks.add(t)
    t.add_done_callback(_bg_tasks.discard)
    return t


def _lock(agent_id: str) -> asyncio.Lock:
    lk = _agent_locks.get(agent_id)
    if lk is None:
        lk = _agent_locks[agent_id] = asyncio.Lock()
    return lk


def forget_status(agent_id: str) -> None:
    """Online-Cache verwerfen, z.B. wenn sich der Tray gerade gemeldet hat."""
    _status_cache.pop(agent_id, None)


async def _agent_status(agent_id: str) -> str:
    """'online' | 'offline' | 'gone' | 'check_failed', 30 s gecacht."""
    now = time.monotonic()
    hit = _status_cache.get(agent_id)
    if hit and now - hit[0] < _STATUS_TTL:
        return hit[1]
    from rmm import get_rmm_client
    try:
        info = await get_rmm_client().check_agent_status(agent_id) or {}
        if not info.get("exists", True):
            st = "gone"
        else:
            st = info.get("status") or "unknown"
    except Exception:
        st = "check_failed"
    _status_cache[agent_id] = (now, st)
    return st


# ── Einreihen ────────────────────────────────────────────────────────────────

async def enqueue(
    agent_id: str,
    hostname: str,
    pkg: dict,
    action: str,
    *,
    priority: int = database.PRIO_INTERACTIVE,
    triggered_by: str | None = None,
    request: dict | None = None,
    workflow_run_id: int | None = None,
    kick_now: bool = True,
    metadata: str | None = None,
) -> dict:
    """Reiht eine Operation ein und stoesst den Drain an.

    Rueckgabe:
      duplicate  True, wenn fuer dieses Paket schon etwas offen war
      log_id     action_log-Id (neu oder vorhanden)
      started    True, wenn der Eintrag sofort beansprucht wurde
      position   1 = als Naechstes (nur wenn wartend)
      current    Anzeigename dessen, was gerade laeuft
      reason     Warte-Grund (agent_offline, ...)
    """
    res = await database.enqueue_action(
        agent_id, hostname, pkg["name"],
        pkg.get("display_name") or pkg["name"],
        pkg.get("type") or "custom", action,
        priority=priority, request=request, triggered_by=triggered_by,
        workflow_run_id=workflow_run_id, metadata=metadata,
    )
    if res["duplicate"]:
        return {
            "duplicate": True, "log_id": res["log_id"],
            "status": res.get("status"), "action": res.get("action"),
        }
    if kick_now:
        try:
            await kick(agent_id)
        except Exception:
            # Eingereiht ist eingereiht — der Tick holt es nach.
            logger.exception("enqueue: kick fuer %s fehlgeschlagen", agent_id[:12])
    return await describe(res["log_id"])


async def describe(log_id: int) -> dict:
    """Aktueller Stand eines Eintrags fuer Antworten an Kiosk/Admin."""
    pos = await database.queue_position(log_id) or {}
    reason = None
    if pos.get("status") == "queued":
        entry = await database.get_action_log_detail(log_id)
        reason = (entry or {}).get("queue_reason")
    return {
        "duplicate": False,
        "log_id": log_id,
        "started": pos.get("status") not in (None, "queued"),
        "status": pos.get("status"),
        "position": pos.get("position") if pos.get("status") == "queued" else None,
        "current": pos.get("current"),
        "reason": reason,
    }


# ── Drain ────────────────────────────────────────────────────────────────────

async def kick(agent_id: str) -> None:
    """Stellt fuer jede Lane des Agents den naechsten Eintrag zu, sofern frei."""
    async with _lock(agent_id):
        for lane in database.QUEUE_LANES:
            try:
                await _drain_lane(agent_id, lane)
            except Exception:
                logger.exception("queue: drain %s/%s fehlgeschlagen", agent_id[:12], lane)


def kick_soon(agent_id: str) -> None:
    """Kick im Hintergrund — fuer Callbacks, die schnell antworten sollen."""
    if agent_id:
        _spawn_bg(kick(agent_id))


async def _drain_lane(agent_id: str, lane: str) -> None:
    for _ in range(_MAX_CLAIMS_PER_LANE):
        if not await database.lane_has_queued(agent_id, lane):
            return
        st = await _agent_status(agent_id)
        if st != "online":
            reason = {
                "offline": "agent_offline",
                "gone": "agent_unknown",
                "check_failed": "rmm_unreachable",
            }.get(st, "agent_offline")
            await database.set_lane_queue_reason(agent_id, lane, reason)
            return
        row = await database.claim_next(agent_id, lane)
        if not row:
            return  # Lane belegt — der Callback des Halters kickt erneut
        if await _deliver(row):
            return  # ein Eintrag in Arbeit, mehr geht in dieser Lane nicht
        # Eintrag wurde ohne Zustellung abgeschlossen (z.B. Paket weg) →
        # naechsten Wartenden versuchen.


async def _deliver(row: dict) -> bool:
    """Baut und versendet einen beanspruchten Eintrag ueber die bestehenden
    Dispatch-Funktionen. True = in Arbeit, False = abgeschlossen ohne Zustellung."""
    from fastapi import HTTPException
    log_id = row["id"]
    agent_id = row["agent_id"]
    hostname = row.get("hostname") or ""
    action = row.get("action")
    try:
        req = json.loads(row.get("request") or "{}")
    except Exception:
        req = {}

    try:
        if lane_is_client(row):
            _spawn_bg(_deliver_client_update(row))
            return True

        from routes import install as inst

        # Workflow-Zeile: nur zustellen, solange der Run laeuft. Abgebrochene
        # oder beendete Runs duerfen nicht nachtraeglich installieren; bei
        # Pause reiht resume() den Step ohnehin neu ein.
        run_id = row.get("workflow_run_id")
        if run_id:
            run = await database.get_workflow_run(run_id)
            if not run or run.get("status") not in ("pending", "running"):
                await database.complete_action_log(
                    log_id, "cancelled",
                    error_summary="Workflow ist nicht mehr aktiv",
                )
                return False

        # Workflow-Script: Code kommt aus dem step_snapshot des Runs
        if row.get("pkg_type") == "script":
            import workflow_engine
            return await workflow_engine.deliver_script_step(row)

        # winget ad-hoc aus dem Agent-Detail: braucht keinen Whitelist-Eintrag
        if req.get("adhoc") and action == "uninstall":
            await inst.dispatch_winget_adhoc_uninstall(
                agent_id, hostname, row["package_name"],
                existing_log_id=log_id, triggered_by=row.get("triggered_by"),
            )
            return True
        if req.get("adhoc") and action == "upgrade":
            await inst.dispatch_winget_adhoc_upgrade(
                agent_id, hostname, row["package_name"],
                existing_log_id=log_id, triggered_by=row.get("triggered_by"),
            )
            return True

        pkg = await database.get_package(row["package_name"])
        if not pkg:
            await database.complete_action_log(
                log_id, "cancelled",
                error_summary="Paket ist nicht mehr freigegeben",
            )
            return False

        common = dict(
            existing_log_id=log_id, allow_duplicate=True,
            triggered_by=row.get("triggered_by"),
        )
        if action == "uninstall":
            await inst.dispatch_uninstall_for_agent(agent_id, hostname, pkg, **common)
        elif action == "downgrade":
            await inst.dispatch_downgrade_for_agent(agent_id, hostname, pkg, **common)
        else:
            await inst.dispatch_install_for_agent(
                agent_id, hostname, pkg,
                version_pin=req.get("version_pin"),
                workflow_run_id=row.get("workflow_run_id"),
                force=bool(req.get("force")),
                **common,
            )
        logger.info(
            "queue: %s %s → agent %s (log %s, Versuch %s)",
            action, row["package_name"], agent_id[:12], log_id, row.get("attempts"),
        )
        return True
    except HTTPException as e:
        # Validierungsfehler aus dem Dispatch: dauerhaft, nicht erneut versuchen.
        await database.complete_action_log(
            log_id, "error", error_summary=str(e.detail)[:300],
        )
        return False
    except Exception:
        logger.exception("queue: Zustellung von log %s fehlgeschlagen", log_id)
        if (row.get("attempts") or 0) >= 3:
            await database.complete_action_log(
                log_id, "error",
                error_summary="Zustellung mehrfach fehlgeschlagen",
            )
            return False
        await database.release_claim(log_id, "dispatch_error")
        return True  # Lane fuer diesen Durchlauf ruhen lassen, Tick versucht es erneut


def lane_is_client(row: dict) -> bool:
    return row.get("lane") == "client" or row.get("pkg_type") == "client_update"


async def _deliver_client_update(row: dict) -> None:
    """Client-Self-Update laeuft heute synchron bis ~5 min — deshalb im
    Hintergrund, damit der Agent-Lock frei bleibt."""
    log_id = row["id"]
    try:
        from routes.admin import _do_client_update, _check_client_update_prereqs
        try:
            await _check_client_update_prereqs()
        except Exception:
            # Build kurzzeitig weg: zurueck in die Queue, naechster Tick
            await database.release_claim(log_id, "client_build_missing")
            return
        ag = await database.get_agent(row["agent_id"])
        if not ag:
            await database.complete_action_log(
                log_id, "cancelled", error_summary="Agent existiert nicht mehr",
            )
            return
        await _do_client_update(row["agent_id"], ag, existing_log_id=log_id)
    except Exception:
        logger.exception("queue: client-update log %s fehlgeschlagen", log_id)
        await database.complete_action_log(
            log_id, "error", error_summary="Client-Update fehlgeschlagen",
        )
    finally:
        kick_soon(row["agent_id"])


# ── Tick ─────────────────────────────────────────────────────────────────────

async def tick() -> None:
    """Netz unter den ereignisgesteuerten Kicks: alle Agents mit Wartenden."""
    for agent_id in await database.agents_with_queued():
        try:
            await kick(agent_id)
        except Exception:
            logger.exception("queue-tick: kick %s fehlgeschlagen", agent_id[:12])
