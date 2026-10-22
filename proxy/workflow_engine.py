"""
workflow_engine.py — Orchestrierung fuer multi-step Workflows.

Steuert den Ablauf von Workflow-Runs: Install-, Script- und Reboot-Steps
werden sequenziell dispatched, Fehler werden per on_failure-Policy behandelt
(abort / skip / retry:N), Timeouts werden via APScheduler erkannt.

Einstiegspunkte:
  start_workflow(workflow_id, agent_id, hostname)  -> run_id
  advance(run_id, action_log_id, status)           <- aus receive_callback
  cancel(run_id)
  check_timeouts()                                 <- APScheduler-Job
  recover_after_restart()                          <- lifespan-Hook
"""
import asyncio
import json
import logging
import secrets
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException

import database
from config import runtime_value
from routes.install import (
    _build_script_and_bootstrap,
    _deliver_command_bg,
    _generate_job_id,
    _ps_quote,
    _spawn_bg,
    dispatch_install_for_agent,
)

logger = logging.getLogger("softshelf")

# ── Interne Hilfsfunktionen ───────────────────────────────────────────────────


async def _public_proxy_url() -> str:
    """Liefert die oeffentlich erreichbare Proxy-URL (ohne trailing slash).
    Fallback auf localhost wenn kein proxy_public_url konfiguriert."""
    from config import get_settings
    url = await runtime_value("proxy_public_url")
    if url:
        return url.rstrip("/")
    cfg = get_settings()
    return f"http://{cfg.host}:{cfg.port}"


# Wie lange ein Install-Step in der Warteschlange warten darf, bevor er
# als timed_out gilt (zusaetzlich zum eigentlichen Step-Timeout).
_QUEUE_WAIT_MAX_H = 6


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_json(s: str | None, default):
    """JSON parsen mit Fallback auf default bei Fehler oder leerem String."""
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


# ── Oeffentliche API ──────────────────────────────────────────────────────────


async def start_workflow(
    workflow_id: int, agent_id: str, hostname: str,
    created_by: str | None = None,
) -> int:
    """Startet einen neuen Workflow-Run fuer einen Agent.

    Prueft ob der Agent bereits einen aktiven Run hat (409 wenn ja),
    laedt den Workflow, legt den Run an und dispatched den ersten Step.

    Args:
        workflow_id: ID des Workflows (aus der workflows-Tabelle).
        agent_id:   Tactical Agent-ID.
        hostname:   Anzeigename des Agents.

    Returns:
        run_id des neuen Workflow-Runs.

    Raises:
        HTTPException 409: Agent hat bereits einen aktiven Run.
        HTTPException 404: Workflow nicht gefunden.
        HTTPException 400: Workflow hat keine Steps.
    """
    # Kein paralleler aktiver Run erlaubt
    existing = await database.get_active_run_for_agent(agent_id)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Agent {hostname!r} hat bereits einen aktiven Workflow-Run "
                f"(run_id={existing['id']}, status={existing['status']}). "
                "Erst abbrechen bevor ein neuer gestartet werden kann."
            ),
        )

    wf = await database.get_workflow(workflow_id)
    if not wf:
        raise HTTPException(status_code=404, detail=f"Workflow {workflow_id} nicht gefunden")

    steps = _parse_json(wf.get("steps"), [])
    if not steps:
        raise HTTPException(
            status_code=400,
            detail=f"Workflow {wf.get('name')!r} hat keine Steps — bitte zuerst bearbeiten.",
        )

    # Snapshot einfrieren — Aenderungen am Workflow beeinflussen laufende Runs nicht
    step_snapshot = json.dumps(steps, ensure_ascii=False)
    run_id = await database.create_workflow_run(
        workflow_id, agent_id, hostname, step_snapshot, created_by=created_by,
    )

    logger.info(
        "workflow run %d gestartet: workflow=%s agent=%s (%s), %d steps",
        run_id, wf.get("name"), agent_id, hostname, len(steps),
    )

    await dispatch_current_step(run_id)
    return run_id


async def dispatch_current_step(run_id: int):
    """Dispatched den aktuellen Step eines laufenden Workflow-Runs.

    Liest current_step aus der DB, laedt den entsprechenden Step aus
    step_snapshot und delegiert an den typ-spezifischen Dispatcher.
    Wenn der Index am Ende des Snapshots steht, wird der Run als
    abgeschlossen markiert.
    """
    run = await database.get_workflow_run(run_id)
    if not run:
        logger.warning("dispatch_current_step: run_id %d nicht gefunden", run_id)
        return
    if run["status"] != "running":
        logger.debug("dispatch_current_step: run %d hat status=%s — nichts zu tun", run_id, run["status"])
        return

    steps = _parse_json(run.get("step_snapshot"), [])
    idx = run.get("current_step", 0)

    if idx >= len(steps):
        # Alle Steps abgearbeitet → Run als completed markieren
        await database.update_workflow_run(run_id, status="completed")
        logger.info("workflow run %d completed (%d steps abgearbeitet)", run_id, len(steps))
        return

    step = steps[idx]
    step_type = step.get("type", "")
    payload = step.get("payload") or {}
    timeout_s = step.get("timeout") or 600

    # Install-Steps: Paket-Timeout aus DB lesen (Office braucht 15-30min)
    if step_type == "install":
        pkg_name = payload.get("package_name")
        if pkg_name:
            pkg = await database.get_package(pkg_name)
            if pkg:
                pkg_timeout = pkg.get("install_timeout") or 120
                # Mindestens Paket-Timeout + 60s Puffer, mindestens 900s
                timeout_s = max(timeout_s, pkg_timeout + 60, 900)

    # Reboot-Steps: Deadline = force_after_hours (default 8h), nicht Step-Timeout
    if step_type == "reboot":
        force_h = int(payload.get("force_after_hours") or 8)
        timeout_s = force_h * 3600

    # Deadline setzen (jetzt + Step-Timeout)
    deadline = (_now_utc() + timedelta(seconds=timeout_s)).strftime("%Y-%m-%d %H:%M:%S")
    await database.update_workflow_run(
        run_id,
        step_deadline_at=deadline,
    )

    logger.info(
        "workflow run %d: dispatche step %d/%d type=%s (timeout=%ds)",
        run_id, idx + 1, len(steps), step_type, timeout_s,
    )

    agent_id = run["agent_id"]
    hostname = run["hostname"]

    if step_type == "install":
        await _dispatch_install_step(run_id, agent_id, hostname, payload)
    elif step_type == "script":
        await _dispatch_script_step(run_id, agent_id, hostname, payload)
    elif step_type == "reboot":
        await _dispatch_reboot_step(run_id, agent_id, hostname, payload, step)
    else:
        logger.error("workflow run %d: unbekannter Step-Typ %r — ueberspringe", run_id, step_type)
        # Unbekannte Steps als skipped behandeln damit der Run nicht stecken bleibt
        await _advance_to_next(run_id)


async def advance(run_id: int, action_log_id: int | None, status: str):
    """Wird aufgerufen wenn ein Step des Runs abgeschlossen wurde.

    Aus receive_callback aufgerufen (oder intern bei reboot-Callback).
    status ist 'success', 'skipped' oder 'error'.

    Auf success/skipped: naechster Step.
    Auf error: on_failure-Policy des Steps auswerten.
    """
    run = await database.get_workflow_run(run_id)
    if not run:
        logger.warning("advance: run_id %d nicht gefunden", run_id)
        return
    if run["status"] != "running":
        logger.debug("advance: run %d hat status=%s — ignoriert", run_id, run["status"])
        return

    steps = _parse_json(run.get("step_snapshot"), [])
    idx = run.get("current_step", 0)

    if idx >= len(steps):
        await database.update_workflow_run(run_id, status="completed")
        return

    step = steps[idx]

    if status in ("success", "skipped"):
        logger.info("workflow run %d step %d: %s → naechster Step", run_id, idx, status)
        await _advance_to_next(run_id)
        return

    # status == "error" — on_failure-Policy auswerten
    on_failure = step.get("on_failure", "abort")
    logger.info("workflow run %d step %d: error, on_failure=%s", run_id, idx, on_failure)

    if on_failure == "skip":
        logger.info("workflow run %d step %d: Fehler uebersprungen (skip-Policy)", run_id, idx)
        await _advance_to_next(run_id)

    elif on_failure and on_failure.startswith("retry:"):
        try:
            max_retries = int(on_failure.split(":", 1)[1])
        except (ValueError, IndexError):
            max_retries = 1

        step_state = _parse_json(run.get("step_state"), {})
        retry_count = step_state.get("retry_count", 0)

        if retry_count < max_retries:
            new_state = dict(step_state)
            new_state["retry_count"] = retry_count + 1
            # CAS statt blindem Update: zwei parallele Error-Callbacks
            # (Agent re-POSTet bei Timeout) wuerden sonst beide retry_count
            # inkrementieren und beide dispatchen — der zweite Dispatch
            # laeuft in den Dedup-409 und beerdigt den laufenden Retry.
            swapped = await database.cas_workflow_step_state(
                run_id, run.get("step_state"), json.dumps(new_state),
            )
            if not swapped:
                logger.info(
                    "workflow run %d step %d: Retry bereits von parallelem "
                    "Callback gezogen — ignoriert", run_id, idx,
                )
                return
            logger.info(
                "workflow run %d step %d: Retry %d/%d",
                run_id, idx, retry_count + 1, max_retries,
            )
            await dispatch_current_step(run_id)
        else:
            logger.warning(
                "workflow run %d step %d: max. Retries (%d) erreicht — abgebrochen",
                run_id, idx, max_retries,
            )
            await database.update_workflow_run(run_id, status="failed")

    else:
        # "abort" (Default) oder unbekannte Policy
        logger.warning(
            "workflow run %d step %d: Fehler mit abort-Policy — Run abgebrochen",
            run_id, idx,
        )
        await database.update_workflow_run(run_id, status="failed")


async def cancel(run_id: int):
    """Bricht einen laufenden Workflow-Run ab."""
    run = await database.get_workflow_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Workflow-Run {run_id} nicht gefunden")
    if run["status"] not in ("pending", "running"):
        raise HTTPException(
            status_code=400,
            detail=f"Workflow-Run {run_id} kann nicht abgebrochen werden (status={run['status']})",
        )
    await database.update_workflow_run(run_id, status="cancelled")
    logger.info("workflow run %d cancelled", run_id)

    # Wenn aktueller Step ein Reboot war: AtStartup-Task auf dem Agent loeschen
    try:
        state = _parse_json(run.get("step_state"), {})
        task_name = state.get("task_name")
        if task_name and state.get("reboot_pending"):
            from rmm import get_rmm_client
            tc = get_rmm_client()
            cmd = f"schtasks /Delete /TN '{task_name}' /F 2>$null; Write-Output 'task deleted'"
            _spawn_bg(tc.run_command(run["agent_id"], cmd, timeout=10))
            logger.info("workflow run %d: cleanup AtStartup task %s on agent", run_id, task_name)
    except Exception as e:
        logger.warning("workflow run %d: failed to cleanup AtStartup task: %s", run_id, e)


async def pause(run_id: int):
    """Pausiert einen laufenden Workflow-Run. Aktueller Step laeuft ggf. noch
    zu Ende, aber advance() dispatcht keinen naechsten Step."""
    run = await database.get_workflow_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Workflow-Run {run_id} nicht gefunden")
    if run["status"] != "running":
        raise HTTPException(
            status_code=400,
            detail=f"Workflow-Run {run_id} kann nicht pausiert werden (status={run['status']})",
        )
    await database.update_workflow_run(run_id, status="paused")
    logger.info("workflow run %d paused", run_id)


_RESUMABLE_STATES = ("paused", "failed", "timed_out")


async def resume(run_id: int, from_step: int | None = None):
    """Setzt einen pausierten/failed/timed_out Run fort.

    Optional from_step setzt current_step neu (Skip-forward bei failed Run).
    None = retry current_step (z.B. nach Container-Restart-Heilung).

    Vor Re-Dispatch werden alle noch offenen action_log-Eintraege dieses Runs
    als error markiert. Damit triggert ein evtl. spaet eingetroffener Callback
    keinen Doppel-Advance und _dispatch_install_step laeuft nicht in einen
    Doppel-pending-Konflikt.
    """
    run = await database.get_workflow_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Workflow-Run {run_id} nicht gefunden")
    if run["status"] not in _RESUMABLE_STATES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Workflow-Run {run_id} kann nicht fortgesetzt werden "
                f"(status={run['status']}, erlaubt: {list(_RESUMABLE_STATES)})"
            ),
        )

    # from_step validieren falls angegeben
    steps = _parse_json(run.get("step_snapshot"), [])
    if from_step is not None:
        if not isinstance(from_step, int) or from_step < 0 or from_step >= len(steps):
            raise HTTPException(
                status_code=400,
                detail=f"from_step muss zwischen 0 und {len(steps) - 1} liegen",
            )
        await database.update_workflow_run(
            run_id, current_step=from_step, step_state="{}",
        )
        logger.info("workflow run %d resume: skip-to-step %d", run_id, from_step)

    # Orphane action_logs des Runs cleanen (Container-Restart-Zombies o.ae.)
    cleaned = await database.abort_orphan_action_logs_for_run(
        run_id,
        error_summary="Run wurde fortgesetzt — pending action_log als orphan markiert",
    )
    if cleaned:
        logger.info("workflow run %d resume: %d orphan action_log(s) auf error gesetzt", run_id, cleaned)

    await database.update_workflow_run(run_id, status="running")
    logger.info("workflow run %d resumed, dispatching current step", run_id)
    await dispatch_current_step(run_id)


# Wie lange ein angeforderter Neustart auf das Ende einer laufenden
# Installation wartet, bevor er trotzdem ausgefuehrt wird (Entscheidung E5).
_REBOOT_WAIT_FOR_INSTALL_MAX_MIN = 60


async def request_reboot(run: dict, *, forced: bool = False) -> dict:
    """Neustart fuer einen Run anfordern statt sofort auszuloesen.

    Ist der Installer-Slot frei, wird sofort neu gestartet. Laeuft gerade
    eine Installation, wartet der Neustart darauf (process_pending_reboots,
    minuetlich) — bis hoechstens _REBOOT_WAIT_FOR_INSTALL_MAX_MIN. Solange
    der Neustart ansteht, beansprucht die Warteschlange nichts Neues.
    Returns {"triggered": bool, "waiting_for": str|None}."""
    state = _parse_json(run.get("step_state"), {})
    state["reboot_requested"] = True
    state.setdefault("reboot_requested_at", _now_utc().strftime("%Y-%m-%d %H:%M:%S"))
    if forced:
        state["reboot_forced"] = True
    await database.update_workflow_run(
        run["id"], step_state=json.dumps(state),
        # Wartezeit auf die Installation darf den Run nicht timed_out setzen
        step_deadline_at=(_now_utc() + timedelta(
            minutes=_REBOOT_WAIT_FOR_INSTALL_MAX_MIN + 60)).strftime("%Y-%m-%d %H:%M:%S"),
    )
    fresh = await database.get_workflow_run(run["id"]) or run
    triggered = await _try_execute_reboot(fresh)
    holder = None if triggered else await database.installer_lane_holder(run["agent_id"])
    return {"triggered": triggered,
            "waiting_for": (holder or {}).get("display_name") or (holder or {}).get("package_name")}


async def _try_execute_reboot(run: dict) -> bool:
    """Fuehrt einen angeforderten Neustart aus, wenn der Installer-Slot frei
    ist oder die Wartezeit abgelaufen ist. True = Shutdown abgesetzt."""
    state = _parse_json(run.get("step_state"), {})
    if not state.get("reboot_requested") or state.get("reboot_triggered"):
        return False
    holder = await database.installer_lane_holder(run["agent_id"])
    forced_now = False
    if holder:
        try:
            req_at = datetime.strptime(
                state.get("reboot_requested_at") or "", "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            req_at = _now_utc()
        waited = (_now_utc() - req_at).total_seconds() / 60
        if waited < _REBOOT_WAIT_FOR_INSTALL_MAX_MIN:
            return False
        # E5: nach der Wartezeit trotzdem — die Installation haengt mit
        # hoher Wahrscheinlichkeit. Sichtbar als Fehler im Aktionsprotokoll.
        logger.warning(
            "workflow run %d: Neustart wartet seit %d min auf %s — erzwinge",
            run["id"], int(waited), holder.get("package_name"),
        )
        await database.complete_action_log(
            holder["id"], "error",
            error_summary="Abgebrochen durch Workflow-Neustart nach "
                          f"{_REBOOT_WAIT_FOR_INSTALL_MAX_MIN} min Wartezeit",
        )
        forced_now = True

    from rmm import get_rmm_client
    brand = (await runtime_value("admin_portal_title")) or "Softshelf"
    safe_brand = brand.replace('"', "'")[:80]
    if state.get("reboot_forced") or forced_now:
        cmd = f'shutdown /r /t 60 /c "{safe_brand}: Erzwungener Neustart" /d p:4:1'
    elif state.get("reboot_waited"):
        cmd = f'shutdown /r /t 60 /c "{safe_brand}: Neustart nach Abschluss der Installation" /d p:4:1'
    else:
        cmd = 'shutdown /r /t 5 /d p:4:1'
    try:
        await get_rmm_client().run_command(run["agent_id"], cmd, timeout=10)
    except Exception:
        logger.exception("workflow run %d: Shutdown-Zustellung fehlgeschlagen", run["id"])
        return False
    state["reboot_triggered"] = True
    await database.update_workflow_run(
        run["id"], step_state=json.dumps(state),
        step_deadline_at=(_now_utc() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
    )
    logger.info("workflow run %d: Neustart ausgeloest (%s)", run["id"], cmd.split(" /c ")[0])
    return True


async def process_pending_reboots() -> None:
    """Minuetlich: angeforderte Neustarts ausfuehren, sobald der Agent
    keine Installation mehr laufen hat (oder die Wartezeit abgelaufen ist)."""
    for run in await database.get_runs_with_reboot_request():
        try:
            state = _parse_json(run.get("step_state"), {})
            if not state.get("reboot_waited"):
                # Merken, dass gewartet wurde → Shutdown mit Vorwarnung statt /t 5
                state["reboot_waited"] = True
                await database.update_workflow_run(run["id"], step_state=json.dumps(state))
                run = await database.get_workflow_run(run["id"]) or run
            await _try_execute_reboot(run)
        except Exception:
            logger.exception("process_pending_reboots: run %s", run.get("id"))


async def check_timeouts():
    """APScheduler-Job: prueft ueberfaellige Workflow-Runs und markiert sie als timed_out.

    Wird minuetlich aufgerufen. Overdue = status=running und
    step_deadline_at liegt in der Vergangenheit.

    Zusaetzlich: Force-Reboot fuer Reboot-Steps die zu lange pending sind
    (force_after_hours abgelaufen, kein Client hat reagiert).
    """
    # Angeforderte Neustarts zuerst — unabhaengig davon, ob etwas ueberfaellig ist
    try:
        await process_pending_reboots()
    except Exception:
        logger.exception("check_timeouts: process_pending_reboots")
    try:
        overdue = await database.get_overdue_workflow_runs()
        if not overdue:
            return
        for run in overdue:
            # Pruefen ob es ein Reboot-Step ist der force-reboot braucht
            state = _parse_json(run.get("step_state"), {})
            if state.get("reboot_pending") and not state.get("reboot_triggered"):
                # TOCTOU-Guard: Status nochmal frisch aus DB lesen
                fresh = await database.get_workflow_run(run["id"])
                if not fresh or fresh["status"] != "running":
                    logger.info("workflow run %d: skip force-reboot (status=%s)",
                                run["id"], (fresh or {}).get("status"))
                    continue
                # Force-Reboot: Client hat nicht reagiert, Deadline abgelaufen.
                # Nicht sofort: als Anforderung, die auf eine laufende
                # Installation wartet (E5, hoechstens 60 min).
                logger.warning(
                    "workflow run %d: reboot force-trigger (deadline abgelaufen)",
                    run["id"],
                )
                try:
                    res = await request_reboot(fresh, forced=True)
                    if not res["triggered"]:
                        logger.info(
                            "workflow run %d: erzwungener Neustart wartet auf %s",
                            run["id"], res.get("waiting_for"),
                        )
                except Exception as e:
                    logger.exception("force-reboot request failed for run %d: %s", run["id"], e)
                    await database.update_workflow_run(run["id"], status="timed_out")
            else:
                logger.warning(
                    "workflow run %d timeout: step=%d, deadline=%s — markiere als timed_out",
                    run["id"], run.get("current_step", 0), run.get("step_deadline_at"),
                )
                await database.update_workflow_run(run["id"], status="timed_out")
    except Exception as e:
        logger.exception("check_timeouts crashed: %s", e)


async def recover_after_restart():
    """Lifespan-Hook: stellt laufende Runs nach Container-Neustart wieder her.

    Wird beim App-Start aufgerufen. Prueft ob die Deadline noch nicht
    abgelaufen ist — wenn ja, re-dispatched den aktuellen Step.
    Abgelaufene Runs werden direkt als timed_out markiert.
    """
    try:
        runs = await database.get_running_workflow_runs()
        if not runs:
            return
        now = _now_utc()
        for run in runs:
            deadline_raw = run.get("step_deadline_at")
            run_id = run["id"]
            if deadline_raw:
                try:
                    dl = datetime.fromisoformat(deadline_raw.replace(" ", "T"))
                    if dl.tzinfo is None:
                        dl = dl.replace(tzinfo=timezone.utc)
                    if dl < now:
                        logger.info(
                            "recover: workflow run %d deadline abgelaufen (%s) → timed_out",
                            run_id, deadline_raw,
                        )
                        await database.update_workflow_run(run_id, status="timed_out")
                        continue
                except Exception as e:
                    logger.warning("recover: deadline parse fuer run %d: %s", run_id, e)
            # Deadline noch gueltig oder nicht gesetzt — re-dispatch.
            # Vorher orphan action_logs cleanen damit Re-Dispatch nicht in
            # einen Doppel-pending-Konflikt laeuft (Container-Restart hat den
            # fire-and-forget _deliver_command_bg ggf. gekillt bevor Tactical
            # den Befehl annahm — Zombie-action_log mit status=running ist die
            # Folge, der Re-Dispatch wuerde sonst eine Exception werfen).
            try:
                cleaned = await database.abort_orphan_action_logs_for_run(
                    run_id,
                    error_summary="Container-Restart waehrend Dispatch — orphan action_log",
                )
                if cleaned:
                    logger.info("recover: run %d — %d orphan action_log(s) auf error gesetzt", run_id, cleaned)
            except Exception as e:
                logger.warning("recover: orphan-action_log cleanup fuer run %d: %s", run_id, e)
            logger.info("recover: re-dispatche workflow run %d (step=%d)", run_id, run.get("current_step", 0))
            _spawn_bg(dispatch_current_step(run_id))
    except Exception as e:
        logger.exception("recover_after_restart crashed: %s", e)


# ── Interne Step-Dispatcher ───────────────────────────────────────────────────


async def _advance_to_next(run_id: int):
    """Setzt den Run auf den naechsten Step und dispatched ihn.

    Verwendet ein atomares UPDATE mit WHERE current_step = expected als
    Concurrency-Guard — verhindert Doppel-Advance bei parallelen Callbacks.
    """
    run = await database.get_workflow_run(run_id)
    if not run:
        return
    expected_step = run.get("current_step", 0)
    next_idx = expected_step + 1
    # Atomic: only advance if step hasn't changed (concurrency guard)
    async with database._db() as db:
        result = await db.execute(
            "UPDATE workflow_runs SET current_step = ?, step_state = '{}', "
            "step_deadline_at = NULL, updated_at = datetime('now') "
            "WHERE id = ? AND current_step = ? AND status = 'running'",
            (next_idx, run_id, expected_step),
        )
        await db.commit()
        if result.rowcount == 0:
            logger.warning("advance: run %d lost update (step was %d)", run_id, expected_step)
            return
    await dispatch_current_step(run_id)


async def _dispatch_install_step(
    run_id: int, agent_id: str, hostname: str, payload: dict
):
    """Dispatched einen install-Step: laedt das Paket aus der DB und startet
    den gewohnten install-Flow via dispatch_install_for_agent."""
    package_name = payload.get("package_name")
    if not package_name:
        logger.error("workflow run %d install-step: package_name fehlt in payload", run_id)
        await database.update_workflow_run(run_id, status="failed")
        return

    pkg = await database.get_package(package_name)
    if not pkg:
        logger.error(
            "workflow run %d install-step: Paket %r nicht gefunden", run_id, package_name
        )
        await database.update_workflow_run(run_id, status="failed")
        return

    version_pin = payload.get("version_pin") or None

    # Ueber die Warteschlange: ein Workflow-Install darf nicht parallel zu
    # einer Kiosk- oder Admin-Installation laufen (Windows-Installer-Mutex).
    # Erster Step reiht sich gleichrangig mit Benutzerklicks ein (E6),
    # Folgesteps laufen mit Vorrang, damit der Run nicht zerfasert.
    import action_queue
    run = await database.get_workflow_run(run_id) or {}
    prio = (database.PRIO_INTERACTIVE if int(run.get("current_step") or 0) == 0
            else database.PRIO_CONTINUATION)
    try:
        res = await action_queue.enqueue(
            agent_id, hostname, pkg, "install",
            priority=prio, triggered_by=f"workflow:{run_id}",
            request={"version_pin": version_pin},
            workflow_run_id=run_id,
        )
    except Exception as e:
        logger.exception(
            "workflow run %d install-step fuer %r: Einreihen fehlgeschlagen: %s",
            run_id, package_name, e,
        )
        await database.update_workflow_run(run_id, status="failed")
        return

    if res.get("duplicate"):
        # Fuer das Paket ist schon etwas offen. Gleiche Absicht → uebernehmen,
        # dann advanced dessen Callback diesen Run. Andere Absicht (z.B. ein
        # offener Uninstall) → Step scheitert sichtbar statt still zu haengen.
        if res.get("action") in ("install", "upgrade", "reinstall") and res.get("log_id"):
            adopted = await database.adopt_for_workflow(res["log_id"], run_id, prio)
            logger.info(
                "workflow run %d install-step %r: offenen Eintrag %s %s",
                run_id, package_name, res["log_id"],
                "uebernommen" if adopted else "gehoert schon zum Run",
            )
        else:
            logger.warning(
                "workflow run %d install-step %r: andere Aktion offen (%s) — Step scheitert",
                run_id, package_name, res.get("action"),
            )
            await database.update_workflow_run(run_id, status="failed")
            return
    else:
        logger.info(
            "workflow run %d install-step: %s %s %s",
            run_id, pkg.get("type"), package_name,
            "gestartet" if res.get("started") else f"eingereiht (Position {res.get('position')})",
        )

    # Wartezeit in der Queue darf den Step nicht in den Timeout treiben:
    # Deadline um die maximale Wartezeit verlaengern, solange nicht gestartet.
    if not res.get("started"):
        try:
            cur = (await database.get_workflow_run(run_id) or {}).get("step_deadline_at")
            base = (datetime.strptime(cur, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    if cur else _now_utc())
            new_dl = (base + timedelta(hours=_QUEUE_WAIT_MAX_H)).strftime("%Y-%m-%d %H:%M:%S")
            await database.update_workflow_run(run_id, step_deadline_at=new_dl)
        except Exception:
            logger.exception("workflow run %d: Deadline-Verlaengerung fehlgeschlagen", run_id)


def _script_code(run_id: int, raw_code: str) -> str:
    """Wrapper fuer den User-Code eines Script-Steps.

    User-Code als temp .ps1 schreiben und via powershell.exe -File
    ausfuehren. Damit beendet 'exit N' nur den inneren Prozess und
    der aeussere (Callback-Wrapper) kann den exit code melden.
    Base64-Transport statt Heredoc: ein Here-String-Literal bricht, sobald
    der User-Code selbst eine Zeile hat die mit '@ beginnt (oder ein eigenes
    Here-String enthaelt) — der Rest liefe dann im Wrapper-Kontext.
    UTF-8-BOM voranstellen: powershell.exe -File liest BOM-loses UTF-8 als
    ANSI — Umlaute im User-Script waeren sonst kaputt."""
    import base64 as _b64
    code_b64 = _b64.b64encode(raw_code.encode("utf-8")).decode("ascii")
    lines = [
        f"$_wfTmp = [System.IO.Path]::Combine($env:TEMP, 'softshelf-wf-{run_id}.ps1')",
        "[System.IO.File]::WriteAllBytes($_wfTmp, "
        f"[byte[]](0xEF,0xBB,0xBF) + [Convert]::FromBase64String('{code_b64}'))",
        "& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $_wfTmp 2>&1",
        "$global:LASTEXITCODE = $LASTEXITCODE",
        "Remove-Item $_wfTmp -Force -ErrorAction SilentlyContinue",
    ]
    return chr(10).join(lines) + chr(10)


async def _script_step_title(run: dict, step: int) -> str:
    """Anzeigename eines Script-Steps im Action-Log: Workflow-Name plus
    Step-Bezeichnung aus dem Editor, z.B. 'WLAN-Fix · Registry setzen'.
    Ohne Bezeichnung 'WLAN-Fix · Schritt 2/3', bei nur einem Step nur der
    Workflow-Name."""
    try:
        steps = json.loads(run.get("step_snapshot") or "[]")
    except Exception:
        steps = []
    label = ""
    if 0 <= step < len(steps):
        label = str(steps[step].get("label") or "").strip()
    name = ""
    if run.get("workflow_id"):
        wf = await database.get_workflow(int(run["workflow_id"]))
        name = str((wf or {}).get("name") or "").strip()
    name = name or "Workflow"
    total = len(steps)
    if label:
        title = f"{name} · {label}"
    elif total > 1:
        title = f"{name} · Schritt {step + 1}/{total}"
    else:
        title = name
    return title[:120]


async def _dispatch_script_step(
    run_id: int, agent_id: str, hostname: str, payload: dict
):
    """Reiht einen script-Step in die Installer-Lane ein. Ein Script kann
    selbst msiexec/winget aufrufen und darf deshalb nicht parallel zu einer
    Installation laufen. Den Code holt deliver_script_step() erst beim
    Zustellen aus dem step_snapshot."""
    raw_code = payload.get("code") or ""
    if not raw_code.strip():
        logger.error("workflow run %d script-step: kein Code in payload", run_id)
        await database.update_workflow_run(run_id, status="failed")
        return

    import action_queue
    run = await database.get_workflow_run(run_id) or {}
    step = int(run.get("current_step") or 0)
    prio = database.PRIO_INTERACTIVE if step == 0 else database.PRIO_CONTINUATION
    res = await action_queue.enqueue(
        agent_id, hostname,
        {"name": f"workflow:{run_id}:script",
         "display_name": await _script_step_title(run, step), "type": "script"},
        "run", priority=prio, triggered_by=f"workflow:{run_id}",
        request={"step": step}, workflow_run_id=run_id,
    )
    if res.get("duplicate"):
        logger.info("workflow run %d script-step %d: bereits offen (log %s)",
                    run_id, step + 1, res.get("log_id"))
        return
    logger.info(
        "workflow run %d script-step %d: %s", run_id, step + 1,
        "gestartet" if res.get("started") else f"eingereiht (Position {res.get('position')})",
    )
    if not res.get("started"):
        try:
            cur = (await database.get_workflow_run(run_id) or {}).get("step_deadline_at")
            base = (datetime.strptime(cur, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    if cur else _now_utc())
            new_dl = (base + timedelta(hours=_QUEUE_WAIT_MAX_H)).strftime("%Y-%m-%d %H:%M:%S")
            await database.update_workflow_run(run_id, step_deadline_at=new_dl)
        except Exception:
            logger.exception("workflow run %d: Deadline-Verlaengerung fehlgeschlagen", run_id)


async def deliver_script_step(row: dict) -> bool:
    """Vom Queue-Drain aufgerufen: baut den Script-Step aus dem step_snapshot
    und stellt ihn zu. False = Eintrag ohne Zustellung abgeschlossen."""
    run_id = row["workflow_run_id"]
    run = await database.get_workflow_run(run_id)
    try:
        step = int(json.loads(row.get("request") or "{}").get("step"))
    except Exception:
        step = -1
    if not run or step != int(run.get("current_step") or 0):
        await database.complete_action_log(
            row["id"], "cancelled", error_summary="Workflow ist bereits weiter",
        )
        return False
    try:
        steps = json.loads(run.get("step_snapshot") or "[]")
        raw_code = (steps[step].get("payload") or {}).get("code") or ""
    except Exception:
        raw_code = ""
    if not raw_code.strip():
        await database.complete_action_log(
            row["id"], "error", error_summary="Script-Step ohne Code",
        )
        return False

    job_id = _generate_job_id()
    cmd = await _build_script_and_bootstrap(_script_code(run_id, raw_code), job_id)
    await database.repurpose_queued_action_log(row["id"], job_id=job_id, action="run")
    _spawn_bg(_deliver_command_bg(
        agent_id=row["agent_id"],
        hostname=row.get("hostname") or "",
        package_name=row["package_name"],
        display_name=row.get("display_name") or await _script_step_title(run, step),
        cmd=cmd,
        action="run",
        pkg_type="script",
        log_id=row["id"],
    ))
    return True
    logger.info("workflow run %d script-step: job_id=%s dispatched", run_id, job_id[:8])


async def _dispatch_reboot_step(
    run_id: int, agent_id: str, hostname: str, payload: dict, step: dict
):
    """Dispatched einen reboot-Step.

    Registriert einen AtStartup-Task der nach dem Neustart einen
    Callback an den Proxy sendet, dann initiiert den Neustart via
    'shutdown /r'. Der Proxy-seitige Callback triggert dann advance().
    """
    countdown = int(payload.get("countdown") or 300)
    if payload.get("message"):
        message = payload["message"]
    else:
        brand = (await runtime_value("admin_portal_title")) or "Softshelf"
        message = f"{brand}: Systemneustart erforderlich"
    max_deferrals = int(payload.get("max_deferrals") or 3)

    # message fuer shutdown /c darf max. 512 Zeichen haben, kein Newline
    safe_shutdown_msg = message.replace('"', "'").replace("\n", " ")[:512]
    # PowerShell-Safe (single-quoted)
    ps_msg = _ps_quote(message)
    ps_shutdown_msg = _ps_quote(safe_shutdown_msg)

    job_id = _generate_job_id()
    base = await _public_proxy_url()
    callback_url = f"{base}/api/v1/callback/{job_id}"
    ps_callback_url = _ps_quote(callback_url)

    # Task-Name: eindeutig pro Run damit kein Konflikt bei mehreren Reboots
    task_name = f"SoftshelReboot_{run_id}"
    ps_task_name = _ps_quote(task_name)

    # Reboot-Callback-Task: feuert AtStartup + bei JEDEM User-Logon. Zwei Trigger
    # weil bei Zscaler/VPN-Clients der Tunnel oft erst nach User-Login hochkommt
    # und ein reiner AtStartup-Versuch ins Leere geht. Bei Erfolg loescht sich
    # der Task selbst — bei Misserfolg bleibt er registriert und versucht es
    # beim naechsten Logon erneut.
    reboot_script = f"""$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$taskName = '{ps_task_name}'
$callbackUrl = '{ps_callback_url}'

$postScript = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$url = '{ps_callback_url}'
$body = '{{"exit_code":0,"output":"Neustart abgeschlossen","success":true,"final":true}}'
# Lange Retry-Strecke: Zscaler/VPN-Tunnel braucht oft 1-3 min nach Logon
$delays = @(0, 10, 20, 40, 60, 90, 120, 180, 240)
$ok = $false
foreach ($d in $delays) {{
    if ($d -gt 0) {{ Start-Sleep -Seconds $d }}
    try {{
        $req = [Net.HttpWebRequest]::Create($url)
        $req.Method = 'POST'
        $req.ContentType = 'application/json'
        $req.Timeout = 15000
        $req.Proxy = [Net.GlobalProxySelection]::GetEmptyWebProxy()
        $bytes = [Text.Encoding]::UTF8.GetBytes($body)
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream(); $s.Write($bytes,0,$bytes.Length); $s.Close()
        $req.GetResponse().Close()
        $ok = $true
        break
    }} catch {{}}
}}
# Task NUR bei Erfolg loeschen — sonst bleibt er fuer naechsten Logon-Versuch erhalten.
if ($ok) {{
    schtasks /Delete /TN '{ps_task_name}' /F 2>$null
}}
'@

# Script in TEMP ablegen
$scriptPath = Join-Path (Join-Path $env:SystemRoot 'Temp') 'sf_reboot_cb_{run_id}.ps1'
[System.IO.File]::WriteAllText($scriptPath, $postScript, [Text.Encoding]::UTF8)

# Zwei Trigger anlegen: AtStartup (SYSTEM, Tunnel evtl. noch nicht da) +
# AtLogon (irgendein User — typischerweise wenn Zscaler-Client auch ready ist).
$tStart = New-ScheduledTaskTrigger -AtStartup
$tLogon = New-ScheduledTaskTrigger -AtLogOn
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 8) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

Register-ScheduledTask -TaskName '{ps_task_name}' `
    -Action $action -Trigger @($tStart, $tLogon) `
    -Settings $settings -Principal $principal -Force | Out-Null

Write-Output "Reboot-Callback-Task registriert: {task_name} (AtStartup + AtLogon)"
Write-Output "Warte auf Reboot-Trigger vom Client oder Force-Timeout..."
"""

    try:
        cmd = await _build_script_and_bootstrap(reboot_script, job_id, skip_final_callback=True)
    except Exception as e:
        logger.exception("workflow run %d reboot-step: _build_script_and_bootstrap: %s", run_id, e)
        await database.update_workflow_run(run_id, status="failed")
        return

    # Step-State: reboot_pending=True damit Client-Polling es sehen kann
    step_state = json.dumps({
        "reboot_pending": True,
        "deferrals": 0,
        "max_deferrals": max_deferrals,
        "job_id": job_id,
        "task_name": task_name,
    })
    await database.update_workflow_run(run_id, step_state=step_state)

    log_id = await database.create_action_log(
        agent_id=agent_id,
        hostname=hostname,
        package_name=f"workflow:{run_id}:reboot",
        display_name=f"Workflow-Neustart ({message[:60]})",
        pkg_type="script",
        action="reboot",
        job_id=job_id,
        workflow_run_id=run_id,
    )

    _spawn_bg(_deliver_command_bg(
        agent_id=agent_id,
        hostname=hostname,
        package_name=f"workflow:{run_id}:reboot",
        display_name=f"Neustart: {message[:60]}",
        cmd=cmd,
        action="reboot",
        pkg_type="script",
        log_id=log_id,
    ))
    logger.info(
        "workflow run %d reboot-step: countdown=%ds, task=%s, job_id=%s dispatched",
        run_id, countdown, task_name, job_id[:8],
    )
