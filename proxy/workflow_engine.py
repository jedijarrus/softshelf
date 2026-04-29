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


async def start_workflow(workflow_id: int, agent_id: str, hostname: str) -> int:
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
    run_id = await database.create_workflow_run(workflow_id, agent_id, hostname, step_snapshot)

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
            await database.update_workflow_run(
                run_id, step_state=json.dumps(new_state)
            )
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


async def resume(run_id: int):
    """Setzt einen pausierten Workflow-Run fort."""
    run = await database.get_workflow_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Workflow-Run {run_id} nicht gefunden")
    if run["status"] != "paused":
        raise HTTPException(
            status_code=400,
            detail=f"Workflow-Run {run_id} kann nicht fortgesetzt werden (status={run['status']})",
        )
    await database.update_workflow_run(run_id, status="running")
    logger.info("workflow run %d resumed, dispatching current step", run_id)
    await dispatch_current_step(run_id)


async def check_timeouts():
    """APScheduler-Job: prueft ueberfaellige Workflow-Runs und markiert sie als timed_out.

    Wird minuetlich aufgerufen. Overdue = status=running und
    step_deadline_at liegt in der Vergangenheit.

    Zusaetzlich: Force-Reboot fuer Reboot-Steps die zu lange pending sind
    (force_after_hours abgelaufen, kein Client hat reagiert).
    """
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
                # Force-Reboot: Client hat nicht reagiert, Deadline abgelaufen
                logger.warning(
                    "workflow run %d: reboot force-trigger (deadline abgelaufen)",
                    run["id"],
                )
                try:
                    from tactical_client import TacticalClient
                    tc = TacticalClient()
                    await tc.run_command(
                        fresh["agent_id"],
                        'shutdown /r /t 60 /c "Softshelf: Erzwungener Neustart" /d p:4:1',
                        timeout=10,
                    )
                    state["reboot_triggered"] = True
                    await database.update_workflow_run(
                        run["id"], step_state=json.dumps(state),
                        step_deadline_at=(
                            datetime.now(timezone.utc) + timedelta(hours=1)
                        ).strftime("%Y-%m-%d %H:%M:%S"),
                    )
                except Exception as e:
                    logger.exception("force-reboot dispatch failed for run %d: %s", run["id"], e)
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
            # Deadline noch gueltig oder nicht gesetzt — re-dispatch
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

    try:
        result = await dispatch_install_for_agent(
            agent_id,
            hostname,
            pkg,
            version_pin=version_pin,
            workflow_run_id=run_id,
        )
        logger.info(
            "workflow run %d install-step: %s %s dispatched (action=%s)",
            run_id, result.get("type"), package_name, result.get("action"),
        )
    except Exception as e:
        logger.exception(
            "workflow run %d install-step fuer %r fehlgeschlagen: %s",
            run_id, package_name, e,
        )
        await database.update_workflow_run(run_id, status="failed")


async def _dispatch_script_step(
    run_id: int, agent_id: str, hostname: str, payload: dict
):
    """Dispatched einen script-Step: baut ein PS-Script aus dem eingebetteten
    Code, legt einen action_log-Eintrag an und startet die Delivery."""
    raw_code = payload.get("code") or ""
    if not raw_code.strip():
        logger.error("workflow run %d script-step: kein Code in payload", run_id)
        await database.update_workflow_run(run_id, status="failed")
        return

    # User-Code als temp .ps1 schreiben und via powershell.exe -File
    # ausfuehren. Damit beendet 'exit N' nur den inneren Prozess und
    # der aeussere (Callback-Wrapper) kann den exit code melden.
    # Heredoc-Marker wird unique gemacht damit User-Code ihn nicht
    # versehentlich enthaelt.
    marker = f"__WF{run_id}END__"
    code = (
        f"$_wfTmp = [System.IO.Path]::Combine($env:TEMP, 'softshelf-wf-{run_id}.ps1')\n"
        f"@'\n{raw_code}\n'@ | Set-Content -Path $_wfTmp -Encoding UTF8\n"
        f"& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $_wfTmp 2>&1\n"
        f"$global:LASTEXITCODE = $LASTEXITCODE\n"
        f"Remove-Item $_wfTmp -Force -ErrorAction SilentlyContinue\n"
    )

    job_id = _generate_job_id()
    try:
        cmd = await _build_script_and_bootstrap(code, job_id)
    except Exception as e:
        logger.exception("workflow run %d script-step: _build_script_and_bootstrap: %s", run_id, e)
        await database.update_workflow_run(run_id, status="failed")
        return

    # current_step aus DB lesen fuer display_name
    _run_now = await database.get_workflow_run(run_id)
    _step_num = ((_run_now or {}).get("current_step") or 0) + 1

    log_id = await database.create_action_log(
        agent_id=agent_id,
        hostname=hostname,
        package_name=f"workflow:{run_id}:script",
        display_name=f"Workflow-Script (Step {_step_num})",
        pkg_type="script",
        action="run",
        job_id=job_id,
        workflow_run_id=run_id,
    )

    _spawn_bg(_deliver_command_bg(
        agent_id=agent_id,
        hostname=hostname,
        package_name=f"workflow:{run_id}:script",
        display_name="Workflow-Script",
        cmd=cmd,
        action="run",
        pkg_type="script",
        log_id=log_id,
    ))
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
    message = payload.get("message") or "Softshelf: Systemneustart erforderlich"
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

    # AtStartup Scheduled Task: sendet Callback nach Neustart und loescht sich selbst.
    # Nutzt Net.WebClient (kein Invoke-WebRequest) und leeren Proxy — wie alle anderen
    # PS-Scripts im Projekt.
    reboot_script = f"""$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# AtStartup Task registrieren — laeuft einmal nach Neustart
$taskName = '{ps_task_name}'
$callbackUrl = '{ps_callback_url}'

$postScript = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$url = '{ps_callback_url}'
$body = '{{"exit_code":0,"output":"Neustart abgeschlossen","success":true,"final":true}}'
$delays = @(0, 5, 15, 30, 60)
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
        break
    }} catch {{}}
}}
# Task selbst loeschen
schtasks /Delete /TN '{ps_task_name}' /F 2>$null
'@

# Script in TEMP ablegen
$scriptPath = Join-Path (Join-Path $env:SystemRoot 'Temp') 'sf_reboot_cb_{run_id}.ps1'
[System.IO.File]::WriteAllText($scriptPath, $postScript, [Text.Encoding]::UTF8)

# AtStartup Scheduled Task anlegen (laeuft als SYSTEM)
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

Register-ScheduledTask -TaskName '{ps_task_name}' `
    -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null

Write-Output "AtStartup Task registriert: {task_name}"
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
