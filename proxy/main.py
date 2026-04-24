"""
Softshelf — Proxy
Starten: uvicorn main:app --host 0.0.0.0 --port 8765
Admin:   http(s)://<server>:8765/admin
"""
import logging
import os
import re
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

import admin_auth
import choco_scanner
import database
import file_uploads
import winget_catalog
import winget_scanner
import winget_enrichment
from auth import verify_download_token
from config import RUNTIME_KEYS, get_settings, runtime_int, runtime_value
from middleware.audit_logger import audit_log_middleware
from middleware.csrf import csrf_middleware
from middleware.rate_limit import rate_limit_middleware
from routes import packages, install, admin, register

logger = logging.getLogger("softshelf")

VERSION = "2.1.0"

# /app/downloads — shared volume mit dem builder-Container
DOWNLOADS_DIR = "/app/downloads"


async def _seed_settings_from_env():
    """
    Auf frischem Deploy werden INITIAL_*-Werte aus der .env in die
    settings-Tabelle übernommen. Danach ist die .env (bis auf Bootstrap)
    irrelevant und alles geschieht im Admin-UI.

    Backward-Compat: liest auch die alten Namen (TACTICAL_URL etc.) ohne
    INITIAL_-Prefix, damit bestehende Deployments nach Upgrade sauber
    migrieren ohne manuellen .env-Edit.
    """
    cfg = get_settings()
    current = await database.get_all_settings()

    seeds = {
        "tactical_url": cfg.initial_tactical_url or os.environ.get("TACTICAL_URL", ""),
        "tactical_api_key": cfg.initial_tactical_api_key or os.environ.get("TACTICAL_API_KEY", ""),
        "registration_secret": cfg.initial_registration_secret or os.environ.get("REGISTRATION_SECRET", ""),
        "proxy_public_url": cfg.initial_proxy_public_url or os.environ.get("PROXY_PUBLIC_URL", ""),
    }
    to_apply = {}
    for key, value in seeds.items():
        if value and not current.get(key):
            to_apply[key] = value

    # Auch Defaults für numerische Runtime-Werte eintragen, damit das
    # Settings-UI nicht mit leeren Feldern erscheint
    for key, meta in RUNTIME_KEYS.items():
        if meta.get("type") == "int" and not current.get(key):
            to_apply[key] = meta.get("default", "0")

    if to_apply:
        await database.set_settings_bulk(to_apply)
        logger.info("Settings seeded from .env: %s", list(to_apply.keys()))


async def _winget_catalog_refresh_job():
    """Lädt einmal pro Tag den winget-Source-Cache von Microsoft runter."""
    try:
        await winget_catalog.refresh_cache(force=True)
    except Exception as e:
        logger.exception("winget catalog refresh job crashed: %s", e)


async def _winget_nightly_job():
    """APScheduler-Job-Wrapper: schwerer asyncio-Code, eigene Exception-Boundary
    damit ein Fehler den Scheduler nicht killt."""
    try:
        await winget_scanner.run_nightly_scan()
    except Exception as e:
        logger.exception("nightly winget scan job crashed: %s", e)


async def _winget_enrichment_job():
    try:
        await winget_enrichment.run_enrichment_job()
    except Exception as e:
        logger.exception("winget enrichment job crashed: %s", e)


async def _choco_nightly_job():
    try:
        await choco_scanner.run_nightly_scan()
    except Exception as e:
        logger.exception("nightly choco scan job crashed: %s", e)


async def _action_log_cleanup_job():
    try:
        count = await database.cleanup_action_logs(days=30)
        if count:
            logger.info("action_log cleanup: %d Eintraege entfernt", count)
    except Exception as e:
        logger.warning("action_log cleanup failed: %s", e)
    # Stale Script-Files (aelter als 4h) aufraeumen
    try:
        import glob, time
        scripts_dir = os.path.join(os.path.dirname(__file__), "data", "scripts")
        cutoff = time.time() - 4 * 3600
        stale = [f for f in glob.glob(os.path.join(scripts_dir, "*.ps1"))
                 if os.path.getmtime(f) < cutoff]
        for f in stale:
            os.remove(f)
        if stale:
            logger.info("Script cleanup: %d stale files removed", len(stale))
    except Exception as e:
        logger.warning("Script cleanup failed: %s", e)
    # Stuck entries: pending/running laenger als 4 Stunden → error
    try:
        async with database._db() as db:
            res = await db.execute(
                "UPDATE action_log SET status = 'error', "
                "error_summary = 'Keine Rueckmeldung vom Agent (Timeout nach 30min)', "
                "completed_at = datetime('now') "
                "WHERE status IN ('pending', 'running') "
                "AND created_at < datetime('now', '-30 minutes')"
            )
            if res.rowcount:
                logger.info("action_log stuck cleanup: %d Eintraege als error markiert", res.rowcount)
            await db.commit()
    except Exception as e:
        logger.warning("action_log stuck cleanup failed: %s", e)


async def _rollout_auto_start_tick():
    """Startet fuer alle staged+auto_advance Pakete OHNE aktiven Rollout
    automatisch einen neuen Rollout — sobald Updates verfuegbar sind.

    Konsequenz: staged + auto_advance = kontinuierlicher Rollout. Admin
    setzt einmal die Flags, neue Versionen werden automatisch durch die
    Phasen gepushed.
    """
    try:
        pkgs = await database.get_packages()
        candidates = [
            p for p in pkgs
            if p.get("staged_rollout") and p.get("auto_advance")
        ]
        if not candidates:
            return
        active = await database.get_active_rollout_phases()
        from routes.admin import _dispatch_rollout_phase
        for p in candidates:
            if p["name"] in active:
                continue  # Rollout laeuft bereits
            # Has updates? Check ob mindestens ein Agent outdated ist
            ptype = p.get("type") or "choco"
            has_updates = False
            if ptype == "winget":
                raw = await database.get_agents_with_winget_package(p["name"])
                has_updates = any(r.get("available_version") for r in raw)
            elif ptype == "choco":
                raw = await database.get_agents_with_choco_package(p["name"])
                has_updates = any(r.get("available_version") for r in raw)
            else:
                raw = await database.get_installations_for_package(p["name"])
                has_updates = any(r.get("outdated") for r in raw)
            if not has_updates:
                continue
            # Rollout anlegen + Phase 1 dispatchen
            rollout_id = await database.create_rollout(
                package_name=p["name"],
                display_name=p.get("display_name") or p["name"],
                action="push_update",
                created_by=None,  # system-gestartet
            )
            try:
                await _dispatch_rollout_phase(p, 1)
                logger.info(
                    "auto-started rollout %s for %s (staged + auto_advance)",
                    rollout_id, p["name"],
                )
            except Exception as e:
                logger.exception("auto-start dispatch failed for %s: %s", p["name"], e)
    except Exception as e:
        logger.exception("rollout auto-start tick crashed: %s", e)


async def _rollout_auto_advance_tick():
    """Alle 15 Min: pruefe aktive Rollouts, advance automatisch wenn
    Bedingungen erfuellt:
      1. Das Paket des Rollouts hat packages.auto_advance=1 (opt-in per
         Paket, kein globaler Switch).
      2. Zeit seit last_advanced_at >= rollout_auto_advance_hours_N_to_M.
      3. Fehler-Rate in aktueller Phase unter rollout_max_error_pct
         (0 = striktes Blocken schon bei einem Fehler).

    Fehler-Rate = offene (un-acked) Fehler mit
    last_action_package == rollout.package_name / Agents-in-Stage.
    """
    from datetime import datetime, timezone, timedelta
    try:
        from config import runtime_value
        # Per-Transition Wartezeit: 1→2 vs 2→3 separat konfigurierbar.
        # Fallback fuer Legacy-Key rollout_auto_advance_hours: wenn gesetzt,
        # gilt das fuer 1→2 (2→3 bekommt Default 168h).
        async def _get_hours(key: str, fallback: int) -> int:
            raw = await runtime_value(key)
            if raw:
                try: return int(raw)
                except: pass
            return fallback
        legacy_hours = await _get_hours("rollout_auto_advance_hours", 0)
        hours_1_to_2 = await _get_hours("rollout_auto_advance_hours_1_to_2",
                                        legacy_hours if legacy_hours > 0 else 24)
        hours_2_to_3 = await _get_hours("rollout_auto_advance_hours_2_to_3", 168)
        max_err_pct_raw = await runtime_value("rollout_max_error_pct") or "0"
        try:
            max_err_pct = int(max_err_pct_raw)
        except Exception:
            max_err_pct = 0
        now = datetime.now(timezone.utc)

        # Stage-Mapping fuer Fehler-Ring-Counting
        phase_stage = {1: "ring1", 2: "ring2", 3: "prod"}
        from routes.admin import _stage_to_ring_filter

        rollouts = await database.list_rollouts(status="active", limit=500)
        for r in rollouts:
            # Per-Paket opt-in: nur Pakete mit auto_advance=1 werden
            # automatisch weitergeschaltet.
            pkg_row = await database.get_package(r["package_name"])
            if not pkg_row or not pkg_row.get("auto_advance"):
                continue
            la_raw = r.get("last_advanced_at")
            if not la_raw:
                continue
            try:
                la = datetime.fromisoformat(la_raw.replace(" ", "T").replace("Z", "+00:00"))
                if la.tzinfo is None:
                    la = la.replace(tzinfo=timezone.utc)
            except Exception:
                continue
            # Welche Transition steht an? current_phase=1 → 1→2-Hours
            if r["current_phase"] == 1:
                wait_hours = hours_1_to_2
            elif r["current_phase"] == 2:
                wait_hours = hours_2_to_3
            elif r["current_phase"] == 3:
                # Phase 3 dispatched → nach kurzer Observations-Zeit
                # (Default 1h, wenn Fehler auftreten pausiert der Tick
                # weiter) Rollout auf 'done' setzen via advance.
                wait_hours = 1
            else:
                continue
            threshold = now - timedelta(hours=max(1, wait_hours))
            if la > threshold:
                continue

            # Fehler-Anteil berechnen
            errors = await database.get_fleet_errors(limit=500)
            err_for_pkg = [e for e in errors
                           if e.get("last_action_package") == r["package_name"]]
            stage = phase_stage.get(r["current_phase"])
            agents_in_stage = await database.get_agents_by_ring(
                _stage_to_ring_filter(stage)
            ) if stage else []
            total_agents = len(agents_in_stage) or 1
            err_pct = (len(err_for_pkg) * 100) // total_agents

            if max_err_pct > 0:
                # Nur blocken wenn Schwelle ueberschritten
                if err_pct > max_err_pct:
                    logger.info(
                        "auto-advance skip rollout %s (paket=%s): "
                        "Fehlerrate %d%% > Schwelle %d%%",
                        r["id"], r["package_name"], err_pct, max_err_pct,
                    )
                    continue
            else:
                # max_err_pct = 0: schon ein einziger Fehler blockt
                if err_for_pkg:
                    logger.info(
                        "auto-advance skip rollout %s (paket=%s): "
                        "%d offene Fehler (max_error_pct=0)",
                        r["id"], r["package_name"], len(err_for_pkg),
                    )
                    continue

            # Advance (pkg schon oben geholt)
            pkg = pkg_row
            from routes.admin import _dispatch_rollout_phase
            updated = await database.advance_rollout(
                r["id"],
                {
                    "at": datetime.now(timezone.utc).isoformat(timespec='seconds'),
                    "auto": True,
                    "error_pct": err_pct,
                },
                expected_phase=r["current_phase"],
            )
            if updated and updated["status"] == "active":
                await _dispatch_rollout_phase(pkg, updated["current_phase"])
                logger.info("auto-advanced rollout %s to phase %s (err_pct=%d)",
                            r["id"], updated["current_phase"], err_pct)
            elif updated and updated["status"] == "done":
                logger.info("auto-advanced rollout %s → done", r["id"])
    except Exception as e:
        logger.exception("rollout auto-advance tick crashed: %s", e)


async def _scheduled_jobs_tick():
    """Minuetlicher Tick: checkt pending scheduled_jobs deren run_at <= now,
    fuehrt sie aus und markiert als done/failed."""
    from datetime import datetime, timezone
    try:
        pending = await database.list_pending_scheduled_jobs()
        now = datetime.now(timezone.utc)
        from routes.admin import execute_scheduled_job
        for job in pending:
            try:
                run_at = datetime.fromisoformat(job["run_at"].replace("Z", "+00:00"))
                if run_at.tzinfo is None:
                    run_at = run_at.replace(tzinfo=timezone.utc)
            except Exception:
                logger.warning("scheduled job %s hat ungueltiges run_at — skipping", job["id"])
                continue
            if run_at > now:
                continue
            logger.info("executing scheduled job %s (%s)", job["id"], job["action_type"])
            import json as _json
            try:
                res = await execute_scheduled_job(job)
                status = "done" if res.get("ok") else "failed"
                await database.update_scheduled_job_status(
                    job["id"], status, _json.dumps(res),
                )
            except Exception as e:
                logger.exception("scheduled job %s crashed", job["id"])
                await database.update_scheduled_job_status(
                    job["id"], "failed", _json.dumps({"error": str(e)[:300]}),
                )
    except Exception as e:
        logger.exception("scheduled jobs tick crashed: %s", e)


async def _profile_autoupdate_job():
    """Nightly auto-update fuer alle Profile mit auto_update=1. Laeuft NACH
    den Scans (winget 02:00, choco 02:15) damit agent_winget_state und
    agent_choco_state frisch sind und die Smart-Skip-Logik korrekt arbeitet."""
    try:
        from routes.admin import run_all_profile_autoupdates
        result = await run_all_profile_autoupdates()
        logger.info("nightly profile auto-update done: %s", result)
    except Exception as e:
        logger.exception("nightly profile auto-update job crashed: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await database.init_db()
    await _seed_settings_from_env()
    await admin_auth.ensure_bootstrap_admin()
    try:
        days = await runtime_int("log_retention_days")
        await database.cleanup_old_logs(days)
        await database.cleanup_expired_sessions()
    except Exception as e:
        logger.warning("Cleanup fehlgeschlagen: %s", e)
    # Stale action_log Eintraege aus vorherigem Container-Restart aufräumen
    try:
        async with database._db() as db:
            res = await db.execute(
                "UPDATE action_log SET status = 'error', "
                "error_summary = 'Container-Restart waehrend Ausfuehrung', "
                "completed_at = datetime('now') "
                "WHERE status IN ('pending', 'running')"
            )
            if res.rowcount:
                logger.info("Stale action_log: %d Eintraege als error markiert", res.rowcount)
            await db.commit()
    except Exception as e:
        logger.warning("action_log stale cleanup: %s", e)
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
    # Scripts-Dir fuer Script-Delivery anlegen + alte Scripts aufraeumen
    scripts_dir = os.path.join(os.path.dirname(__file__), "data", "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    try:
        import glob
        stale = glob.glob(os.path.join(scripts_dir, "*.ps1"))
        for f in stale:
            os.remove(f)
        if stale:
            logger.info("Startup: %d stale script files removed", len(stale))
    except Exception as e:
        logger.warning("Script cleanup on startup: %s", e)

    # APScheduler für nightly winget Scan + Enrichment + Catalog-Refresh.
    # Reihenfolge: Catalog refresh zuerst, dann scan, dann enrichment (das den
    # frischen Catalog mit dem Scan kombiniert).
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        _winget_catalog_refresh_job,
        CronTrigger(hour=1, minute=30),
        id="winget_catalog_refresh",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        _winget_nightly_job,
        CronTrigger(hour=2, minute=0),
        id="winget_nightly_scan",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        _winget_enrichment_job,
        CronTrigger(hour=2, minute=30),
        id="winget_enrichment",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        _choco_nightly_job,
        CronTrigger(hour=2, minute=15),
        id="choco_nightly_scan",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        _profile_autoupdate_job,
        CronTrigger(hour=3, minute=0),
        id="profile_autoupdate",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    # Naechtlicher Cleanup: action_log Eintraege aelter 30 Tage entfernen
    scheduler.add_job(
        _action_log_cleanup_job,
        CronTrigger(hour=3, minute=30),
        id="action_log_cleanup",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    # Minuetlicher Tick fuer scheduled_jobs (Maintenance-Windows).
    # Ein einzelner Job statt per-Schedule-DateTrigger — einfacher zu
    # handhaben + ueberlebt Restarts (wir lesen beim Tick aus der DB).
    from apscheduler.triggers.interval import IntervalTrigger
    scheduler.add_job(
        _scheduled_jobs_tick,
        IntervalTrigger(minutes=1),
        id="scheduled_jobs_tick",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=120,
    )
    # Alle 15 Min: pruefe Rollouts, auto-advance wenn enabled + Bedingungen passen
    scheduler.add_job(
        _rollout_auto_advance_tick,
        IntervalTrigger(minutes=15),
        id="rollout_auto_advance",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=900,
    )
    # Alle 15 Min: pruefe staged+auto_advance Pakete ohne aktiven Rollout →
    # starte automatisch neuen Rollout wenn Updates verfuegbar.
    scheduler.add_job(
        _rollout_auto_start_tick,
        IntervalTrigger(minutes=15),
        id="rollout_auto_start",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=900,
    )
    scheduler.start()
    app.state.scheduler = scheduler
    logger.info("APScheduler started with %d job(s)", len(scheduler.get_jobs()))

    try:
        yield
    finally:
        scheduler.shutdown(wait=False)
        logger.info("APScheduler stopped")


app = FastAPI(
    title="Softshelf — Proxy",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

# Middleware-Reihenfolge: Audit außen, dann Rate-Limit, dann CSRF
app.add_middleware(BaseHTTPMiddleware, dispatch=csrf_middleware)
app.add_middleware(BaseHTTPMiddleware, dispatch=rate_limit_middleware)
app.add_middleware(BaseHTTPMiddleware, dispatch=audit_log_middleware)

app.include_router(packages.router, prefix="/api/v1")
app.include_router(install.router,  prefix="/api/v1")
app.include_router(register.router, prefix="/api/v1")
app.include_router(admin.router)


@app.get("/api/v1/client-config")
async def client_config():
    """
    Öffentliche Client-Metadaten (Titel, Version) für den Kiosk-Client.
    Kein Bearer-Auth — nur UI-Text, nicht sensibel.
    """
    from config import runtime_value
    app_name = await runtime_value("client_app_name") or "Softshelf"
    return {
        "app_name": app_name,
        "version": VERSION,
    }


@app.get("/api/v1/icon")
async def public_icon():
    """Branding-Icon für den Tray-Client (öffentlich, kein Auth)."""
    icon_path = os.path.join(os.path.dirname(database.DB_PATH), "branding", "icon.ico")
    if not os.path.isfile(icon_path):
        raise HTTPException(status_code=404)
    return FileResponse(icon_path, media_type="image/x-icon")


@app.get("/api/v1/health")
async def health():
    try:
        await database.health_ping()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"DB nicht erreichbar: {e}")
    return {"status": "ok", "version": VERSION}


@app.get("/download/{filename}")
async def download_exe(filename: str):
    """
    Stellt den Tray-Client und den Installer zum Download bereit
    (kein Auth – enthaelt keine Secrets). Der Dateiname wird gegen den
    aktuellen product_slug geprueft: nur `${slug}.exe` und
    `${slug}-setup.exe` sind erlaubt. Damit kann ein Angreifer nicht
    mit einem hergeleiteten Pfad aus dem downloads-Volume lesen, und
    ein Wechsel des Slugs ungueltigt automatisch die alten URLs.
    """
    slug = await runtime_value("product_slug") or "Softshelf"
    allowed = {f"{slug}.exe", f"{slug}-setup.exe"}
    # .ps1 Scripts aus dem downloads-Verzeichnis (fuer Debug/Deploy)
    if filename.endswith(".ps1") and re.fullmatch(r"[a-zA-Z0-9_\-]{1,80}\.ps1", filename):
        allowed.add(filename)
    if filename not in allowed:
        raise HTTPException(status_code=404, detail="Nicht gefunden")
    path = os.path.join(DOWNLOADS_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=404,
            detail=f"{filename} noch nicht gebaut. Im Admin-UI unter Einstellungen auf 'EXEs bauen' klicken.",
        )
    return FileResponse(path, media_type="application/octet-stream", filename=filename)


@app.get("/api/v1/file/{sha256}")
async def download_custom_file(sha256: str, token: str = Query(...)):
    """Signed-URL Download für custom MSI/EXE Pakete (vom Tactical-Agent)."""
    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256.lower()):
        raise HTTPException(status_code=400, detail="Ungültiger Hash")

    verify_download_token(token, sha256)

    pkg = await database.get_package_by_sha(sha256)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")

    path = file_uploads.find_file_path(sha256)
    if not path:
        raise HTTPException(status_code=404, detail="Datei nicht im Storage")

    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=pkg.get("filename") or os.path.basename(path),
    )
