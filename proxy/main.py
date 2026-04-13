"""
Softshelf — Proxy
Starten: uvicorn main:app --host 0.0.0.0 --port 8765
Admin:   http(s)://<server>:8765/admin
"""
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware

import admin_auth
import database
import file_uploads
from auth import verify_download_token
from config import RUNTIME_KEYS, get_settings, runtime_int, runtime_value
from middleware.audit_logger import audit_log_middleware
from middleware.csrf import csrf_middleware
from middleware.rate_limit import rate_limit_middleware
from routes import packages, install, admin, register

logger = logging.getLogger("softshelf")

VERSION = "1.2.0"

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
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
    yield


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
