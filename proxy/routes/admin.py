"""
Admin-Oberfläche: /admin
Session-Cookie-Auth mit lokaler User-DB + optionalem Microsoft-Entra-SSO.
CSRF-Schutz via Middleware (X-Requested-With) bleibt aktiv.
"""
import asyncio
import html
import logging
import os
import re
import secrets
from datetime import datetime, timezone
from typing import Optional
from fastapi import (
    APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator

import httpx

import admin_auth
import database
import file_uploads
import winget_catalog
import winget_enrichment
import winget_scanner
from winget_catalog import is_os_managed
from config import (
    RUNTIME_KEYS,
    get_settings,
    runtime_int,
    runtime_value,
    validate_runtime_value,
)
from tactical_client import TacticalClient

router = APIRouter()
logger = logging.getLogger("softshelf.admin")

# Strong references für fire-and-forget Background-Tasks (Python GC sammelt
# sonst möglicherweise laufende Tasks ein, siehe Python docs zu asyncio.create_task)
_bg_tasks: set[asyncio.Task] = set()


def _spawn_bg(coro) -> asyncio.Task:
    t = asyncio.create_task(coro)
    _bg_tasks.add(t)
    t.add_done_callback(_bg_tasks.discard)
    return t

_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "..", "templates", "admin.html")
_HELP_PATH = os.path.join(os.path.dirname(__file__), "..", "templates", "admin_help.html")
_LOGIN_PATH = os.path.join(os.path.dirname(__file__), "..", "templates", "admin_login.html")

_PKG_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,99}$")
_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9\-]{8,64}$")
_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._\-@]{2,80}$")
# winget PackageIdentifier (z. B. 'Mozilla.Firefox', 'Microsoft.VisualStudioCode')
_WINGET_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,199}$")
# Versions-Label: alphanumerisch, Punkt, Bindestrich, Unterstrich
_VERSION_LABEL_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,49}$")
# Reject anything with control chars, NUL, newlines — for free-text fields
# die in Shell-/PowerShell-Commands oder JS-Strings landen
_NO_CTRL_RE = re.compile(r"^[^\x00-\x1f\x7f]*$")


def _check_no_ctrl(value: str, field: str) -> str:
    if not _NO_CTRL_RE.fullmatch(value):
        raise ValueError(f"{field} enthält Steuerzeichen oder Zeilenumbrüche")
    return value


def _validate_version_label(label: str) -> str:
    label = label.strip()
    if not label:
        return label
    if not _VERSION_LABEL_RE.fullmatch(label):
        raise HTTPException(
            status_code=400,
            detail="Version-Label darf nur Buchstaben, Zahlen, Punkt, Bindestrich, Unterstrich enthalten (max 50)",
        )
    return label


def _validate_entry_point(ep: str) -> str:
    ep = ep.strip().replace("\\", "/")
    if not ep:
        return ep
    if not _NO_CTRL_RE.fullmatch(ep):
        raise HTTPException(status_code=400, detail="Entry-Point enthält Steuerzeichen")
    if ".." in ep.split("/"):
        raise HTTPException(status_code=400, detail="Entry-Point enthält ..")
    if ep.startswith("/"):
        raise HTTPException(status_code=400, detail="Entry-Point darf nicht mit / beginnen")
    return ep


def _validate_install_args(args: str) -> str:
    args = args.strip()
    if not args:
        return args
    if not _NO_CTRL_RE.fullmatch(args):
        raise HTTPException(status_code=400, detail="Install-Args enthalten Steuerzeichen")
    return args


def _validate_uninstall_cmd(cmd: str) -> str:
    cmd = cmd.strip()
    if not cmd:
        return cmd
    if not _NO_CTRL_RE.fullmatch(cmd):
        raise HTTPException(status_code=400, detail="Uninstall-Command enthält Steuerzeichen")
    return cmd


async def _require_admin(request: Request) -> dict:
    """
    Auth-Dependency für alle Admin-Endpoints: prüft Session-Cookie und
    gibt das User-Dict zurück. 401 bei ungültiger oder fehlender Session.
    Die JS-api()-Funktion fängt 401 ab und redirected zu /admin/login.
    """
    token = request.cookies.get(admin_auth.SESSION_COOKIE)
    user = await admin_auth.get_session_user(token)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Nicht angemeldet",
            headers={"X-Auth-Required": "session"},
        )
    return user


async def _portal_title_html() -> str:
    """
    Liest den admin_portal_title aus den Runtime-Settings und HTML-escaped ihn.
    Wird in admin.html und admin_login.html als {{ADMIN_PORTAL_TITLE}}
    ersetzt. Doppelte Sicherheit: der Settings-Validator verbietet bereits
    HTML-Sonderzeichen, aber wir escapen trotzdem (defense in depth).
    """
    raw = await runtime_value("admin_portal_title") or "Softshelf"
    return html.escape(raw, quote=True)


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    """Liefert die Admin-SPA. Bei fehlender Session → Redirect zum Login."""
    token = request.cookies.get(admin_auth.SESSION_COOKIE)
    user = await admin_auth.get_session_user(token)
    if not user:
        return RedirectResponse(url="/admin/login", status_code=302)
    with open(_TEMPLATE_PATH, encoding="utf-8") as f:
        page = f.read()
    page = page.replace("{{ADMIN_PORTAL_TITLE}}", await _portal_title_html())
    return HTMLResponse(page)


@router.get("/admin/api/help", response_class=HTMLResponse,
            dependencies=[Depends(_require_admin)])
async def admin_help():
    """HTML-Fragment mit der Admin-Dokumentation. Wird vom Hilfe-Tab lazy geladen.

    Ersetzt {{SF_*}}-Platzhalter durch die aktuellen Runtime-Werte (Proxy-URL,
    Registration-Secret, Setup-EXE-URL, Slug). Damit sind die PowerShell-
    Deployment-Snippets im Hilfe-Tab direkt copy-paste-faehig fuer die
    konkrete Installation. Endpoint ist admin-only — das Secret bleibt also
    in der Session des angemeldeten Admins.
    """
    with open(_HELP_PATH, encoding="utf-8") as f:
        page = f.read()

    proxy_url = (await runtime_value("proxy_public_url") or "").rstrip("/")
    secret    = await runtime_value("registration_secret") or ""
    slug      = await runtime_value("product_slug") or "Softshelf"
    setup_url = f"{proxy_url}/download/{slug}-setup.exe" if proxy_url else ""

    page = page.replace("{{SF_PROXY_URL}}",     html.escape(proxy_url, quote=True))
    page = page.replace("{{SF_REG_SECRET}}",    html.escape(secret,    quote=True))
    page = page.replace("{{SF_SETUP_EXE_URL}}", html.escape(setup_url, quote=True))
    page = page.replace("{{SF_SLUG}}",          html.escape(slug,      quote=True))
    return page


# ── Login / Logout / Whoami ───────────────────────────────────────────────────

def _is_https_request(request: Request | None) -> bool:
    """True wenn der Original-Request über HTTPS kam (direkt oder via Reverse-Proxy)."""
    if not request:
        return False
    if request.url.scheme == "https":
        return True
    # Hinter Reverse-Proxy: X-Forwarded-Proto
    fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return fwd_proto == "https"


def _set_session_cookie(response, token: str, expires_at: datetime, request: Request | None = None):
    max_age = max(0, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
    response.set_cookie(
        key=admin_auth.SESSION_COOKIE,
        value=token,
        max_age=max_age,
        httponly=True,
        samesite="strict",
        secure=_is_https_request(request),
        path="/admin",
    )


@router.get("/admin/login", response_class=HTMLResponse)
async def login_page():
    with open(_LOGIN_PATH, encoding="utf-8") as f:
        page = f.read()
    sso_on = await admin_auth.sso_enabled()
    page = page.replace("{{SSO_ENABLED}}", "true" if sso_on else "false")
    page = page.replace("{{ADMIN_PORTAL_TITLE}}", await _portal_title_html())
    return HTMLResponse(page)


@router.post("/admin/login")
async def do_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = await admin_auth.authenticate_local(username.strip(), password)
    if not user:
        return JSONResponse(
            {"ok": False, "error": "Benutzername oder Passwort falsch."},
            status_code=401,
        )
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    token, expires = await admin_auth.create_session(user["id"], ip, ua)
    response = JSONResponse({"ok": True, "redirect": "/admin"})
    _set_session_cookie(response, token, expires, request)
    return response


@router.post("/admin/logout")
async def do_logout(request: Request):
    token = request.cookies.get(admin_auth.SESSION_COOKIE)
    if token:
        await admin_auth.revoke_session(token)
    response = JSONResponse({"ok": True, "redirect": "/admin/login"})
    response.delete_cookie(admin_auth.SESSION_COOKIE, path="/admin")
    return response


@router.get("/admin/api/whoami")
async def whoami(user: dict = Depends(_require_admin)):
    return {
        "id": user["user_id"],
        "username": user["username"],
        "display_name": user.get("display_name"),
        "email": user.get("email"),
        "sso_provider": user.get("sso_provider"),
    }


# ── Microsoft Entra ID SSO ────────────────────────────────────────────────────

async def _sso_redirect_uri() -> str:
    base = (await runtime_value("proxy_public_url")).rstrip("/")
    if not base:
        cfg = get_settings()
        base = f"http://{cfg.host}:{cfg.port}"
    return f"{base}/admin/sso/callback"


@router.get("/admin/sso/login")
async def sso_login():
    if not await admin_auth.sso_enabled():
        raise HTTPException(status_code=400, detail="SSO ist nicht aktiviert")
    redirect_uri = await _sso_redirect_uri()
    url = await admin_auth.sso_authorize_url(redirect_uri)
    if not url:
        raise HTTPException(
            status_code=400,
            detail="SSO ist nicht vollständig konfiguriert (Tenant-ID / Client-ID prüfen)",
        )
    return RedirectResponse(url=url, status_code=302)


@router.get("/admin/sso/callback")
async def sso_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
):
    if error:
        return HTMLResponse(
            f"<h1>SSO-Fehler</h1><p>{error}: {error_description or ''}</p>"
            f"<p><a href='/admin/login'>Zurück zum Login</a></p>",
            status_code=400,
        )
    if not code or not state:
        raise HTTPException(status_code=400, detail="code/state fehlen")
    if not admin_auth.consume_sso_state(state):
        raise HTTPException(status_code=400, detail="Ungültiger oder abgelaufener state-Token")

    redirect_uri = await _sso_redirect_uri()
    try:
        info = await admin_auth.sso_exchange_code(code, redirect_uri)
    except ValueError as e:
        return HTMLResponse(
            f"<h1>SSO-Fehler</h1><p>{e}</p>"
            f"<p><a href='/admin/login'>Zurück zum Login</a></p>",
            status_code=400,
        )

    user = await admin_auth.sso_login_or_provision(
        oid=info["oid"],
        email=info["email"],
        email_verified=info.get("email_verified", False),
        name=info["name"],
    )
    if not user:
        return HTMLResponse(
            "<h1>Zugriff verweigert</h1>"
            "<p>Dein Microsoft-Konto ist nicht in der Admin-Benutzerverwaltung hinterlegt. "
            "Bitte vorher manuell anlegen oder 'User automatisch anlegen' in den Einstellungen aktivieren.</p>"
            "<p><a href='/admin/login'>Zurück zum Login</a></p>",
            status_code=403,
        )

    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    token, expires = await admin_auth.create_session(user["id"], ip, ua)
    response = RedirectResponse(url="/admin", status_code=302)
    _set_session_cookie(response, token, expires, request)
    return response


# ── Admin User Management ─────────────────────────────────────────────────────

class UserCreateRequest(BaseModel):
    username: str = Field(min_length=2, max_length=80)
    display_name: str = Field(default="", max_length=80)
    email: str = Field(default="", max_length=200)
    password: str = Field(min_length=8, max_length=200)
    is_active: bool = True

    @field_validator("username")
    @classmethod
    def _check_username(cls, v: str) -> str:
        if not _USERNAME_RE.fullmatch(v):
            raise ValueError("Username darf nur a-zA-Z0-9._-@ enthalten (2-80 Zeichen)")
        return v


class UserUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=80)
    email: Optional[str] = Field(default=None, max_length=200)
    password: Optional[str] = Field(default=None, min_length=8, max_length=200)
    is_active: Optional[bool] = None


def _public_user(u: dict) -> dict:
    return {
        "id": u["id"],
        "username": u["username"],
        "display_name": u.get("display_name"),
        "email": u.get("email"),
        "is_active": bool(u.get("is_active")),
        "created_at": u.get("created_at"),
        "last_login": u.get("last_login"),
        "sso_provider": u.get("sso_provider"),
        "has_password": bool(u.get("password_hash")),
    }


@router.get("/admin/api/users", dependencies=[Depends(_require_admin)])
async def list_users():
    users = await database.get_admin_users()
    return [_public_user(u) for u in users]


@router.post("/admin/api/users", dependencies=[Depends(_require_admin)])
async def create_user(body: UserCreateRequest):
    existing = await database.get_admin_user_by_username(body.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username bereits vergeben")
    user_id = await database.create_admin_user(
        username=body.username,
        display_name=body.display_name or None,
        email=body.email or None,
        password_hash=admin_auth.hash_password(body.password),
        is_active=body.is_active,
    )
    user = await database.get_admin_user_by_id(user_id)
    return _public_user(user)


@router.patch("/admin/api/users/{user_id}", dependencies=[Depends(_require_admin)])
async def update_user(user_id: int, body: UserUpdateRequest):
    user = await database.get_admin_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User nicht gefunden")

    # Safeguard: nicht den letzten aktiven Admin deaktivieren
    if body.is_active is False and user.get("is_active"):
        active = await database.count_active_admins()
        if active <= 1:
            raise HTTPException(status_code=400, detail="Letzter aktiver Admin kann nicht deaktiviert werden")

    await database.update_admin_user(
        user_id,
        display_name=body.display_name,
        email=body.email,
        password_hash=(admin_auth.hash_password(body.password) if body.password else None),
        is_active=body.is_active,
    )
    # Bei deaktivieren: alle bestehenden Sessions des Users wegwerfen
    if body.is_active is False:
        await database.delete_user_sessions(user_id)
    updated = await database.get_admin_user_by_id(user_id)
    return _public_user(updated)


@router.delete("/admin/api/users/{user_id}", dependencies=[Depends(_require_admin)])
async def delete_user(user_id: int, current: dict = Depends(_require_admin)):
    user = await database.get_admin_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User nicht gefunden")
    if current["user_id"] == user_id:
        raise HTTPException(status_code=400, detail="Du kannst dich nicht selbst löschen")
    if user.get("is_active"):
        active = await database.count_active_admins()
        if active <= 1:
            raise HTTPException(status_code=400, detail="Letzter aktiver Admin kann nicht gelöscht werden")
    await database.delete_user_sessions(user_id)
    await database.delete_admin_user(user_id)
    return {"ok": True}


@router.post("/admin/api/users/me/change-password",
             dependencies=[Depends(_require_admin)])
async def change_own_password(
    request: Request,
    current: dict = Depends(_require_admin),
):
    # Body als JSON: {old_password, new_password}
    payload = await request.json()
    old_pw = (payload.get("old_password") or "").strip()
    new_pw = (payload.get("new_password") or "").strip()
    if len(new_pw) < 8:
        raise HTTPException(status_code=400, detail="Neues Passwort muss mind. 8 Zeichen haben")

    user = await database.get_admin_user_by_id(current["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User nicht gefunden")

    if not user.get("password_hash"):
        raise HTTPException(
            status_code=400,
            detail="Dieser Account hat kein lokales Passwort (SSO-only). "
                   "Login läuft über Microsoft-SSO.",
        )

    if not admin_auth.verify_password(old_pw, user.get("password_hash")):
        raise HTTPException(status_code=403, detail="Aktuelles Passwort ist falsch")

    await database.update_admin_user(
        user["id"], password_hash=admin_auth.hash_password(new_pw)
    )

    # Alle bestehenden Sessions wegwerfen — gestohlene Cookies sollen nach
    # Passwort-Rotation nicht weiterleben.
    await database.delete_user_sessions(user["id"])

    # Frische Session ausstellen, damit der Admin nicht ausgeloggt wird
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    new_token, expires = await admin_auth.create_session(user["id"], ip, ua)
    response = JSONResponse({"ok": True})
    _set_session_cookie(response, new_token, expires, request)
    return response


# ── Packages (Whitelist) ──────────────────────────────────────────────────────

class EnabledPackage(BaseModel):
    name: str
    display_name: str
    category: str = "Allgemein"
    type: str = "choco"
    filename: str | None = None
    size_bytes: int | None = None
    install_args: str | None = None
    uninstall_cmd: str | None = None
    detection_name: str | None = None
    current_version_id: int | None = None
    archive_type: str | None = None
    entry_point: str | None = None
    winget_publisher: str | None = None
    winget_version: str | None = None


class SearchResult(BaseModel):
    name: str
    display_name: str
    description: str
    enabled: bool


class EnableRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    display_name: str = Field(min_length=1, max_length=80)
    category: str = Field(default="Allgemein", min_length=1, max_length=40)

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        if not _PKG_NAME_RE.fullmatch(v):
            raise ValueError("Paketname enthält ungültige Zeichen")
        return v

    @field_validator("display_name", "category")
    @classmethod
    def _check_text(cls, v: str) -> str:
        if not _TEXT_RE.fullmatch(v):
            raise ValueError("Text enthält ungültige Zeichen")
        return v


@router.get("/admin/api/enabled", response_model=list[EnabledPackage],
            dependencies=[Depends(_require_admin)])
async def get_enabled():
    rows = await database.get_packages()
    return [EnabledPackage(**r) for r in rows]


@router.get("/admin/api/search", response_model=list[SearchResult],
            dependencies=[Depends(_require_admin)])
async def search_packages(q: str = Query(default="", min_length=0, max_length=100)):
    chocos = await database.get_cached_chocos()
    if chocos is None:
        try:
            fresh = await TacticalClient().get_chocos()
            chocos = [pkg.get("name", "") for pkg in fresh if pkg.get("name")]
            await database.save_chocos_cache(chocos)
        except Exception:
            logger.exception("Tactical-Chocos-Fetch fehlgeschlagen")
            raise HTTPException(status_code=502, detail="Tactical RMM nicht erreichbar")

    name_map = await database.get_name_map()
    q_lower = q.lower().strip()

    results = []
    for name in chocos:
        if not name:
            continue
        if q_lower and q_lower not in name.lower():
            continue
        results.append(SearchResult(
            name=name,
            display_name=name_map.get(name, name),
            description="",
            enabled=name in name_map,
        ))
        if len(results) >= 30:
            break

    return results


@router.post("/admin/api/enable", dependencies=[Depends(_require_admin)])
async def enable_package(body: EnableRequest):
    await database.upsert_package(body.name, body.display_name or body.name, body.category)
    rows = await database.get_packages()
    return {"ok": True, "total": len(rows)}


@router.delete("/admin/api/enable/{name}", dependencies=[Depends(_require_admin)])
async def disable_package(name: str):
    """
    Entfernt ein Paket aus der Whitelist. Bei custom-Paketen werden alle
    Versionen, Installations-Tracking-Daten und ungenutzte Dateien
    aufgeräumt. Geteilte Uploads (selber Hash anderswo verwendet) bleiben.
    """
    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")

    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")

    # Alle SHA-256-Hashes einsammeln (flache + alle Versionen)
    shas: set[str] = set()
    if pkg.get("sha256"):
        shas.add(pkg["sha256"])
    for v in await database.get_package_versions(name):
        if v.get("sha256"):
            shas.add(v["sha256"])

    # Tracking + Versionen + Paket aufräumen
    await database.delete_installations_for_package(name)
    await database.delete_versions_for_package(name)
    await database.delete_package(name)

    # Files: nur löschen wenn niemand sonst den Hash nutzt
    for sha in shas:
        pkg_users = await database.sha256_usage_count(sha)
        ver_users = await database.count_versions_with_sha(sha)
        if pkg_users == 0 and ver_users == 0:
            file_uploads.delete_file(sha)

    rows = await database.get_packages()
    return {"ok": True, "total": len(rows)}


@router.patch("/admin/api/enable/{name}", dependencies=[Depends(_require_admin)])
async def update_package(name: str, body: EnableRequest):
    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht aktiv")

    ptype = pkg.get("type") or "choco"
    if ptype == "custom":
        await database.upsert_custom_package(
            name=name,
            display_name=body.display_name or pkg["display_name"],
            category=body.category,
            filename=pkg.get("filename") or name,
            sha256=pkg.get("sha256") or "",
            size_bytes=pkg.get("size_bytes") or 0,
            install_args=pkg.get("install_args") or "",
            uninstall_cmd=pkg.get("uninstall_cmd"),
            detection_name=pkg.get("detection_name"),
        )
    elif ptype == "winget":
        await database.update_winget_package(
            name=name,
            display_name=body.display_name or pkg["display_name"],
            category=body.category,
            winget_version=pkg.get("winget_version"),
        )
    else:
        await database.upsert_package(name, body.display_name or name, body.category)
    return {"ok": True}


class CustomUpdateRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)
    category: str = Field(default="Custom", min_length=1, max_length=40)
    install_args: str = Field(default="", max_length=500)
    uninstall_cmd: str = Field(default="", max_length=1000)
    detection_name: str = Field(default="", max_length=200)
    entry_point: str = Field(default="", max_length=500)  # nur für archive

    @field_validator("display_name", "category")
    @classmethod
    def _check_text(cls, v: str) -> str:
        if not _TEXT_RE.fullmatch(v):
            raise ValueError("Text enthält ungültige Zeichen")
        return v

    @field_validator("install_args", "uninstall_cmd", "detection_name", "entry_point")
    @classmethod
    def _check_no_ctrl(cls, v: str) -> str:
        if v and not _NO_CTRL_RE.fullmatch(v):
            raise ValueError("Feld enthält Steuerzeichen oder Zeilenumbrüche")
        return v


@router.get("/admin/api/custom/{name}/detect-uninstall",
            dependencies=[Depends(_require_admin)])
async def detect_uninstall_cmd(name: str):
    """
    Scannt die letzten-aktiven Agents über die Tactical-API und sucht
    nach einem installierten Programm, dessen Name dem detection_name
    des Pakets entspricht. Gibt den Uninstall-Command aus der Windows-
    Registry zurück (kommt 1:1 von Tactical).
    """
    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    if pkg.get("type") != "custom":
        raise HTTPException(status_code=400, detail="Nur für custom-Pakete")

    needle = (pkg.get("detection_name") or pkg.get("display_name") or name).lower().strip()
    if not needle:
        raise HTTPException(status_code=400, detail="Kein detection_name gesetzt — zuerst im Feld ausfüllen.")

    agents = await database.get_agents()
    # Neueste last_seen zuerst, max 30 Agents pro Scan (gegen Durchlauf-Zeit)
    agents.sort(key=lambda a: a.get("last_seen") or "", reverse=True)
    agents = agents[:30]

    tactical = TacticalClient()
    scanned = 0
    for agent in agents:
        try:
            sw = await tactical.get_installed_software(agent["agent_id"])
        except Exception:
            continue
        scanned += 1
        for item in sw:
            iname = (item.get("name") or "").lower()
            if not iname:
                continue
            if needle in iname or iname in needle:
                un = (item.get("uninstall") or "").strip()
                if un:
                    return {
                        "ok": True,
                        "uninstall_cmd": un,
                        "matched_name": item.get("name"),
                        "agent_hostname": agent.get("hostname"),
                        "agents_scanned": scanned,
                    }
    return {
        "ok": False,
        "uninstall_cmd": "",
        "agents_scanned": scanned,
        "detail": f"Kein passender Eintrag auf {scanned} Agents gefunden. Paket muss auf mindestens einem Gerät installiert sein und Tactical's Software-Scan muss durchgelaufen sein.",
    }


@router.patch("/admin/api/custom/{name}", dependencies=[Depends(_require_admin)])
async def update_custom_package(name: str, body: CustomUpdateRequest):
    """
    Vollständiges Update eines custom-Pakets — Display-Name, Kategorie,
    Args, Uninstall-Command, Detection-Name und (für Archive) Entry-Point.
    Bei Archive-Paketen wird der neue Entry-Point gegen die archive_entries
    der current-Version validiert und auch in package_versions gespeichert.

    Datei (sha256/filename/size) bleibt unverändert; für eine neue Datei
    das Paket im Edit-Panel hochladen (= neue Version).
    """
    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    if pkg.get("type") != "custom":
        raise HTTPException(status_code=400, detail="Kein custom-Paket")

    archive_type = pkg.get("archive_type") or "single"
    eff_entry = pkg.get("entry_point")

    # Entry-Point nur bei Archive-Paketen erlaubt + gegen die current-Version validieren
    if body.entry_point.strip():
        if archive_type != "archive":
            raise HTTPException(
                status_code=400,
                detail="Entry-Point ist nur für Archive-Pakete relevant",
            )
        new_entry = body.entry_point.strip().replace("\\", "/")
        cv = await database.get_current_package_version(name)
        if not cv:
            raise HTTPException(
                status_code=400, detail="Keine current-Version vorhanden"
            )
        import json as _json
        try:
            entries = _json.loads(cv.get("archive_entries") or "[]")
        except Exception:
            entries = []
        if new_entry not in entries:
            raise HTTPException(
                status_code=400,
                detail=f"Entry-Point '{new_entry}' ist nicht im Archiv enthalten",
            )
        # Auch in der current-Version aktualisieren, damit set_current beim
        # Wechsel/Re-Apply den neuen Wert übernimmt
        await database.update_version_entry_point(cv["id"], new_entry)
        eff_entry = new_entry

    await database.upsert_custom_package(
        name=name,
        display_name=body.display_name.strip() or pkg["display_name"],
        category=body.category.strip() or "Custom",
        filename=pkg["filename"],
        sha256=pkg["sha256"],
        size_bytes=pkg["size_bytes"] or 0,
        install_args=body.install_args.strip() or "",
        uninstall_cmd=(body.uninstall_cmd.strip() or None),
        detection_name=(body.detection_name.strip() or None),
        archive_type=archive_type,
        entry_point=eff_entry,
    )
    return {"ok": True}


# ── Package Versions + Push-Update ────────────────────────────────────────────

@router.get("/admin/api/packages/{name}/versions", dependencies=[Depends(_require_admin)])
async def list_package_versions(name: str):
    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    versions = await database.get_package_versions(name)
    summary = await database.get_agent_installation_summary(name)
    return {
        "package": {
            "name": name,
            "display_name": pkg["display_name"],
            "type": pkg.get("type"),
            "current_version_id": pkg.get("current_version_id"),
        },
        "versions": versions,
        "installation_summary": summary,
    }


@router.post(
    "/admin/api/packages/{name}/versions/{version_id}/set-current",
    dependencies=[Depends(_require_admin)],
)
async def set_current_version(name: str, version_id: int):
    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg or pkg.get("type") != "custom":
        raise HTTPException(status_code=404, detail="Custom-Paket nicht gefunden")
    try:
        await database.set_current_package_version(name, version_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "current_version_id": version_id}


@router.get(
    "/admin/api/packages/{name}/versions/{version_id}/files",
    dependencies=[Depends(_require_admin)],
)
async def list_version_files(name: str, version_id: int):
    """
    Listet ALLE Dateien im ZIP einer Archive-Version auf (für die
    Inhalt-verwalten-Ansicht).
    """
    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg or pkg.get("type") != "custom":
        raise HTTPException(status_code=404, detail="Custom-Paket nicht gefunden")

    version = await database.get_package_version(version_id)
    if not version or version.get("package_name") != name:
        raise HTTPException(status_code=404, detail="Version nicht gefunden")
    if (version.get("archive_type") or "single") != "archive":
        raise HTTPException(
            status_code=400, detail="Nur für Programm-Ordner-Versionen verfügbar"
        )

    sha = version.get("sha256")
    if not sha:
        raise HTTPException(status_code=400, detail="Version hat keinen sha256")
    file_path = file_uploads.find_file_path(sha)
    if not file_path:
        raise HTTPException(status_code=404, detail="Archiv-Datei nicht im Storage")

    files = file_uploads.extract_archive_filelist(file_path)
    return {
        "version_id": version_id,
        "version_label": version.get("version_label"),
        "entry_point": version.get("entry_point"),
        "size_bytes": version.get("size_bytes"),
        "files": files,
        "total_files": len(files),
    }


@router.post(
    "/admin/api/packages/{name}/versions/{version_id}/edit",
    dependencies=[Depends(_require_admin)],
)
async def edit_archive_version(
    name: str,
    version_id: int,
    files: list[UploadFile] = File(default=[]),
    remove: str = Form(""),
    add_prefix: str = Form(""),
    version_label: str = Form(""),
    version_notes: str = Form(""),
    entry_point: str = Form(""),
    set_current: str = Form("true"),
):
    """
    Erzeugt aus einer bestehenden Archive-Version eine NEUE Version mit
    angepasstem Inhalt. `remove` ist eine JSON-Liste der Pfade die entfernt
    werden sollen, `files` sind neue Dateien die unter `add_prefix/<filename>`
    eingefügt werden. Bei Konflikt ersetzt die neue Datei die alte.

    Erzeugt eine neue package_versions-Row, lässt die Quell-Version unangetastet.
    Wenn set_current=true (Default), wird die neue Version sofort aktiv.
    """
    import json as _json

    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg or pkg.get("type") != "custom":
        raise HTTPException(status_code=404, detail="Custom-Paket nicht gefunden")

    source_version = await database.get_package_version(version_id)
    if not source_version or source_version.get("package_name") != name:
        raise HTTPException(status_code=404, detail="Version nicht gefunden")
    if (source_version.get("archive_type") or "single") != "archive":
        raise HTTPException(
            status_code=400, detail="Nur Archive-Versionen können bearbeitet werden"
        )

    source_sha = source_version.get("sha256")
    if not source_sha:
        raise HTTPException(status_code=400, detail="Source-Version hat kein Archiv")
    source_path = file_uploads.find_file_path(source_sha)
    if not source_path:
        raise HTTPException(status_code=404, detail="Source-Archiv nicht im Storage")

    try:
        remove_paths = _json.loads(remove) if remove else []
    except _json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="remove muss JSON-Array sein")
    if not isinstance(remove_paths, list):
        raise HTTPException(status_code=400, detail="remove muss JSON-Array sein")
    if not remove_paths and not files:
        raise HTTPException(
            status_code=400,
            detail="Mindestens eine Operation (Hinzufügen oder Löschen) erforderlich",
        )

    max_mb = await runtime_int("max_upload_mb")
    max_bytes = max_mb * 1024 * 1024

    final_path, total_size, sha256, all_files, executable_entries = (
        await file_uploads.edit_archive(
            source_path=source_path,
            remove_paths=set(remove_paths),
            add_files=files,
            add_prefix=add_prefix,
            max_size_bytes=max_bytes,
        )
    )

    # Entry-Point: vom Source erben wenn noch vorhanden, sonst expliziter Wert,
    # sonst auto-pick
    src_ep = (source_version.get("entry_point") or "").strip()
    requested = _validate_entry_point(entry_point or "")
    if requested:
        if requested not in executable_entries:
            raise HTTPException(
                status_code=400,
                detail=f"Angegebener Entry-Point nicht im Archiv: {requested}",
            )
        eff_entry = requested
    elif src_ep and src_ep in executable_entries:
        eff_entry = src_ep
    else:
        eff_entry = file_uploads.pick_default_entry(executable_entries)
        if not eff_entry:
            raise HTTPException(
                status_code=400, detail="Kein Entry-Point ermittelbar"
            )

    # Versions-Label
    existing_labels = await database.get_existing_version_labels(name)
    label = _validate_version_label(version_label)
    if not label:
        n = len(existing_labels) + 1
        while f"v{n}" in existing_labels:
            n += 1
        label = f"v{n}"
    if label in existing_labels:
        raise HTTPException(
            status_code=409, detail=f"Version-Label '{label}' existiert bereits",
        )

    archive_filename = os.path.basename(final_path)
    entries_json = _json.dumps(executable_entries)

    try:
        new_version_id = await database.add_package_version(
            package_name=name,
            version_label=label,
            filename=archive_filename,
            sha256=sha256,
            size_bytes=total_size,
            install_args=source_version.get("install_args") or pkg.get("install_args") or "",
            uninstall_cmd=source_version.get("uninstall_cmd") or pkg.get("uninstall_cmd"),
            notes=(version_notes.strip() or None),
            archive_type="archive",
            entry_point=eff_entry,
            archive_entries=entries_json,
        )
    except Exception:
        logger.exception("Version-Insert fehlgeschlagen")
        raise HTTPException(
            status_code=500, detail="Version konnte nicht angelegt werden"
        )

    set_current_flag = _parse_bool_form(set_current, default=True)
    if set_current_flag:
        await database.set_current_package_version(name, new_version_id)

    return {
        "ok":            True,
        "name":          name,
        "version":       {"id": new_version_id, "label": label, "is_current": set_current_flag},
        "size_bytes":    total_size,
        "sha256":        sha256,
        "entry_point":   eff_entry,
        "total_files":   len(all_files),
        "added":         len(files),
        "removed":       len(remove_paths),
    }


@router.delete(
    "/admin/api/packages/{name}/versions/{version_id}",
    dependencies=[Depends(_require_admin)],
)
async def delete_version(name: str, version_id: int):
    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg or pkg.get("type") != "custom":
        raise HTTPException(status_code=404, detail="Custom-Paket nicht gefunden")

    try:
        deleted = await database.delete_package_version(version_id, expected_package_name=name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not deleted:
        raise HTTPException(status_code=404, detail="Version nicht gefunden")

    sha = deleted.get("sha256")
    if sha:
        pkg_users = await database.sha256_usage_count(sha)
        ver_users = await database.count_versions_with_sha(sha)
        if pkg_users == 0 and ver_users == 0:
            file_uploads.delete_file(sha)

    return {"ok": True}


@router.get(
    "/admin/api/packages/{name}/installations",
    dependencies=[Depends(_require_admin)],
)
async def list_package_installations(name: str):
    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    installs = await database.get_installations_for_package(name)
    summary = await database.get_agent_installation_summary(name)
    return {"installations": installs, "summary": summary}


@router.get(
    "/admin/api/packages/{name}/agents",
    dependencies=[Depends(_require_admin)],
)
async def list_package_agents(name: str):
    """
    Universelle Paket-Detail-Sicht: auf welchen Agents ist dieses Paket
    installiert. Dispatched nach packages.type:

      - winget: agent_winget_state (winget_id = name)
      - choco:  agent_choco_state (choco_name = name)
      - custom: agent_installations + package_versions für version-label,
                current-version-vergleich für outdated-flag

    Pro Eintrag: agent_id, hostname, last_seen (online-state ableitbar),
    installed_version, available_version (nur winget/choco), outdated
    (nur custom — ob die installierte Version unter der current liegt).
    """
    if not _PKG_NAME_RE.fullmatch(name) and not _WINGET_ID_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    ptype = pkg.get("type") or "choco"

    agents: list[dict] = []
    if ptype == "winget":
        rows = await database.get_agents_with_winget_package(name)
        for r in rows:
            agents.append({
                "agent_id":          r["agent_id"],
                "hostname":          r["hostname"],
                "last_seen":         r["last_seen"],
                "installed_version": r["installed_version"],
                "available_version": r["available_version"],
                "scanned_at":        r["scanned_at"],
                "outdated":          bool(r["available_version"]),
            })
    elif ptype == "choco":
        rows = await database.get_agents_with_choco_package(name)
        for r in rows:
            agents.append({
                "agent_id":          r["agent_id"],
                "hostname":          r["hostname"],
                "last_seen":         r["last_seen"],
                "installed_version": r["installed_version"],
                "available_version": r["available_version"],
                "scanned_at":        r["scanned_at"],
                "outdated":          bool(r["available_version"]),
            })
    else:
        # custom: bestehende get_installations_for_package liefert version-
        # label und outdated-flag gegen current_version_id
        rows = await database.get_installations_for_package(name)
        for r in rows:
            agents.append({
                "agent_id":          r["agent_id"],
                "hostname":          r["hostname"],
                "last_seen":         r["last_seen"],
                "installed_version": r.get("version_label"),
                "available_version": None,
                "scanned_at":        r.get("installed_at"),
                "outdated":          bool(r.get("outdated")),
            })

    return {
        "package": {
            "name":         name,
            "display_name": pkg.get("display_name"),
            "type":         ptype,
            "category":     pkg.get("category"),
        },
        "total":  len(agents),
        "agents": agents,
    }


@router.post(
    "/admin/api/packages/{name}/push-update",
    dependencies=[Depends(_require_admin)],
)
async def push_update(name: str):
    """
    Triggert ein Reinstall der current-Version auf allen Agents, die das
    Paket installiert haben aber NICHT auf der current Version sind.
    Geht über den gleichen Tactical-cmd-Pfad wie ein normaler Install,
    inkl. Fire-and-forget Bg-Task pro Agent.
    """
    from routes.install import _build_install_command, _run_custom_command_bg

    if not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg or pkg.get("type") != "custom":
        raise HTTPException(status_code=404, detail="Custom-Paket nicht gefunden")
    if not pkg.get("sha256"):
        raise HTTPException(status_code=400, detail="Paket hat keine aktive Version")

    outdated = await database.get_outdated_agents_for_package(name)
    if not outdated:
        return {"ok": True, "dispatched": 0, "message": "Keine outdated Agents."}

    current_vid = pkg.get("current_version_id")
    dispatched = 0
    failed: list[str] = []

    for ag in outdated:
        try:
            cmd = await _build_install_command(pkg, ag["agent_id"])
            _spawn_bg(_run_custom_command_bg(
                ag["agent_id"], ag["hostname"], name, pkg["display_name"],
                cmd, "install", current_vid,
            ))
            await database.log_install(
                ag["agent_id"], ag["hostname"], name, pkg["display_name"], "install",
            )
            dispatched += 1
        except Exception as e:
            failed.append(f"{ag.get('hostname')}: {e}")

    return {
        "ok": True,
        "dispatched": dispatched,
        "outdated": len(outdated),
        "failed": failed,
    }


# ── Agents ────────────────────────────────────────────────────────────────────

@router.get("/admin/api/agents", dependencies=[Depends(_require_admin)])
async def get_agents():
    return await database.get_agents()


@router.get("/admin/api/agents/{agent_id}/installs", dependencies=[Depends(_require_admin)])
async def get_agent_installs(agent_id: str, limit: int = Query(default=200, ge=1, le=1000)):
    return await database.get_install_log(agent_id=agent_id, limit=limit)


@router.get("/admin/api/agents/{agent_id}/managed", dependencies=[Depends(_require_admin)])
async def get_agent_managed_packages(agent_id: str):
    """Pakete die dieser Agent über das Self-Service-Center installiert hat,
    inkl. installierter Version und Outdated-Flag."""
    return await database.get_agent_installations(agent_id)


# ── Agent Lifecycle: Revoke / Delete / Ban / Unban ────────────────────────────

_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9\-]{8,64}$")


class BanRequest(BaseModel):
    reason: str = Field(default="", max_length=500)

    @field_validator("reason")
    @classmethod
    def _check_reason(cls, v: str) -> str:
        if v and not _NO_CTRL_RE.fullmatch(v):
            raise ValueError("Reason enthält Steuerzeichen")
        return v


@router.post(
    "/admin/api/agents/{agent_id}/revoke",
    dependencies=[Depends(_require_admin)],
)
async def revoke_agent_token(agent_id: str):
    """Bumpt token_version → alle existierenden Tokens für diesen Agent werden
    sofort ungültig. Der Client kriegt beim nächsten Request 401 'Token wurde
    widerrufen' und muss neu registriert werden."""
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungültige Agent-ID")
    agent = await database.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent nicht gefunden")
    await database.bump_token_version(agent_id)
    new_tv = await database.get_token_version(agent_id)
    return {"ok": True, "agent_id": agent_id, "new_token_version": new_tv}


@router.delete(
    "/admin/api/agents/{agent_id}",
    dependencies=[Depends(_require_admin)],
)
async def delete_agent_endpoint(agent_id: str):
    """Löscht einen Agent komplett: agent_installations + install_log + agents.
    Tokens werden dadurch automatisch ungültig (default-token_version=1).
    Der Eintrag im agent_blocklist (falls vorhanden) bleibt unangetastet, damit
    ein bewusst gebannter Client nach Re-Register nicht wieder durchkommt."""
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungültige Agent-ID")
    agent = await database.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent nicht gefunden")
    await database.delete_agent(agent_id)
    return {"ok": True}


@router.post(
    "/admin/api/agents/{agent_id}/ban",
    dependencies=[Depends(_require_admin)],
)
async def ban_agent_endpoint(
    agent_id: str,
    body: BanRequest,
    user: dict = Depends(_require_admin),
):
    """Setzt einen Agent auf die Blocklist. Bumpt zusätzlich token_version,
    damit auch der laufende Token sofort tot ist."""
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungültige Agent-ID")
    agent = await database.get_agent(agent_id)
    hostname = agent["hostname"] if agent else None
    await database.ban_agent(
        agent_id=agent_id,
        hostname=hostname,
        banned_by=user.get("username") or "unknown",
        reason=(body.reason.strip() or None),
    )
    if agent:
        await database.bump_token_version(agent_id)
    return {"ok": True, "agent_id": agent_id, "banned_by": user.get("username")}


@router.post(
    "/admin/api/agents/{agent_id}/unban",
    dependencies=[Depends(_require_admin)],
)
async def unban_agent_endpoint(agent_id: str):
    """Entfernt einen Agent von der Blocklist. Erlaubt erneutes Re-Register."""
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungültige Agent-ID")
    removed = await database.unban_agent(agent_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Agent war nicht gebannt")
    return {"ok": True, "agent_id": agent_id}


@router.get("/admin/api/blocklist", dependencies=[Depends(_require_admin)])
async def list_blocklist():
    """Liste aller gebannten Agents (auch der gelöschten)."""
    return await database.get_blocklist()


# ── Distribution Overview + Admin-Triggered Install/Uninstall ─────────────────

@router.get("/admin/api/distributions", dependencies=[Depends(_require_admin)])
async def get_distributions():
    """
    Übersicht aller custom-Pakete mit deren Verteilung. Liefert pro Paket:
    Metadaten, current-Version-Label, Installations-Summary und die Liste
    der Agents mit ihrer jeweils installierten Version.
    """
    packages = await database.get_packages()
    custom_packages = [p for p in packages if p.get("type") == "custom"]

    result = []
    for pkg in custom_packages:
        installs = await database.get_installations_for_package(pkg["name"])
        summary = await database.get_agent_installation_summary(pkg["name"])
        current_label = None
        if pkg.get("current_version_id"):
            cv = await database.get_package_version(pkg["current_version_id"])
            if cv:
                current_label = cv.get("version_label")
        result.append({
            "name":                  pkg["name"],
            "display_name":          pkg["display_name"],
            "category":              pkg.get("category"),
            "current_version_id":    pkg.get("current_version_id"),
            "current_version_label": current_label,
            "filename":              pkg.get("filename"),
            "size_bytes":            pkg.get("size_bytes"),
            "summary":               summary,
            "installations":         installs,
            "has_uninstall":         bool(pkg.get("uninstall_cmd")),
        })
    return result


async def _resolve_agent(agent_id: str) -> dict:
    """Findet Agent-Hostname oder wirft 404."""
    for a in await database.get_agents():
        if a["agent_id"] == agent_id:
            return a
    raise HTTPException(status_code=404, detail="Agent nicht gefunden")


@router.post(
    "/admin/api/agents/{agent_id}/install/{package_name}",
    dependencies=[Depends(_require_admin)],
)
async def admin_install_on_agent(agent_id: str, package_name: str):
    """Admin-getriggerter Install (oder Upgrade bei winget) eines whitelisted
    Pakets auf einem einzelnen Agent. Dispatch nach packages.type."""
    from routes.install import (
        _build_install_command,
        _run_custom_command_bg,
        _build_winget_command,
        _run_winget_command_bg,
    )

    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungültige Agent-ID")
    pkg = await database.get_package(package_name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")

    agent = await _resolve_agent(agent_id)
    ptype = pkg.get("type") or "choco"

    if ptype == "custom":
        if not _PKG_NAME_RE.fullmatch(package_name):
            raise HTTPException(status_code=400, detail="Ungültiger Paketname")
        if not pkg.get("sha256"):
            raise HTTPException(status_code=400, detail="Paket hat keine aktive Version")
        cmd = await _build_install_command(pkg, agent_id)
        _spawn_bg(_run_custom_command_bg(
            agent_id, agent["hostname"], package_name, pkg["display_name"],
            cmd, "install", pkg.get("current_version_id"),
        ))
    elif ptype == "winget":
        if not _WINGET_ID_RE.fullmatch(package_name):
            raise HTTPException(status_code=400, detail="Ungültige winget-ID")
        # Install vs Upgrade: aus dem aktuellen agent_winget_state entscheiden
        state = await database.get_agent_winget_state(agent_id)
        st = state.get(package_name)
        if st and st.get("installed_version") and st.get("available_version"):
            action = "upgrade"
        else:
            action = "install"
        cmd = _build_winget_command(action, package_name, pkg.get("winget_version"))
        _spawn_bg(_run_winget_command_bg(
            agent_id, agent["hostname"], package_name, pkg["display_name"],
            cmd, action, package_name,
        ))
    else:
        if not _PKG_NAME_RE.fullmatch(package_name):
            raise HTTPException(status_code=400, detail="Ungültiger Paketname")
        # Choco via run_command (gleicher Pfad wie der kiosk-client install)
        # damit Soft-Errors deterministisch in scan_meta.last_action_error landen
        from routes.install import _build_choco_command, _run_choco_command_bg
        cmd = _build_choco_command("install", package_name)
        _spawn_bg(_run_choco_command_bg(
            agent_id, agent["hostname"], package_name, pkg["display_name"],
            cmd, "install",
        ))

    await database.log_install(
        agent_id, agent["hostname"], package_name, pkg["display_name"], "install"
    )
    return {"ok": True, "agent": agent["hostname"]}


@router.post(
    "/admin/api/agents/{agent_id}/uninstall/{package_name}",
    dependencies=[Depends(_require_admin)],
)
async def admin_uninstall_on_agent(agent_id: str, package_name: str):
    """Admin-getriggerter Uninstall eines whitelisted Pakets auf einem
    einzelnen Agent. Dispatch nach packages.type."""
    from routes.install import (
        _run_custom_command_bg,
        _build_uninstall_command,
        _build_winget_command,
        _run_winget_command_bg,
    )

    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungültige Agent-ID")
    pkg = await database.get_package(package_name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")

    agent = await _resolve_agent(agent_id)
    ptype = pkg.get("type") or "choco"

    if ptype == "custom":
        if not _PKG_NAME_RE.fullmatch(package_name):
            raise HTTPException(status_code=400, detail="Ungültiger Paketname")
        uninstall_cmd = (pkg.get("uninstall_cmd") or "").strip()
        if not uninstall_cmd:
            raise HTTPException(
                status_code=400,
                detail="Für dieses Paket wurde kein Uninstall-Command hinterlegt.",
            )
        ps_cmd = _build_uninstall_command(uninstall_cmd)
        _spawn_bg(_run_custom_command_bg(
            agent_id, agent["hostname"], package_name, pkg["display_name"],
            ps_cmd, "uninstall", pkg.get("current_version_id"),
        ))
    elif ptype == "winget":
        if not _WINGET_ID_RE.fullmatch(package_name):
            raise HTTPException(status_code=400, detail="Ungültige winget-ID")
        cmd = _build_winget_command("uninstall", package_name)
        _spawn_bg(_run_winget_command_bg(
            agent_id, agent["hostname"], package_name, pkg["display_name"],
            cmd, "uninstall", package_name,
        ))
    else:
        if not _PKG_NAME_RE.fullmatch(package_name):
            raise HTTPException(status_code=400, detail="Ungültiger Paketname")
        from routes.install import _build_choco_command, _run_choco_command_bg
        cmd = _build_choco_command("uninstall", package_name)
        _spawn_bg(_run_choco_command_bg(
            agent_id, agent["hostname"], package_name, pkg["display_name"],
            cmd, "uninstall",
        ))

    await database.log_install(
        agent_id, agent["hostname"], package_name, pkg["display_name"], "uninstall"
    )
    return {"ok": True, "agent": agent["hostname"]}


_SOFTWARE_PARENS_RE = re.compile(r"\s*[\(\[].*?[\)\]]\s*")
_SOFTWARE_WS_RE = re.compile(r"\s+")
_SOFTWARE_NON_ALNUM_RE = re.compile(r"[^a-z0-9]")


def _normalize_software_name(name: str) -> str:
    if not name:
        return ""
    s = _SOFTWARE_PARENS_RE.sub(" ", name)
    return _SOFTWARE_WS_RE.sub(" ", s).strip().lower()


def _alnum_haystack(name: str) -> str:
    return _SOFTWARE_NON_ALNUM_RE.sub("", _normalize_software_name(name))


# Generische Architektur-/Edition-Tokens die KEIN sinnvoller Match-Anker sind.
# Wenn z. B. das letzte Segment einer winget-ID '64-bit' ist, würde
# 'Adobe.Acrobat.Reader.64-bit' sonst gegen 'SAP GUI 64bit' matchen — totaler
# Quatsch. Diese Tokens werden ignoriert.
_GENERIC_WINGET_TOKENS = frozenset({
    "64bit", "32bit", "x64", "x86", "amd64", "arm64", "arm",
    "win32", "win64", "msix", "msi", "exe", "appx",
    "pro", "home", "enterprise", "std", "standard", "ultimate",
    "free", "preview", "beta", "nightly",
    "en", "de", "english", "german", "deutsch",
})


def _winget_id_tokens(winget_id: str) -> tuple[list[str], str]:
    """Extracts comparable tokens from a winget PackageIdentifier.

    Each dot-separated segment is stripped of punctuation, lowercased, and
    kept if it is at least 3 alphanum chars, not purely numeric, and not in
    `_GENERIC_WINGET_TOKENS`. Returns (tokens, last_meaningful_segment).
    The last_meaningful_segment is the LAST kept token (skipping single-digit
    or generic trailing segments wie '7' bei RoyalApps.RoyalTS.7).
    """
    tokens: list[str] = []
    segs = (winget_id or "").lower().split(".")
    for seg in segs:
        seg_clean = _SOFTWARE_NON_ALNUM_RE.sub("", seg)
        if len(seg_clean) < 3:
            continue
        if seg_clean.isdigit():
            continue
        if seg_clean in _GENERIC_WINGET_TOKENS:
            continue
        tokens.append(seg_clean)
    last_clean = tokens[-1] if tokens else ""
    return tokens, last_clean


def _winget_match_strength(tactical_name: str, winget_id: str) -> int:
    """
    Score-basiertes Matching zwischen einem Tactical-Software-Scan Display-Namen
    und einer winget PackageIdentifier. Höhere Scores = stärkere Matches.

    Regeln:
      - Tokens werden gegen den alphanumerisch-normalisierten Display-Namen
        substring-gematcht.
      - Stark: mehrere Tokens matchen (Score = Summe der Längen).
      - Schwach (aber gültig): genau ein Token matcht UND es ist das letzte
        Segment der winget-ID. So matcht z. B. 'Bitwarden' gegen
        Bitwarden.Bitwarden, aber 'Microsoft Office' matcht NICHT
        Microsoft.Edge, weil 'microsoft' nicht das letzte Segment ist.
    """
    haystack = _alnum_haystack(tactical_name)
    if not haystack:
        return 0
    tokens, last_clean = _winget_id_tokens(winget_id)
    if not tokens:
        return 0
    matched = [t for t in tokens if t in haystack]
    if not matched:
        return 0
    if len(matched) >= 2:
        return sum(len(t) for t in matched)
    if len(matched) == 1 and last_clean and matched[0] == last_clean:
        return len(matched[0])
    return 0


@router.get(
    "/admin/api/agents/{agent_id}/software",
    dependencies=[Depends(_require_admin)],
)
async def get_agent_software(agent_id: str):
    """
    Liefert ALLE installierte Software auf einem Agent + Management-Status.

    Zwei Quellen werden gemerged:
      - agent_winget_state (per Tactical run_command winget export gescraped)
      - Tactical software-scan API (ARP-basiert)

    Pro Eintrag:
      managed     = True wenn das Paket in der Softshelf-Whitelist ist
      managed_type = winget | choco | custom | None
      package_name = der packages.name falls managed
      can_activate = True wenn ein winget-id existiert und das Paket noch
                     nicht whitelisted ist (One-Click-Aktivieren möglich)
    """
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungültige Agent-ID")
    agent = await _resolve_agent(agent_id)

    # Quelle 1: Tactical software-scan
    tactical_error: str | None = None
    try:
        tactical_items = await TacticalClient().get_installed_software(agent_id)
    except httpx.HTTPStatusError as e:
        logger.warning("software-scan HTTP %s for %s", e.response.status_code, agent_id)
        tactical_items = []
        tactical_error = (
            f"Tactical RMM nicht erreichbar (HTTP {e.response.status_code}). "
            "Liste zeigt nur von Softshelf verwaltete Pakete."
        )
    except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as e:
        logger.warning("software-scan network error for %s: %s", agent_id, e)
        tactical_items = []
        tactical_error = (
            "Tactical RMM nicht erreichbar (Netzwerkfehler). "
            "Liste zeigt nur von Softshelf verwaltete Pakete."
        )
    except Exception as e:
        logger.warning("software-scan failed for %s: %s", agent_id, e)
        tactical_items = []
        tactical_error = f"Tactical-Scan fehlgeschlagen: {str(e)[:180]}"

    # Quelle 2: per-Agent winget state aus dem nightly Scan
    winget_state = await database.get_agent_winget_state(agent_id)

    # Quelle 2b: per-Agent choco state — wird vom choco_scanner befüllt
    # (nightly + nach jeder choco-Aktion). Liefert installed_version und
    # available_version pro choco-Paket, deterministisch.
    choco_state = await database.get_agent_choco_state(agent_id)

    # Whitelist nach Typ aufteilen
    pkg_rows = await database.get_packages()
    winget_whitelist: dict[str, dict] = {}
    other_whitelist: list[dict] = []
    for pkg in pkg_rows:
        ptype = pkg.get("type") or "choco"
        if ptype == "winget":
            winget_whitelist[pkg["name"]] = pkg
        else:
            other_whitelist.append(pkg)

    def _find_other_match(display_name: str) -> dict | None:
        # Alphanumerisch-stripped Match (Hyphen, Spaces, Camelcase, Versions-
        # Suffixe spielen keine Rolle):
        #   'StarfaceUCC' (whitelist) ↔ 'STARFACE UCC Client v6.7.3.81' (tactical)
        #   beide → 'starfaceucc...' → starfaceucc Substring-Match findet
        #   sich im längeren String.
        nl_alnum = _alnum_haystack(display_name)
        if not nl_alnum:
            return None
        for pkg in other_whitelist:
            for needle in (
                pkg.get("detection_name"),
                pkg.get("display_name"),
                pkg["name"],
            ):
                if not needle:
                    continue
                ln_alnum = _alnum_haystack(needle)
                if not ln_alnum or len(ln_alnum) < 3:
                    continue
                if ln_alnum in nl_alnum or nl_alnum in ln_alnum:
                    return pkg
        return None

    items: list[dict] = []
    matched_winget_ids: set[str] = set()

    # Pass 1: Tactical-Items, mit Best-Score-Matching gegen winget_state
    for item in tactical_items:
        name = (item.get("name") or "").strip()
        if not name:
            continue
        version = (item.get("version") or "").strip() or None
        publisher = (item.get("publisher") or "").strip() or None

        # Bestes winget-Match finden (token-score-basiert)
        best_score = 0
        best_wid: str | None = None
        for wid in winget_state.keys():
            if wid in matched_winget_ids:
                continue
            score = _winget_match_strength(name, wid)
            if score > best_score:
                best_score = score
                best_wid = wid

        if best_wid:
            matched_winget_ids.add(best_wid)
            wstate = winget_state[best_wid]
            wpkg = winget_whitelist.get(best_wid)
            os_managed = is_os_managed(best_wid)
            avail = wstate.get("available_version")
            # OS-managed Pakete (Edge, Office, Teams, …) lassen sich NICHT
            # via winget upgraden — wir maskieren das Update-Flag und
            # markieren die Row als os_managed damit das UI einen klaren
            # Hinweis statt eines toten Update-Buttons rendern kann.
            effective_avail = None if os_managed else avail
            items.append({
                "name":              wpkg["display_name"] if wpkg else name,
                "winget_id":         best_wid,
                "installed_version": wstate.get("installed_version") or version,
                "available_version": effective_avail,
                "publisher":         (wpkg.get("winget_publisher") if wpkg else None) or publisher,
                "source":            "winget",
                "managed":           bool(wpkg),
                "managed_type":      "winget" if wpkg else None,
                "package_name":      best_wid if wpkg else None,
                "can_activate":      not wpkg and not os_managed,
                "update_available":  bool(effective_avail),
                "os_managed":        os_managed,
            })
            continue

        # Tactical-only: gegen choco/custom whitelist matchen
        wpkg = _find_other_match(name)
        items.append({
            "name":              name,
            "winget_id":         None,
            "installed_version": version,
            "available_version": None,
            "publisher":         publisher,
            "source":            "tactical_scan",
            "managed":           bool(wpkg),
            "managed_type":      (wpkg.get("type") if wpkg else None),
            "package_name":      wpkg["name"] if wpkg else None,
            "can_activate":      False,
            "update_available":  False,
            "os_managed":        False,
        })

    # Pass 2: winget_state Einträge die KEIN Tactical-Match hatten
    for wid, wstate in winget_state.items():
        if wid in matched_winget_ids:
            continue
        wpkg = winget_whitelist.get(wid)
        os_managed = is_os_managed(wid)
        avail = wstate.get("available_version")
        effective_avail = None if os_managed else avail
        items.append({
            "name":              wpkg["display_name"] if wpkg else wid,
            "winget_id":         wid,
            "installed_version": wstate.get("installed_version"),
            "available_version": effective_avail,
            "publisher":         wpkg.get("winget_publisher") if wpkg else (wid.split(".")[0] if "." in wid else None),
            "source":            "winget",
            "managed":           bool(wpkg),
            "managed_type":      "winget" if wpkg else None,
            "package_name":      wid if wpkg else None,
            "can_activate":      not wpkg and not os_managed,
            "update_available":  bool(effective_avail),
            "os_managed":        os_managed,
        })

    # Pass 3: custom- UND choco-Pakete aus agent_installations die NICHT
    # bereits über einen Tactical-Scan-Match in Pass 1 als managed gelandet
    # sind. Tritt auf wenn der User gerade ein Paket über Softshelf
    # installiert hat und Tactical's software-scan es noch nicht aufgegriffen
    # hat (Minuten bis Stunden), ODER wenn der Tactical-Display-Name nicht
    # ähnlich genug zum Paket-Namen ist um per Substring-Heuristik zu
    # matchen (z.B. choco 'StarfaceUCC' vs Tactical 'STARFACE UCC Client
    # v6.7.3.81'). Softshelf weiß durch sein eigenes Tracking immer
    # deterministisch was installiert ist.
    already_managed_pkgs = {
        i["package_name"] for i in items
        if i.get("package_name") and i.get("managed")
    }
    tracked = await database.get_agent_installations(agent_id)
    for t in tracked:
        pkg_name = t["package_name"]
        if pkg_name in already_managed_pkgs:
            continue
        ttype = t.get("type")
        if ttype not in ("custom", "choco"):
            continue
        # Whitelist-Row holen für display_name + Metadaten
        whitelist_row = next(
            (p for p in pkg_rows if p["name"] == pkg_name and (p.get("type") or "choco") == ttype),
            None,
        )
        if not whitelist_row:
            continue
        items.append({
            "name":              whitelist_row.get("display_name") or pkg_name,
            "winget_id":         None,
            "installed_version": t.get("version_label"),
            "available_version": None,
            "publisher":         None,
            "source":            "softshelf_tracking",
            "managed":           True,
            "managed_type":      ttype,
            "package_name":      pkg_name,
            "can_activate":      False,
            "update_available":  bool(t.get("outdated")),
            "os_managed":        False,
        })

    # Pass 4: Choco-State Enrichment für alle managed:choco Rows. Egal aus
    # welchem Pass die Row kam — wenn der Eintrag im agent_choco_state
    # existiert, gewinnen seine Versionen über die Substring-Heuristik vom
    # Tactical-Scan.
    for item in items:
        if item.get("managed_type") != "choco":
            continue
        pkg_name = item.get("package_name")
        if not pkg_name:
            continue
        cstate = choco_state.get(pkg_name)
        if not cstate:
            continue
        cs_installed = cstate.get("installed_version")
        cs_avail = cstate.get("available_version")
        if cs_installed:
            item["installed_version"] = cs_installed
        if cs_avail:
            item["available_version"] = cs_avail
            item["update_available"] = True

    # Sortieren: Updates zuerst, dann managed, dann unmanaged, jeweils nach Name
    items.sort(key=lambda i: (
        0 if i["update_available"] else (1 if i["managed"] else 2),
        (i["name"] or "").lower(),
    ))

    scan_meta = await database.get_scan_meta(agent_id)
    return {
        "agent_id":       agent_id,
        "hostname":       agent["hostname"],
        "tactical_error": tactical_error,
        "items":          items,
        "total":          len(items),
        "scan_meta":      scan_meta,
    }


# ── Audit Log ─────────────────────────────────────────────────────────────────

@router.get("/admin/api/audit", dependencies=[Depends(_require_admin)])
async def get_audit(limit: int = Query(default=200, ge=1, le=1000)):
    return await database.get_audit_log(limit=limit)


# ── Custom File Upload ────────────────────────────────────────────────────────

def _parse_bool_form(value: str, default: bool = True) -> bool:
    if value is None:
        return default
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


@router.post("/admin/api/upload", dependencies=[Depends(_require_admin)])
async def upload_custom_file(
    file: UploadFile = File(...),
    display_name: str = Form(""),
    category: str = Form("Custom"),
    install_args: str = Form(""),
    uninstall_cmd: str = Form(""),
    detection_name: str = Form(""),
    target_package: str = Form(""),
    version_label: str = Form(""),
    version_notes: str = Form(""),
    set_current: str = Form("true"),
):
    """
    Upload einer MSI/EXE. Zwei Modi:

    1. **Neues Paket** (`target_package` leer):
       Datei + Metadaten anlegen, automatisch als Version 'v1' registriert
       und sofort aktiv gesetzt.

    2. **Neue Version eines bestehenden Pakets** (`target_package=<name>`):
       Datei wird als zusätzliche Version angelegt. Wenn `set_current=true`
       (Default), wird sie sofort die aktive Version. `version_label` muss
       eindeutig sein (Default: nächste freie 'vN').
    """
    max_mb = await runtime_int("max_upload_mb")
    max_bytes = max_mb * 1024 * 1024

    target_package = (target_package or "").strip()
    is_new_package = not target_package
    existing_pkg: dict | None = None

    if is_new_package:
        display_name = display_name.strip()
        category = category.strip() or "Custom"
        if not display_name or not _TEXT_RE.fullmatch(display_name):
            raise HTTPException(status_code=400, detail="Ungültiger Anzeigename")
        if not _TEXT_RE.fullmatch(category):
            raise HTTPException(status_code=400, detail="Ungültige Kategorie")
    else:
        if not _PKG_NAME_RE.fullmatch(target_package):
            raise HTTPException(status_code=400, detail="Ungültiger target_package")
        existing_pkg = await database.get_package(target_package)
        if not existing_pkg:
            raise HTTPException(
                status_code=404, detail=f"Paket '{target_package}' nicht gefunden"
            )
        if existing_pkg.get("type") != "custom":
            raise HTTPException(
                status_code=400, detail="Nur custom-Pakete unterstützen Versionen"
            )

    final_path, size_bytes, sha256 = await file_uploads.save_upload(file, max_bytes)
    ext = os.path.splitext(file.filename or "")[1].lower()

    msi_meta = {}
    if ext == ".msi":
        msi_meta = await file_uploads.parse_msi_metadata(final_path)

    # Install-Args: Eingabe → Default, im Versions-Modus auch vom Paket erben
    eff_args = _validate_install_args(install_args)
    if not eff_args and not is_new_package:
        eff_args = (existing_pkg.get("install_args") or "").strip()
    if not eff_args:
        eff_args = "/qn /norestart" if ext == ".msi" else "/S"

    # Uninstall-Cmd: Eingabe → vom Paket erben → MSI-Auto
    eff_uninstall = _validate_uninstall_cmd(uninstall_cmd)
    if not eff_uninstall and not is_new_package:
        eff_uninstall = (existing_pkg.get("uninstall_cmd") or "").strip()
    if not eff_uninstall and ext == ".msi" and msi_meta.get("ProductCode"):
        eff_uninstall = file_uploads.build_msi_uninstall_cmd(msi_meta["ProductCode"])

    # Detection-Name: Eingabe → MSI-ProductName → vom Paket erben (nur neuer Pkg)
    eff_detection = detection_name.strip()
    if is_new_package:
        if not eff_detection and msi_meta.get("ProductName"):
            eff_detection = msi_meta["ProductName"]

    # ── Modus 1: Neues Paket ──
    if is_new_package:
        slug = file_uploads._slug_from_filename(file.filename or "")
        if not _PKG_NAME_RE.fullmatch(slug):
            raise HTTPException(
                status_code=400,
                detail=f"Dateiname ergibt ungültigen Paketnamen: {slug!r}",
            )
        name = await file_uploads._unique_name(slug)

        await database.upsert_custom_package(
            name=name,
            display_name=display_name,
            category=category,
            filename=file.filename or name,
            sha256=sha256,
            size_bytes=size_bytes,
            install_args=eff_args,
            uninstall_cmd=eff_uninstall or None,
            detection_name=eff_detection or None,
        )

        label = _validate_version_label(version_label) or "v1"
        try:
            version_id = await database.add_package_version(
                package_name=name,
                version_label=label,
                filename=file.filename or name,
                sha256=sha256,
                size_bytes=size_bytes,
                install_args=eff_args,
                uninstall_cmd=eff_uninstall or None,
                notes=(version_notes.strip() or None),
            )
        except Exception:
            logger.exception("Version-Insert fehlgeschlagen")
            raise HTTPException(
                status_code=500, detail="Version konnte nicht angelegt werden"
            )

        await database.set_current_package_version(name, version_id)

        return {
            "ok": True,
            "name": name,
            "display_name": display_name,
            "category": category,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "install_args": eff_args,
            "uninstall_cmd": eff_uninstall or None,
            "detection_name": eff_detection or None,
            "msi_metadata": msi_meta,
            "version": {"id": version_id, "label": label, "is_current": True},
        }

    # ── Modus 2: Neue Version an bestehendes Paket ──
    name = target_package

    existing_labels = await database.get_existing_version_labels(name)
    label = _validate_version_label(version_label)
    if not label:
        n = len(existing_labels) + 1
        while f"v{n}" in existing_labels:
            n += 1
        label = f"v{n}"
    if label in existing_labels:
        raise HTTPException(
            status_code=409,
            detail=f"Version-Label '{label}' existiert bereits",
        )

    try:
        version_id = await database.add_package_version(
            package_name=name,
            version_label=label,
            filename=file.filename or name,
            sha256=sha256,
            size_bytes=size_bytes,
            install_args=eff_args,
            uninstall_cmd=eff_uninstall or None,
            notes=(version_notes.strip() or None),
        )
    except Exception:
        logger.exception("Version-Insert fehlgeschlagen (Konflikt)")
        raise HTTPException(
            status_code=409, detail="Version-Label konnte nicht angelegt werden (evtl. doppelt)"
        )

    set_current_flag = _parse_bool_form(set_current, default=True)
    if set_current_flag:
        await database.set_current_package_version(name, version_id)

    return {
        "ok": True,
        "name": name,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "install_args": eff_args,
        "uninstall_cmd": eff_uninstall or None,
        "msi_metadata": msi_meta,
        "version": {"id": version_id, "label": label, "is_current": set_current_flag},
    }


@router.delete("/admin/api/upload/{name}", dependencies=[Depends(_require_admin)])
async def delete_custom_file(name: str):
    """Alias für DELETE /admin/api/enable/{name} – die unified delete-Logik."""
    return await disable_package(name)


@router.post("/admin/api/upload-folder", dependencies=[Depends(_require_admin)])
async def upload_custom_folder(
    files: list[UploadFile] = File(...),
    display_name: str = Form(""),
    category: str = Form("Custom"),
    install_args: str = Form(""),
    uninstall_cmd: str = Form(""),
    detection_name: str = Form(""),
    entry_point: str = Form(""),
    target_package: str = Form(""),
    version_label: str = Form(""),
    version_notes: str = Form(""),
    set_current: str = Form("true"),
):
    """
    Upload eines Programm-Ordners. Der Browser sendet alle Dateien des Ordners
    via webkitdirectory; der Server zippt sie zu einem einzelnen Archiv und
    legt es im selben File-Storage ab wie die Single-File-Uploads.

    Zwei Modi (analog zu /admin/api/upload):
    1. **Neues Paket** (target_package leer)
    2. **Neue Version** an bestehendes Paket (target_package gesetzt)
    """
    import json as _json

    max_mb = await runtime_int("max_upload_mb")
    max_bytes = max_mb * 1024 * 1024

    target_package = (target_package or "").strip()
    is_new_package = not target_package
    existing_pkg: dict | None = None

    if is_new_package:
        display_name = display_name.strip()
        category = category.strip() or "Custom"
        if not display_name or not _TEXT_RE.fullmatch(display_name):
            raise HTTPException(status_code=400, detail="Ungültiger Anzeigename")
        if not _TEXT_RE.fullmatch(category):
            raise HTTPException(status_code=400, detail="Ungültige Kategorie")
    else:
        if not _PKG_NAME_RE.fullmatch(target_package):
            raise HTTPException(status_code=400, detail="Ungültiger target_package")
        existing_pkg = await database.get_package(target_package)
        if not existing_pkg:
            raise HTTPException(
                status_code=404, detail=f"Paket '{target_package}' nicht gefunden"
            )
        if existing_pkg.get("type") != "custom":
            raise HTTPException(
                status_code=400, detail="Nur custom-Pakete unterstützen Versionen"
            )

    final_path, total_size, sha256, entries = await file_uploads.save_folder_upload(
        files, max_bytes
    )

    # Entry-Point validieren / ermitteln
    eff_entry = _validate_entry_point(entry_point or "")
    if eff_entry and eff_entry not in entries:
        raise HTTPException(
            status_code=400,
            detail=f"Entry-Point '{eff_entry}' ist nicht in den hochgeladenen Dateien enthalten",
        )
    if not eff_entry:
        eff_entry = file_uploads.pick_default_entry(entries)
        if not eff_entry:
            raise HTTPException(
                status_code=400,
                detail="Konnte keinen Entry-Point ermitteln — bitte manuell angeben",
            )

    # Defaults für Args
    eff_args = _validate_install_args(install_args)
    if not eff_args and not is_new_package:
        eff_args = (existing_pkg.get("install_args") or "").strip()
    # Kein universeller Default für Archive — der Entry-Point bestimmt die Args.

    # Uninstall-Cmd
    eff_uninstall = _validate_uninstall_cmd(uninstall_cmd)
    if not eff_uninstall and not is_new_package:
        eff_uninstall = (existing_pkg.get("uninstall_cmd") or "").strip()

    eff_detection = detection_name.strip()

    archive_filename = os.path.basename(final_path)  # <sha>.zip
    entries_json = _json.dumps(entries)

    # ── Modus 1: Neues Paket ──
    if is_new_package:
        # Slug aus dem display_name (nicht aus filename, da das nur "<sha>.zip" wäre)
        slug_base = re.sub(r"[^a-zA-Z0-9._\-]", "_", display_name)
        slug_base = re.sub(r"_+", "_", slug_base).strip("_-.")
        if not slug_base:
            slug_base = "paket"
        if not slug_base[0].isalnum():
            slug_base = "p_" + slug_base
        slug = slug_base[:100]
        if not _PKG_NAME_RE.fullmatch(slug):
            raise HTTPException(
                status_code=400,
                detail=f"Display-Name ergibt ungültigen Paketnamen: {slug!r}",
            )
        name = await file_uploads._unique_name(slug)

        await database.upsert_custom_package(
            name=name,
            display_name=display_name,
            category=category,
            filename=archive_filename,
            sha256=sha256,
            size_bytes=total_size,
            install_args=eff_args,
            uninstall_cmd=eff_uninstall or None,
            detection_name=eff_detection or None,
            archive_type="archive",
            entry_point=eff_entry,
        )

        label = _validate_version_label(version_label) or "v1"
        try:
            version_id = await database.add_package_version(
                package_name=name,
                version_label=label,
                filename=archive_filename,
                sha256=sha256,
                size_bytes=total_size,
                install_args=eff_args,
                uninstall_cmd=eff_uninstall or None,
                notes=(version_notes.strip() or None),
                archive_type="archive",
                entry_point=eff_entry,
                archive_entries=entries_json,
            )
        except Exception:
            logger.exception("Version-Insert fehlgeschlagen")
            raise HTTPException(
                status_code=500, detail="Version konnte nicht angelegt werden"
            )
        await database.set_current_package_version(name, version_id)

        return {
            "ok":             True,
            "name":           name,
            "display_name":   display_name,
            "category":       category,
            "size_bytes":     total_size,
            "sha256":         sha256,
            "archive_type":   "archive",
            "entry_point":    eff_entry,
            "entries":        entries,
            "install_args":   eff_args,
            "uninstall_cmd":  eff_uninstall or None,
            "detection_name": eff_detection or None,
            "version":        {"id": version_id, "label": label, "is_current": True},
        }

    # ── Modus 2: Neue Version an bestehendes Paket ──
    name = target_package
    existing_labels = await database.get_existing_version_labels(name)
    label = _validate_version_label(version_label)
    if not label:
        n = len(existing_labels) + 1
        while f"v{n}" in existing_labels:
            n += 1
        label = f"v{n}"
    if label in existing_labels:
        raise HTTPException(
            status_code=409, detail=f"Version-Label '{label}' existiert bereits",
        )

    try:
        version_id = await database.add_package_version(
            package_name=name,
            version_label=label,
            filename=archive_filename,
            sha256=sha256,
            size_bytes=total_size,
            install_args=eff_args,
            uninstall_cmd=eff_uninstall or None,
            notes=(version_notes.strip() or None),
            archive_type="archive",
            entry_point=eff_entry,
            archive_entries=entries_json,
        )
    except Exception:
        logger.exception("Version-Insert fehlgeschlagen (Konflikt)")
        raise HTTPException(
            status_code=409, detail="Version-Label konnte nicht angelegt werden (evtl. doppelt)"
        )

    set_current_flag = _parse_bool_form(set_current, default=True)
    if set_current_flag:
        await database.set_current_package_version(name, version_id)

    return {
        "ok":           True,
        "name":         name,
        "size_bytes":   total_size,
        "sha256":       sha256,
        "archive_type": "archive",
        "entry_point":  eff_entry,
        "entries":      entries,
        "version":      {"id": version_id, "label": label, "is_current": set_current_flag},
    }


@router.get("/admin/api/storage", dependencies=[Depends(_require_admin)])
async def get_storage():
    """Freier/genutzter Speicherplatz auf der Upload-Partition."""
    return file_uploads.get_storage_info()


# ── Runtime Settings ──────────────────────────────────────────────────────────

_SECRET_MASK = "••••••••"


class SettingsUpdate(BaseModel):
    """Partial update. Nur Keys die gesendet werden, werden verändert."""
    values: dict[str, str]


@router.get("/admin/api/settings", dependencies=[Depends(_require_admin)])
async def get_settings_view():
    """
    Gibt alle Runtime-Settings zurück. Secrets werden maskiert,
    aber `has_value` zeigt an ob ein Wert gesetzt ist.
    """
    current = await database.get_all_settings()
    result = []
    for key, meta in RUNTIME_KEYS.items():
        raw = current.get(key, "") or meta.get("default", "")
        has_value = bool(current.get(key) or (not meta.get("required")))
        if meta.get("secret"):
            value = _SECRET_MASK if current.get(key) else ""
        else:
            value = raw
        result.append({
            "key": key,
            "label": meta["label"],
            "help": meta.get("help", ""),
            "type": meta.get("type", "string"),
            "secret": meta.get("secret", False),
            "required": meta.get("required", False),
            "value": value,
            "has_value": has_value,
            "default": meta.get("default", ""),
        })
    return {"settings": result}


@router.patch("/admin/api/settings", dependencies=[Depends(_require_admin)])
async def patch_settings(body: SettingsUpdate):
    """
    Partial Update. Wenn ein Secret-Wert gleich dem Maskierungs-Platzhalter ist,
    wird er ignoriert (unverändert gelassen).
    """
    to_apply: dict[str, str] = {}
    errors: dict[str, str] = {}

    for key, value in body.values.items():
        if key not in RUNTIME_KEYS:
            errors[key] = "Unbekannter Key"
            continue
        # Maskierungs-Platzhalter → überspringen (bedeutet "nicht geändert")
        if RUNTIME_KEYS[key].get("secret") and value == _SECRET_MASK:
            continue
        try:
            to_apply[key] = validate_runtime_value(key, value)
        except ValueError as e:
            errors[key] = str(e)

    if errors:
        raise HTTPException(status_code=400, detail={"errors": errors})

    if to_apply:
        await database.set_settings_bulk(to_apply)

    return {"ok": True, "updated": list(to_apply.keys())}


@router.post("/admin/api/settings/rotate-registration-secret",
             dependencies=[Depends(_require_admin)])
async def rotate_registration_secret():
    """Generiert ein neues Registration-Secret und speichert es."""
    new_secret = secrets.token_hex(32)
    await database.set_setting("registration_secret", new_secret)
    return {"ok": True, "new_secret": new_secret}


@router.get("/admin/api/settings/{key}/reveal", dependencies=[Depends(_require_admin)])
async def reveal_setting(key: str):
    """
    Gibt den echten Wert eines Secret-Settings zurueck (fuer den Anzeigen-Button
    im Admin-UI). Non-secrets werden über den normalen GET /settings geliefert.
    """
    if key not in RUNTIME_KEYS:
        raise HTTPException(status_code=404, detail="Unbekannter Key")
    meta = RUNTIME_KEYS[key]
    if not meta.get("secret"):
        raise HTTPException(status_code=400, detail="Nur für Secret-Werte")
    value = await database.get_setting(key, "")
    return {"key": key, "value": value}


# ── Client Build (Wine PyInstaller builder) ───────────────────────────────────

@router.get("/admin/api/build/status", dependencies=[Depends(_require_admin)])
async def build_status():
    """Gibt den Status des letzten Build + eine Liste der letzten 10 Builds zurück."""
    latest = await database.get_latest_successful_build()
    recent = await database.get_builds(limit=10)

    slug = await runtime_value("product_slug") or "Softshelf"
    tray_name  = f"{slug}.exe"
    setup_name = f"{slug}-setup.exe"

    downloads_dir = "/app/downloads"
    tray_path  = os.path.join(downloads_dir, tray_name)
    setup_path = os.path.join(downloads_dir, setup_name)

    def _info(path: str) -> dict | None:
        if os.path.isfile(path):
            stat = os.stat(path)
            return {"size": stat.st_size, "mtime": int(stat.st_mtime)}
        return None

    return {
        "latest_build": latest,
        "recent_builds": recent,
        "slug": slug,
        "tray_name": tray_name,
        "setup_name": setup_name,
        "artifacts": {
            tray_name:  _info(tray_path),
            setup_name: _info(setup_path),
        },
    }


@router.get("/admin/api/build/{build_id}", dependencies=[Depends(_require_admin)])
async def build_detail(build_id: int):
    build = await database.get_build(build_id)
    if not build:
        raise HTTPException(status_code=404, detail="Build nicht gefunden")
    return build


@router.post("/admin/api/build", dependencies=[Depends(_require_admin)])
async def trigger_build():
    """
    Triggert einen neuen EXE-Build via den builder-Container.
    Benötigt dass proxy_public_url in den Einstellungen gesetzt ist.
    """
    proxy_url = await runtime_value("proxy_public_url")
    if not proxy_url:
        raise HTTPException(
            status_code=400,
            detail="proxy_public_url ist nicht gesetzt. Bitte zuerst in den Einstellungen eintragen.",
        )

    # Slug aus Runtime-Settings. Der Validator beim Speichern stellt sicher,
    # dass hier nur ein legitimer Wert stehen kann — zusaetzlich validiert
    # der Builder und build.sh das nochmal vor der Verwendung (defense in depth).
    slug = await runtime_value("product_slug") or "Softshelf"

    cfg = get_settings()
    version = "1.5.0"  # wird in der EXE angezeigt

    build_id = await database.start_build_log(proxy_url, version)

    # Build im Hintergrund starten, nicht auf Ergebnis warten
    _spawn_bg(_run_build_async(build_id, cfg.builder_url, proxy_url, version, slug))

    return {"ok": True, "build_id": build_id, "status": "running"}


async def _run_build_async(build_id: int, builder_url: str, proxy_url: str, version: str, slug: str):
    """Ruft den Builder-Container auf und speichert das Ergebnis im build_log."""
    status = "failed"
    log = ""
    try:
        async with httpx.AsyncClient(timeout=600) as c:
            r = await c.post(
                f"{builder_url}/build",
                json={
                    "proxy_url": proxy_url,
                    "version": version,
                    "product_slug": slug,
                },
            )
            data = r.json()
            log = data.get("log", "")
            status = "success" if data.get("ok") else "failed"
    except Exception as e:
        log = f"Builder nicht erreichbar: {e}"
        status = "failed"
    finally:
        await database.finish_build_log(build_id, status, log)


# ── Winget ────────────────────────────────────────────────────────────────────


class WingetSearchResult(BaseModel):
    id: str
    name: str
    publisher: str
    latest_version: str
    source: str
    enabled: bool


class WingetActivateRequest(BaseModel):
    id: str = Field(min_length=1, max_length=200)
    display_name: str = Field(min_length=1, max_length=80)
    category: str = Field(default="Allgemein", min_length=1, max_length=40)
    publisher: str = Field(default="", max_length=120)
    latest_version: str = Field(default="", max_length=50)

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not _WINGET_ID_RE.fullmatch(v):
            raise ValueError("Ungültige winget-PackageIdentifier")
        return v

    @field_validator("display_name", "category")
    @classmethod
    def _check_text(cls, v: str) -> str:
        if not _TEXT_RE.fullmatch(v):
            raise ValueError("Text enthält ungültige Zeichen")
        return v

    @field_validator("publisher", "latest_version")
    @classmethod
    def _check_optional(cls, v: str) -> str:
        if v and not _NO_CTRL_RE.fullmatch(v):
            raise ValueError("Feld enthält Steuerzeichen")
        return v


@router.get(
    "/admin/api/winget/search",
    response_model=list[WingetSearchResult],
    dependencies=[Depends(_require_admin)],
)
async def winget_search(q: str = Query(default="", min_length=0, max_length=100)):
    """Sucht im Microsoft winget-Catalog. Leere Query liefert leere Liste."""
    if not q.strip():
        return []
    try:
        results = await winget_catalog.search(q)
    except Exception:
        logger.exception("winget catalog search failed")
        raise HTTPException(status_code=502, detail="winget-Catalog nicht erreichbar")

    enabled_ids = await database.get_whitelisted_winget_ids()
    return [
        WingetSearchResult(
            id=r["id"],
            name=r["name"],
            publisher=r["publisher"],
            latest_version=r["latest_version"],
            source=r["source"],
            enabled=r["id"] in enabled_ids,
        )
        for r in results
    ]


@router.post("/admin/api/winget/activate", dependencies=[Depends(_require_admin)])
async def winget_activate(body: WingetActivateRequest):
    """
    Whitelistet ein winget-Paket. Falls Felder nicht angegeben sind, werden
    sie aus dem Catalog nachgeholt.
    """
    name = body.display_name
    publisher = body.publisher
    latest_version = body.latest_version
    if not name or not publisher or not latest_version:
        try:
            details = await winget_catalog.get_details(body.id)
        except Exception:
            details = None
        if details:
            name = name or details["name"]
            publisher = publisher or details["publisher"]
            latest_version = latest_version or details["latest_version"]

    await database.upsert_winget_package(
        name=body.id,
        display_name=name or body.id,
        category=body.category,
        publisher=publisher or None,
        winget_version=None,  # MVP: immer latest, kein Pin
    )
    rows = await database.get_packages()
    return {"ok": True, "total": len(rows)}


@router.get("/admin/api/winget/discovery", dependencies=[Depends(_require_admin)])
async def winget_discovery():
    """
    Liefert die Discovery-Liste:
      - Primary: winget-IDs aus agent_winget_state, die nicht whitelisted sind
      - Bonus: Tactical-software-scan Display-Namen aus discovery_enrichment
               (mit aufgelöstem winget_id + confidence)
    Beide Quellen werden zu einer gemischten Liste kombiniert.
    """
    primary = await database.query_winget_discovery()
    bonus = await database.query_software_discovery()

    # Primary in Map für O(1) Dedup
    primary_ids = {row["winget_id"] for row in primary}

    items = []
    for row in primary:
        items.append({
            "source":         "winget_scan",
            "winget_id":      row["winget_id"],
            "display_name":   row["winget_id"],  # ohne enrichment-Hilfe nur die ID
            "install_count":  row["install_count"],
            "sample_version": row.get("sample_version") or "",
            "confidence":     "high",  # winget-scan = direkter Treffer
        })

    for row in bonus:
        wid = row.get("winget_id")
        if wid and wid in primary_ids:
            # Bereits via primary abgedeckt, dem Bonus-Eintrag nichts neues
            continue
        items.append({
            "source":         "tactical_scan",
            "winget_id":      wid or "",
            "display_name":   row["display_name"],
            "install_count":  row["install_count"],
            "sample_version": "",
            "confidence":     row.get("confidence") or "none",
        })

    return {"items": items, "total": len(items)}


@router.get("/admin/api/winget/discovery-count", dependencies=[Depends(_require_admin)])
async def winget_discovery_count():
    """Zahl für das Header-Banner. Billig, einmal pro Page-Load."""
    count = await database.get_winget_discovery_count()
    return {"count": count}


@router.post("/admin/api/winget/rescan/{agent_id}", dependencies=[Depends(_require_admin)])
async def winget_rescan(agent_id: str):
    """
    Triggert einen sofortigen targeted Re-Scan eines Agents. Setzt
    consecutive_failures zurück damit Agents die aus dem nightly-Batch
    rausgefallen sind wieder am nächsten Run teilnehmen.
    """
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungültige Agent-ID")
    agent = await database.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent nicht gefunden")

    await database.reset_scan_failures(agent_id)
    # Im Hintergrund starten — Admin-UI muss nicht warten
    _spawn_bg(winget_scanner.scan_agent(agent_id))
    return {"ok": True, "started": True}


@router.post("/admin/api/winget/run-nightly", dependencies=[Depends(_require_admin)])
async def winget_run_nightly_now():
    """Manueller Trigger für den nightly-Scan (für Tests + on-demand)."""
    _spawn_bg(winget_scanner.run_nightly_scan())
    return {"ok": True, "started": True}


@router.post("/admin/api/winget/run-enrichment", dependencies=[Depends(_require_admin)])
async def winget_run_enrichment_now():
    """Manueller Trigger für den Enrichment-Job."""
    _spawn_bg(winget_enrichment.run_enrichment_job())
    return {"ok": True, "started": True}


class WingetUninstallOnAgentRequest(BaseModel):
    winget_id: str = Field(min_length=1, max_length=200)

    @field_validator("winget_id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not _WINGET_ID_RE.fullmatch(v):
            raise ValueError("Ungültige winget-PackageIdentifier")
        return v


@router.post(
    "/admin/api/agents/{agent_id}/winget-uninstall",
    dependencies=[Depends(_require_admin)],
)
async def winget_uninstall_on_agent(agent_id: str, body: WingetUninstallOnAgentRequest):
    """
    Deinstalliert ein winget-Paket auf einem Agent — funktioniert auch wenn
    das Paket NICHT in der Softshelf-Whitelist steht. Wird vom Agent-Detail
    benutzt um unerwünschte Software via `winget uninstall --id <ID>` direkt
    aufzuräumen.
    """
    from routes.install import _build_winget_command, _run_winget_command_bg

    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungültige Agent-ID")
    agent = await _resolve_agent(agent_id)

    wid = body.winget_id
    cmd = _build_winget_command("uninstall", wid)
    # Display-Name aus der Whitelist falls vorhanden, sonst die ID selbst
    pkg = await database.get_package(wid)
    display_name = pkg["display_name"] if pkg else wid

    _spawn_bg(_run_winget_command_bg(
        agent_id, agent["hostname"], wid, display_name, cmd, "uninstall", wid,
    ))
    await database.log_install(
        agent_id, agent["hostname"], wid, display_name, "uninstall"
    )
    return {"ok": True, "agent": agent["hostname"]}
