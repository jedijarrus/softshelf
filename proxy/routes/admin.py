"""
Admin-Oberfläche: /admin
Session-Cookie-Auth mit lokaler User-DB + optionalem Microsoft-Entra-SSO.
CSRF-Schutz via Middleware (X-Requested-With) bleibt aktiv.
"""
import asyncio
import base64
import html
import io
import logging
import os
import re
import secrets
from datetime import datetime, timezone
from typing import Optional
from fastapi import (
    APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field, field_validator

import httpx
from PIL import Image, UnidentifiedImageError
from PIL.Image import DecompressionBombError

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
_WINGET_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-+]{0,199}$")
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


# RBAC: path-prefixes die nur Admins bearbeiten duerfen (POST/PATCH/DELETE).
# Alle anderen POST/PATCH/DELETE sind fuer operator+admin. GET ueberall fuer
# viewer+operator+admin. Viewer hat sonst nix — kein Dispatch, kein Edit.
_ADMIN_ONLY_PATHS = (
    "/admin/api/settings",
    "/admin/api/users",
    "/admin/api/enable",            # Whitelist add/PATCH
    "/admin/api/disable",
    "/admin/api/upload",
    "/admin/api/build",
    "/admin/api/builds",
    "/admin/api/branding",
    "/admin/api/icon",
    "/admin/api/winget/activate",
    "/admin/api/winget/bulk-activate",
    "/admin/api/winget/",            # catches /{name}/scope, /version-pin, etc
    "/admin/api/packages/",          # catches /required, /staged, /notes
    "/admin/api/profiles",           # Profile-Edit + Create + Delete
    "/admin/api/rescan-secret",
    "/admin/api/scheduled",          # Maintenance-Windows: create + delete admin only
    # Agents: Ring-Mutation + Ban/Unban + Delete sind admin-only.
    # Dispatch (install/uninstall/update-all/ack-error) bleibt operator OK.
    "/admin/api/agents/",
)

# Exception-Suffixes: wenn POST/PATCH/DELETE auf admin-only path liegt aber
# mit diesem Suffix endet, bleibt es operator-zugaenglich (Dispatch-Aktionen).
_ADMIN_ONLY_EXCEPTIONS = (
    "/push-update",
    "/update-all",
    "/rollouts",
    "/apply",                        # profile apply
    "/ack-error",                    # error acknowledgement
    "/install",                      # wird mit /install/{pkg} gematched
    "/uninstall",
    "/install-bulk",
    "/rescan",
    "/winget-uninstall",
)


async def _require_admin(request: Request) -> dict:
    """
    Auth-Dependency: prueft Session-Cookie + erzwingt Role-based Access.

    Rollen:
      admin    — alles
      operator — dispatch (install/uninstall/push/bulk), ack errors, ring setzen;
                 KEIN whitelist-edit, KEINE users/settings/build
      viewer   — nur GETs, keine state-changing operations

    RBAC wird hier zentral gecheckt anhand method + path. Dadurch muss
    kein Endpoint einzeln dekoriert werden.
    """
    token = request.cookies.get(admin_auth.SESSION_COOKIE)
    user = await admin_auth.get_session_user(token)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Nicht angemeldet",
            headers={"X-Auth-Required": "session"},
        )
    role = user.get("role") or "admin"
    method = request.method.upper()
    path = request.url.path

    # GETs ueberall frei fuer alle Rollen
    if method == "GET":
        return user

    # Viewer: keine state-changing Aktionen
    if role == "viewer":
        raise HTTPException(
            status_code=403,
            detail="Viewer-Rolle hat nur Lesezugriff.",
        )

    # Admin-only Pfade mit Exception-Liste fuer Operator-Dispatch-Aktionen.
    if role != "admin" and any(path.startswith(p) for p in _ADMIN_ONLY_PATHS):
        # /admin/api/agents/{id}/install/{pkg} — endet auf /install/... nicht /install
        # Also: prüfe ob irgendein Exception-Suffix im Pfad vorkommt nach dem
        # Prefix-Match. Wir nutzen "endswith ODER enthaelt /suffix/"
        # (z.B. /install/PAKET), beides als Operator-Aktion zulaessig.
        for suffix in _ADMIN_ONLY_EXCEPTIONS:
            if path.endswith(suffix) or (suffix + "/") in path:
                return user
        raise HTTPException(
            status_code=403,
            detail=(
                f"Aktion nur fuer admin-Rolle. Deine Rolle: {role}. "
                f"Bitte einen Admin um Durchfuehrung."
            ),
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
        "role": user.get("role") or "admin",
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

_VALID_ROLES = {"admin", "operator", "viewer"}


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=2, max_length=80)
    display_name: str = Field(default="", max_length=80)
    email: str = Field(default="", max_length=200)
    password: str = Field(min_length=8, max_length=200)
    is_active: bool = True
    role: str = "admin"

    @field_validator("username")
    @classmethod
    def _check_username(cls, v: str) -> str:
        if not _USERNAME_RE.fullmatch(v):
            raise ValueError("Username darf nur a-zA-Z0-9._-@ enthalten (2-80 Zeichen)")
        return v

    @field_validator("role")
    @classmethod
    def _check_role(cls, v: str) -> str:
        if v not in _VALID_ROLES:
            raise ValueError(f"role muss eine von {sorted(_VALID_ROLES)} sein")
        return v


class UserUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=80)
    email: Optional[str] = Field(default=None, max_length=200)
    password: Optional[str] = Field(default=None, min_length=8, max_length=200)
    is_active: Optional[bool] = None
    role: Optional[str] = None

    @field_validator("role")
    @classmethod
    def _check_role(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if v not in _VALID_ROLES:
            raise ValueError(f"role muss eine von {sorted(_VALID_ROLES)} sein")
        return v


def _public_user(u: dict) -> dict:
    return {
        "id": u["id"],
        "username": u["username"],
        "display_name": u.get("display_name"),
        "email": u.get("email"),
        "is_active": bool(u.get("is_active")),
        "role": u.get("role") or "admin",
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
        role=body.role,
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
        role=body.role,
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
    winget_scope: str | None = None
    required: int = 0
    notes: str | None = None
    staged_rollout: int = 0
    hidden_in_kiosk: int = 0
    auto_advance: int = 0


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
async def list_package_agents(
    name: str,
    q: str = "",
    outdated_only: bool = False,
):
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

    Filter:
      q             - Substring auf hostname oder agent_id
      outdated_only - nur Agents mit outdated==True
    """
    if not _PKG_NAME_RE.fullmatch(name) and not _WINGET_ID_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    ptype = pkg.get("type") or "choco"
    needle = (q or "").strip().lower()

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
        # custom: Zwei Quellen zusammenfuehren:
        #   1) agent_installations — Softshelf-tracked Installs (mit
        #      version_id + outdated-Flag gegen current_version_id)
        #   2) Tactical-Software-Scan pro Agent + detection_name-Match —
        #      erwischt pre-existing Installs die NICHT via Softshelf kamen
        rows = await database.get_installations_for_package(name)
        tracked_ids: set[str] = set()
        for r in rows:
            agents.append({
                "agent_id":          r["agent_id"],
                "hostname":          r["hostname"],
                "last_seen":         r["last_seen"],
                "installed_version": r.get("version_label"),
                "available_version": None,
                "scanned_at":        r.get("installed_at"),
                "outdated":          bool(r.get("outdated")),
                "source":            "tracked",
            })
            tracked_ids.add(r["agent_id"])

        # Tactical-Scan fuer alle anderen aktiven Agents parallel abrufen.
        # Match via detection_name (fallback display_name). Nur Agents mit
        # last_seen in den letzten 30 Tagen — sonst zu viele dead-Calls.
        detection_needle = (
            (pkg.get("detection_name") or pkg.get("display_name") or name)
            .lower().strip()
        )
        if detection_needle:
            from datetime import datetime, timezone, timedelta
            all_agents = await database.get_agents()
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec='seconds')
            candidates = [
                a for a in all_agents
                if not a.get("banned")
                and a["agent_id"] not in tracked_ids
                and (a.get("last_seen") or "") >= cutoff
            ]

            import asyncio
            sem = asyncio.Semaphore(8)  # max 8 parallele Tactical-Calls
            tactical = TacticalClient()

            async def _scan_one(agent: dict):
                async with sem:
                    try:
                        sw = await tactical.get_installed_software(agent["agent_id"])
                    except Exception:
                        return None
                for item in sw or []:
                    iname = (item.get("name") or "").lower()
                    if not iname:
                        continue
                    if detection_needle in iname or iname in detection_needle:
                        return {
                            "agent_id":          agent["agent_id"],
                            "hostname":          agent.get("hostname"),
                            "last_seen":         agent.get("last_seen"),
                            "installed_version": item.get("version") or None,
                            "available_version": None,
                            "scanned_at":        None,
                            "outdated":          False,  # unbekannt — kein version-id-tracking
                            "source":            "tactical",
                        }
                return None

            results = await asyncio.gather(
                *(_scan_one(a) for a in candidates), return_exceptions=True
            )
            for r in results:
                if isinstance(r, dict):
                    agents.append(r)

    total_all = len(agents)
    if needle:
        agents = [
            a for a in agents
            if needle in (a.get("hostname") or "").lower()
            or needle in (a.get("agent_id") or "").lower()
        ]
    if outdated_only:
        agents = [a for a in agents if a.get("outdated")]

    return {
        "package": {
            "name":         name,
            "display_name": pkg.get("display_name"),
            "type":         ptype,
            "category":     pkg.get("category"),
        },
        "total":          total_all,
        "total_filtered": len(agents),
        "agents":         agents,
    }


@router.post(
    "/admin/api/packages/{name}/push-update",
    dependencies=[Depends(_require_admin)],
)
async def push_update(name: str, stage: str = "all"):
    """
    Triggert ein Update auf allen Agents die das Paket outdated haben.

    Pro Paket-Typ:
      - custom: Reinstall der current-Version auf allen NICHT-current Agents
      - winget: upgrade auf allen Agents wo agent_winget_state.available_version
                gesetzt ist
      - choco:  install (choco install ist idempotent und macht upgrade) auf
                allen Agents wo agent_choco_state.available_version gesetzt ist

    Geht durch den shared dispatch_install_for_agent/upgrade-Helper, damit
    scope, version-pin und soft-error-detection konsistent bleiben.
    """
    from routes.install import dispatch_upgrade_for_agent, _build_install_command, _run_custom_command_bg

    # Namens-Check ist fuer winget looser als fuer choco/custom
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    ptype = pkg.get("type") or "choco"
    if ptype != "winget" and not _PKG_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungueltiger Paketname")
    if ptype == "winget" and not _WINGET_ID_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungueltige winget-ID")

    _check_stage(stage)
    _enforce_staged_guard(pkg, stage)

    # Agent-Filter gemaess stage: bauen wir ein Set von agent_ids
    # damit wir den outdated-Filter gegen-schneiden koennen.
    allowed_agents = {a["agent_id"] for a in
                      await database.get_agents_by_ring(_stage_to_ring_filter(stage))}

    if ptype == "custom":
        if not pkg.get("sha256"):
            raise HTTPException(status_code=400, detail="Paket hat keine aktive Version")

        outdated = await database.get_outdated_agents_for_package(name)
        outdated = [a for a in outdated if a["agent_id"] in allowed_agents]
        if not outdated:
            return {"ok": True, "dispatched": 0, "message": "Keine outdated Agents in dieser Stage."}

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
        return {"ok": True, "dispatched": dispatched,
                "outdated": len(outdated), "failed": failed}

    # winget / choco: dieselbe generische Logik, nur andere Source-Tabelle
    if ptype == "winget":
        raw = await database.get_agents_with_winget_package(name)
    else:
        raw = await database.get_agents_with_choco_package(name)

    outdated_agents = [r for r in raw if r.get("available_version")
                       and r["agent_id"] in allowed_agents]
    if not outdated_agents:
        return {"ok": True, "dispatched": 0, "message": "Keine outdated Agents in dieser Stage."}

    dispatched = 0
    failed: list[str] = []
    for ag in outdated_agents:
        try:
            await dispatch_upgrade_for_agent(ag["agent_id"], ag.get("hostname") or "", pkg)
            dispatched += 1
        except Exception as e:
            failed.append(f"{ag.get('hostname')}: {e}")
    return {"ok": True, "dispatched": dispatched,
            "outdated": len(outdated_agents), "failed": failed}


# ── Scheduled Jobs (Maintenance-Windows) ───────────────────────────────────
#
# Admin legt Jobs an (run_at + action). APScheduler laeuft in main.py und
# checkt alle 60s pending Jobs deren run_at <= now ist und fuehrt sie aus.
# Einfacher als per-job DateTrigger registrieren und wieder aufraumen.
#
# Unterstuetzte action_type:
#   "push_update":    {"package_name": X, "stage": "all|ring1|..."}
#   "update_all":     {"package_name": X, "stage": "..."}
#   "bulk_distribution": {"package_names": [...], "action": "push_update|uninstall_all", "stage": "..."}
#   "compliance_fix": {"stage": "..."}

_VALID_JOB_ACTIONS = {
    "push_update", "update_all", "bulk_distribution", "compliance_fix",
}


class ScheduledJobCreateBody(BaseModel):
    run_at: str          # ISO 8601 datetime (UTC)
    action_type: str
    action_params: dict
    description: str = Field(default="", max_length=200)

    @field_validator("action_type")
    @classmethod
    def _check_action(cls, v: str) -> str:
        if v not in _VALID_JOB_ACTIONS:
            raise ValueError(f"action_type muss eine von {sorted(_VALID_JOB_ACTIONS)} sein")
        return v

    @field_validator("run_at")
    @classmethod
    def _check_time(cls, v: str) -> str:
        try:
            from datetime import datetime
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            raise ValueError("run_at muss ISO 8601 datetime sein")
        return v

    @field_validator("action_params")
    @classmethod
    def _check_params(cls, v: dict) -> dict:
        # Hartes Limit fuer DoS-Schutz: kein Array > 500, kein String > 500
        names = v.get("package_names")
        if names is not None:
            if not isinstance(names, list):
                raise ValueError("package_names muss eine Liste sein")
            if len(names) > 500:
                raise ValueError("package_names max 500")
            for n in names:
                if not isinstance(n, str) or len(n) > 200:
                    raise ValueError("package_name-Eintrag ungueltig")
        pn = v.get("package_name")
        if pn is not None and (not isinstance(pn, str) or len(pn) > 200):
            raise ValueError("package_name ungueltig")
        stage = v.get("stage")
        if stage is not None and stage not in _VALID_STAGES:
            raise ValueError(f"stage ungueltig")
        action = v.get("action")
        if action is not None and action not in ("push_update", "uninstall_all"):
            raise ValueError("action ungueltig")
        return v


async def execute_scheduled_job(job: dict) -> dict:
    """Fuehrt einen scheduled Job aus. Wird von APScheduler-Tick oder manuell
    gerufen. Returns result dict."""
    import json as _json
    from routes.install import dispatch_install_for_agent, dispatch_upgrade_for_agent, dispatch_uninstall_for_agent

    try:
        params = _json.loads(job["action_params"])
    except Exception:
        return {"ok": False, "error": "Ungueltige action_params"}

    action_type = job["action_type"]
    stage = params.get("stage", "all")
    if stage not in _VALID_STAGES:
        return {"ok": False, "error": f"Invalid stage: {stage}"}

    allowed_agents = {a["agent_id"] for a in
                      await database.get_agents_by_ring(_stage_to_ring_filter(stage))}
    dispatched = 0
    errors: list[str] = []

    try:
        if action_type in ("push_update", "update_all"):
            pkg = await database.get_package(params.get("package_name"))
            if not pkg:
                return {"ok": False, "error": "Paket nicht gefunden"}
            ptype = pkg.get("type") or "choco"
            if ptype == "winget":
                raw = await database.get_agents_with_winget_package(pkg["name"])
            elif ptype == "choco":
                raw = await database.get_agents_with_choco_package(pkg["name"])
            else:
                raw = []
            targets = [r for r in raw if r.get("available_version") and r["agent_id"] in allowed_agents]
            for ag in targets:
                try:
                    await dispatch_upgrade_for_agent(ag["agent_id"], ag.get("hostname") or "", pkg)
                    dispatched += 1
                except Exception as e:
                    errors.append(f"{ag.get('hostname')}: {e}")
        elif action_type == "bulk_distribution":
            bulk_action = params.get("action", "push_update")
            pkg_names = params.get("package_names") or []
            if not isinstance(pkg_names, list):
                return {"ok": False, "error": "package_names muss Liste sein"}
            for pkg_name in pkg_names:
                if not isinstance(pkg_name, str):
                    continue
                pkg = await database.get_package(pkg_name)
                if not pkg:
                    continue
                ptype = pkg.get("type") or "choco"
                if ptype == "winget":
                    raw = await database.get_agents_with_winget_package(pkg_name)
                elif ptype == "choco":
                    raw = await database.get_agents_with_choco_package(pkg_name)
                else:
                    raw = await database.get_installations_for_package(pkg_name)
                if bulk_action == "push_update":
                    targets = [a for a in raw if a.get("available_version") or a.get("outdated")]
                else:
                    targets = raw
                targets = [a for a in targets if a["agent_id"] in allowed_agents]
                for ag in targets:
                    try:
                        if bulk_action == "push_update":
                            await dispatch_upgrade_for_agent(ag["agent_id"], ag.get("hostname") or "", pkg)
                        else:
                            await dispatch_uninstall_for_agent(ag["agent_id"], ag.get("hostname") or "", pkg)
                        dispatched += 1
                    except Exception as e:
                        errors.append(f"{ag.get('hostname')}/{pkg_name}: {e}")
        elif action_type == "compliance_fix":
            overview = await database.get_compliance_overview()
            for p in overview["required_packages"]:
                pkg = await database.get_package(p["name"])
                if not pkg:
                    continue
                if pkg.get("staged_rollout") and stage == "all":
                    continue
                for miss in p["missing"]:
                    if miss["agent_id"] not in allowed_agents:
                        continue
                    try:
                        await dispatch_install_for_agent(
                            miss["agent_id"], miss.get("hostname") or "", pkg,
                        )
                        dispatched += 1
                    except Exception as e:
                        errors.append(f"{miss.get('hostname')}/{p['name']}: {e}")
    except Exception as e:
        logger.exception("scheduled job execution crashed: %s", e)
        return {"ok": False, "error": str(e)[:300]}

    return {
        "ok": True,
        "dispatched": dispatched,
        "errors": errors,
    }


@router.post("/admin/api/scheduled", dependencies=[Depends(_require_admin)])
async def create_scheduled(body: ScheduledJobCreateBody, user: dict = Depends(_require_admin)):
    job_id = await database.create_scheduled_job(
        run_at=body.run_at,
        action_type=body.action_type,
        action_params=body.action_params,
        description=body.description,
        created_by=user.get("user_id"),
    )
    job = await database.get_scheduled_job(job_id)
    return {"ok": True, "job": job}


@router.get("/admin/api/scheduled", dependencies=[Depends(_require_admin)])
async def list_scheduled(status: str | None = None):
    if status and status not in ("pending", "done", "cancelled", "failed"):
        raise HTTPException(status_code=400, detail="Ungueltiger status")
    return {"jobs": await database.list_scheduled_jobs(status=status, limit=200)}


@router.delete("/admin/api/scheduled/{job_id}", dependencies=[Depends(_require_admin)])
async def cancel_scheduled(job_id: int):
    await database.cancel_scheduled_job(job_id)
    return {"ok": True}


# ── Rollouts (phased rollout state machine) ─────────────────────────────────
#
# Konzept: Admin startet „Rollout" fuer ein Paket — erste Phase geht an Ring 1
# (Canary). Admin pruft Fehler, klickt „Weiter" fuer Phase 2 (Pilot), dann
# Phase 3 (Produktion). Bei Fehler: „Abbrechen" stoppt.
#
# Phase -> Stage-Mapping:
#   1 -> ring1 (Canary)
#   2 -> ring2 (Pilot)
#   3 -> prod  (Rest, nicht-Test-Ringe)
#
# Kein Auto-Advance — Admin muss manuell weiterklicken, damit Fehlerpruefung
# immer zwischen den Phasen moeglich ist.

_PHASE_TO_STAGE = {1: "ring1", 2: "ring2", 3: "prod"}


class StartRolloutBody(BaseModel):
    action: str = "push_update"

    @field_validator("action")
    @classmethod
    def _check_action(cls, v: str) -> str:
        if v not in ("push_update",):
            raise ValueError("action muss 'push_update' sein")
        return v


async def _dispatch_rollout_phase(pkg: dict, phase: int) -> dict:
    """Dispatched die aktuelle Phase eines Rollouts an die passenden Agents."""
    from routes.install import dispatch_install_for_agent, dispatch_upgrade_for_agent
    stage = _PHASE_TO_STAGE.get(phase)
    if not stage:
        return {"dispatched": 0, "failed": []}
    ptype = pkg.get("type") or "choco"
    allowed = {a["agent_id"] for a in
               await database.get_agents_by_ring(_stage_to_ring_filter(stage))}
    # Fleet: nur outdated + in allowed ring
    if ptype == "winget":
        raw = await database.get_agents_with_winget_package(pkg["name"])
    elif ptype == "choco":
        raw = await database.get_agents_with_choco_package(pkg["name"])
    else:
        raw = []  # custom hat eigenen push-update-Pfad, kein Rollout-Support
    targets = [r for r in raw if r.get("available_version") and r["agent_id"] in allowed]
    dispatched = 0
    failed: list[str] = []
    for ag in targets:
        try:
            await dispatch_upgrade_for_agent(ag["agent_id"], ag.get("hostname") or "", pkg)
            dispatched += 1
        except Exception as e:
            failed.append(f"{ag.get('hostname')}: {e}")
    return {"dispatched": dispatched, "failed": failed, "stage": stage}


@router.post("/admin/api/packages/{name}/rollouts", dependencies=[Depends(_require_admin)])
async def start_rollout(name: str, body: StartRolloutBody, user: dict = Depends(_require_admin)):
    """Startet einen phased rollout fuer ein Paket. Dispatched sofort Phase 1."""
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    rollout_id = await database.create_rollout(
        package_name=name,
        display_name=pkg.get("display_name") or name,
        action=body.action,
        created_by=user.get("user_id"),
    )
    result = await _dispatch_rollout_phase(pkg, 1)
    return {"ok": True, "rollout_id": rollout_id, "phase": 1, **result}


@router.post("/admin/api/rollouts/{rollout_id}/advance", dependencies=[Depends(_require_admin)])
async def advance_rollout_endpoint(rollout_id: int):
    from datetime import datetime, timezone
    rollout = await database.get_rollout(rollout_id)
    if not rollout:
        raise HTTPException(status_code=404, detail="Rollout nicht gefunden")
    if rollout["status"] != "active":
        raise HTTPException(status_code=400, detail=f"Rollout ist nicht aktiv ({rollout['status']})")
    pkg = await database.get_package(rollout["package_name"])
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht mehr vorhanden")
    # advance persistiert zuerst die aktuelle Phase als "durchlaufen", dann
    # dispatched die NEUE Phase. Compare-and-swap gegen rollout["current_phase"]
    # damit zwei parallele Klicks nicht doppelt advancen.
    updated = await database.advance_rollout(
        rollout_id,
        {"at": datetime.now(timezone.utc).isoformat(timespec='seconds')},
        expected_phase=rollout["current_phase"],
    )
    if not updated:
        raise HTTPException(
            status_code=409,
            detail="Rollout wurde inzwischen geaendert — bitte Ansicht neu laden.",
        )
    if updated["status"] == "done":
        return {"ok": True, "rollout": updated, "dispatched": 0, "message": "Rollout abgeschlossen"}
    result = await _dispatch_rollout_phase(pkg, updated["current_phase"])
    return {"ok": True, "rollout": updated, **result}


@router.post("/admin/api/rollouts/{rollout_id}/cancel", dependencies=[Depends(_require_admin)])
async def cancel_rollout_endpoint(rollout_id: int):
    """Cancelt den Rollout. Wenn das Paket auto_advance=1 hat: schaltet
    auto_advance automatisch aus — sonst wuerde der naechste auto-start-Tick
    sofort einen neuen Rollout anlegen (Loop)."""
    rollout = await database.get_rollout(rollout_id)
    await database.cancel_rollout(rollout_id)
    if rollout:
        pkg = await database.get_package(rollout["package_name"])
        if pkg and pkg.get("auto_advance"):
            await database.update_package_auto_advance(pkg["name"], False)
    return {"ok": True}


@router.post("/admin/api/rollouts/{rollout_id}/pause-auto",
             dependencies=[Depends(_require_admin)])
async def pause_auto_rollout(rollout_id: int):
    """Pausiert Auto-Advance fuer den laufenden Rollout: setzt das Paket-
    Flag auto_advance=0. Rollout bleibt aktiv, Admin kann dann manuell
    'Weiter' klicken. Kein Cancel."""
    rollout = await database.get_rollout(rollout_id)
    if not rollout:
        raise HTTPException(status_code=404, detail="Rollout nicht gefunden")
    pkg = await database.get_package(rollout["package_name"])
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    await database.update_package_auto_advance(pkg["name"], False)
    return {"ok": True}


@router.get("/admin/api/packages/{name}/rollouts",
            dependencies=[Depends(_require_admin)])
async def list_package_rollouts(name: str):
    """Alle Rollouts eines Pakets (Historie) — neueste zuerst."""
    import json as _json
    rows = await database.list_rollouts_for_package(name, limit=50)
    for r in rows:
        try:
            r["phase_history_parsed"] = _json.loads(r.get("phase_history") or "[]")
        except Exception:
            r["phase_history_parsed"] = []
    return {"rollouts": rows}


@router.get("/admin/api/rollouts", dependencies=[Depends(_require_admin)])
async def list_rollouts_endpoint(status: str | None = None):
    if status and status not in ("active", "done", "cancelled"):
        raise HTTPException(status_code=400, detail="Ungueltiger status")
    return {"rollouts": await database.list_rollouts(status=status, limit=100)}


@router.get("/admin/api/rollouts/staged-overview", dependencies=[Depends(_require_admin)])
async def get_staged_overview():
    """Aggregierte Sicht aller staged Pakete mit pro-Paket Rollout-Status.

    Liefert pro Paket:
      - status: 'running' | 'ready' | 'done' | 'never'
      - target_version + dominante alte installed_version (fuer Diff)
      - phases[1..3]: Ring-Stats (total, on_target, on_old, missing)
      - active_rollout (wenn status=running) inkl. phase_history
      - last_done_rollout (wenn vorhanden)
      - error_count (offene Fehler fuer dieses Paket)
      - auto_advance Flag des Pakets
    """
    import json as _json

    all_pkgs = await database.get_packages()
    staged = [p for p in all_pkgs if p.get("staged_rollout")]
    if not staged:
        return {"packages": [], "ring_labels": {
            1: (await runtime_value("rollout_ring1_label")) or "Canary",
            2: (await runtime_value("rollout_ring2_label")) or "Pilot",
            3: (await runtime_value("rollout_ring3_label")) or "Produktion",
        }}

    active_rollouts = await database.get_active_rollout_phases()
    latest_rollouts = await database.get_rollout_latest_per_package()
    error_counts = await database.get_package_error_counts()

    # Vollstaendige aktive Rollout-Rows einmal holen und auf Paket-Namen indexieren
    active_rollout_rows_list = await database.list_rollouts(status="active", limit=500)
    active_rollout_rows: dict[str, dict] = {}
    for r in active_rollout_rows_list:
        try:
            r["phase_history_parsed"] = _json.loads(r.get("phase_history") or "[]")
        except Exception:
            r["phase_history_parsed"] = []
        active_rollout_rows[r["package_name"]] = r

    labels = {
        1: (await runtime_value("rollout_ring1_label")) or "Canary",
        2: (await runtime_value("rollout_ring2_label")) or "Pilot",
        3: (await runtime_value("rollout_ring3_label")) or "Produktion",
    }

    out = []
    for pkg in staged:
        name = pkg["name"]
        ptype = pkg.get("type") or "choco"

        # Target-Version ermitteln (je nach Paket-Typ)
        target_version = None
        if ptype == "winget":
            target_version = pkg.get("winget_version")
            if not target_version:
                # Latest aus Catalog ODER dominante available_version im Fleet
                try:
                    details = await winget_catalog.get_details(name)
                    if details:
                        target_version = details.get("latest_version")
                except Exception:
                    pass
                if not target_version:
                    fleet = await database.get_agents_with_winget_package(name)
                    avs = [r.get("available_version") for r in fleet if r.get("available_version")]
                    if avs:
                        target_version = max(avs)
        elif ptype == "choco":
            fleet = await database.get_agents_with_choco_package(name)
            avs = [r.get("available_version") for r in fleet if r.get("available_version")]
            if avs:
                target_version = max(avs)
        else:  # custom
            cv_id = pkg.get("current_version_id")
            if cv_id:
                cv = await database.get_package_version(cv_id)
                if cv:
                    target_version = cv.get("version_label")

        # Per-Ring Version-Split
        split = await database.get_package_agents_version_split(name, ptype, target_version)

        # Dominante Versionen im Fleet berechnen:
        # - current_installed_version: haeufigste installed_version (any)
        # - old_installed_version:     haeufigste installed_version != target (fuer Diff)
        all_vers_counter: dict[str, int] = {}
        old_vers_counter: dict[str, int] = {}
        for ring in (1, 2, 3):
            for a in split[ring]["agents"]:
                iv = a.get("installed_version")
                if not iv:
                    continue
                all_vers_counter[iv] = all_vers_counter.get(iv, 0) + 1
                if iv != target_version:
                    old_vers_counter[iv] = old_vers_counter.get(iv, 0) + 1
        current_installed_version = max(all_vers_counter, key=all_vers_counter.get) if all_vers_counter else None
        installed_version = max(old_vers_counter, key=old_vers_counter.get) if old_vers_counter else None

        # Hat mindestens ein Agent (ungeblocked) das Update noch nicht?
        has_updates = any(
            split[phase]["on_old"] > 0 for phase in (1, 2, 3)
        )

        # Status bestimmen
        active_phase = active_rollouts.get(name)
        last = latest_rollouts.get(name)
        active_rollout = active_rollout_rows.get(name)
        if active_phase is not None:
            status = "running"
        elif has_updates:
            status = "ready"      # Updates verfuegbar, kein aktiver Rollout
        elif last and last["status"] == "done":
            status = "done"       # Zuletzt erfolgreich ausgerollt, keine neuen Updates
        else:
            status = "idle"       # Staged-Flag gesetzt aber keine Updates, nie ausgerollt

        # Phase-Status pro Phase ableiten
        def _phase_status(phase: int) -> str:
            if active_phase is None:
                return "pending"
            if phase < active_phase:
                return "done"
            if phase == active_phase:
                return "active"
            return "pending"

        phases_out = []
        for phase in (1, 2, 3):
            s = split[phase]
            phases_out.append({
                "phase":     phase,
                "label":     labels[phase],
                "total":     s["total"],
                "on_target": s["on_target"],
                "on_old":    s["on_old"],
                "missing":   s["missing"],
                "status":    _phase_status(phase),
            })

        out.append({
            "name":                      name,
            "display_name":              pkg.get("display_name") or name,
            "type":                      ptype,
            "winget_publisher":          pkg.get("winget_publisher"),
            "auto_advance":              bool(pkg.get("auto_advance")),
            "status":                    status,
            "target_version":            target_version,
            "installed_version":         installed_version,
            "current_installed_version": current_installed_version,
            "phases":                    phases_out,
            "active_rollout":            active_rollout,
            "last_rollout":              last,
            "error_count":               error_counts.get(name, 0),
        })

    # Sort: running first, then ready (updates avail), dann done, dann idle
    status_order = {"running": 0, "ready": 1, "done": 2, "idle": 3}
    out.sort(key=lambda p: (status_order.get(p["status"], 4),
                            -(p.get("error_count") or 0),
                            p["display_name"].lower()))

    return {"packages": out, "ring_labels": labels}


@router.get("/admin/api/rollouts/ring-overview", dependencies=[Depends(_require_admin)])
async def get_ring_overview_endpoint():
    """Pro Ring: Agents-Liste + Labels aus Settings."""
    labels = {
        1: (await runtime_value("rollout_ring1_label")) or "Canary",
        2: (await runtime_value("rollout_ring2_label")) or "Pilot",
        3: (await runtime_value("rollout_ring3_label")) or "Produktion",
    }
    rings = await database.get_ring_overview()
    for r in rings:
        r["label"] = labels.get(r["ring"], f"Ring {r['ring']}")
        r["is_prod"] = (r["ring"] == 3)
    return {"rings": rings, "labels": labels}


@router.get("/admin/api/rollouts/settings", dependencies=[Depends(_require_admin)])
async def get_rollout_settings():
    """Rollout-Policy + Ring-Labels als Key-Value-Map."""
    keys = (
        "rollout_ring1_label", "rollout_ring2_label", "rollout_ring3_label",
        "rollout_default_staged",
        "rollout_auto_advance_enabled",
        "rollout_auto_advance_hours_1_to_2",
        "rollout_auto_advance_hours_2_to_3",
        "rollout_max_error_pct",
    )
    out = {}
    for k in keys:
        out[k] = await runtime_value(k) or (RUNTIME_KEYS.get(k, {}).get("default") or "")
    return out


class BulkDistBody(BaseModel):
    package_names: list[str] = Field(min_length=1, max_length=500)
    action: str  # "push_update" | "uninstall_all"
    stage: str = "all"

    @field_validator("action")
    @classmethod
    def _check_action(cls, v: str) -> str:
        if v not in ("push_update", "uninstall_all"):
            raise ValueError("action muss push_update oder uninstall_all sein")
        return v

    @field_validator("stage")
    @classmethod
    def _check_stage_v(cls, v: str) -> str:
        if v not in _VALID_STAGES:
            raise ValueError(f"stage ungueltig. Erlaubt: {sorted(_VALID_STAGES)}")
        return v


@router.post("/admin/api/distributions/bulk", dependencies=[Depends(_require_admin)])
async def bulk_distribution_action(body: BulkDistBody):
    """Bulk-Action ueber mehrere Pakete in einem Rutsch.

    action='push_update': fuer jedes Paket ein push-update (Update auf allen
    outdated Agents) — nutzt den bestehenden pro-Paket push-update Pfad.

    action='uninstall_all': deinstalliert das Paket auf allen Agents die
    es installiert haben. Hart, nur mit Confirm-Modal im UI.

    Returns: {per_package: [{name, dispatched, outdated, failed}]}
    """
    from routes.install import dispatch_upgrade_for_agent, dispatch_uninstall_for_agent

    per_package: list[dict] = []
    total_dispatched = 0

    allowed_agents = {a["agent_id"] for a in
                      await database.get_agents_by_ring(_stage_to_ring_filter(body.stage))}

    for name in body.package_names:
        pkg = await database.get_package(name)
        if not pkg:
            per_package.append({"name": name, "error": "Paket nicht gefunden"})
            continue
        try:
            _enforce_staged_guard(pkg, body.stage)
        except HTTPException as e:
            per_package.append({"name": name, "error": e.detail})
            continue
        ptype = pkg.get("type") or "choco"

        # Agents sammeln je nach Typ
        if ptype == "winget":
            raw = await database.get_agents_with_winget_package(name)
        elif ptype == "choco":
            raw = await database.get_agents_with_choco_package(name)
        else:
            raw = await database.get_installations_for_package(name)

        if body.action == "push_update":
            # Nur outdated Agents
            if ptype == "custom":
                affected = [a for a in raw if a.get("outdated")]
            else:
                affected = [a for a in raw if a.get("available_version")]
        else:  # uninstall_all
            affected = raw

        # Ring-Filter anwenden
        affected = [a for a in affected if a["agent_id"] in allowed_agents]

        dispatched = 0
        failed: list[str] = []
        for ag in affected:
            try:
                if body.action == "push_update":
                    await dispatch_upgrade_for_agent(
                        ag["agent_id"], ag.get("hostname") or "", pkg,
                    )
                else:
                    await dispatch_uninstall_for_agent(
                        ag["agent_id"], ag.get("hostname") or "", pkg,
                    )
                dispatched += 1
            except Exception as e:
                failed.append(f"{ag.get('hostname')}: {e}")

        total_dispatched += dispatched
        per_package.append({
            "name":       name,
            "dispatched": dispatched,
            "total":      len(affected),
            "failed":     failed,
        })

    return {
        "ok":               True,
        "total_dispatched": total_dispatched,
        "per_package":      per_package,
    }


# ── Agents ────────────────────────────────────────────────────────────────────

class PackageRequiredBody(BaseModel):
    required: bool


class PackageNotesBody(BaseModel):
    notes: str = Field(default="", max_length=2000)


class PackageStagedBody(BaseModel):
    staged: bool


class PackageHiddenBody(BaseModel):
    hidden: bool


class PackageAutoAdvanceBody(BaseModel):
    auto: bool


class AgentRingBody(BaseModel):
    ring: int = Field(ge=1, le=3)  # 1=Canary, 2=Pilot, 3=Produktion


# Gueltige stage-Strings fuer Dispatch-Endpoints.
# - "all":   ohne Ring-Filter (Standard, unstaged)
# - "ring1": nur Ring 1 (Canary — kleinste Testgruppe)
# - "ring2": nur Ring 2 (Pilot)
# - "ring3": nur Ring 3
# - "rings": alle Test-Ringe zusammen (ring > 0)
# - "prod":  nur Produktions-Agents (ring = 0, nach Test-Phase)
_VALID_STAGES = {"all", "ring1", "ring2", "ring3", "rings", "prod"}


def _check_stage(stage: str) -> str:
    if stage not in _VALID_STAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Ungueltige stage '{stage}'. Erlaubt: {sorted(_VALID_STAGES)}",
        )
    return stage


def _stage_to_ring_filter(stage: str) -> str | int:
    """Konvertiert stage-String zu get_agents_by_ring-Param."""
    if stage in ("all", "rings", "prod"):
        return stage
    # ring1..ring9 → int
    return int(stage.replace("ring", ""))


def _enforce_staged_guard(pkg: dict, stage: str):
    """Wenn Paket staged_rollout=1 hat, darf stage nicht 'all' sein.
    Admin muss explizit Phase waehlen damit nichts ausversehen fleet-wide geht."""
    if pkg.get("staged_rollout") and stage == "all":
        raise HTTPException(
            status_code=400,
            detail=(
                f"Paket '{pkg.get('name')}' ist staged — stage muss explizit "
                f"ring1/ring2/ring3/rings/prod sein. Starte mit ring1 (Canary)."
            ),
        )


@router.patch("/admin/api/packages/{name}/required", dependencies=[Depends(_require_admin)])
async def set_package_required(name: str, body: PackageRequiredBody):
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    await database.update_package_required(name, body.required)
    return {"ok": True, "required": body.required}


@router.patch("/admin/api/packages/{name}/staged", dependencies=[Depends(_require_admin)])
async def set_package_staged(name: str, body: PackageStagedBody):
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    await database.update_package_staged(name, body.staged)
    return {"ok": True, "staged": body.staged}


@router.patch("/admin/api/packages/{name}/hidden", dependencies=[Depends(_require_admin)])
async def set_package_hidden(name: str, body: PackageHiddenBody):
    """Pro Paket: im Kiosk-Client ausblenden (bleibt aber sichtbar sobald
    installiert, damit User es updaten/deinstallieren kann).
    Use-case: Admin-only Remote-Deploy-Software ohne Self-Service-Sicht."""
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    await database.update_package_hidden(name, body.hidden)
    return {"ok": True, "hidden": body.hidden}


@router.patch("/admin/api/packages/{name}/auto-advance", dependencies=[Depends(_require_admin)])
async def set_package_auto_advance(name: str, body: PackageAutoAdvanceBody):
    """Per-Paket Auto-Advance-Toggle fuer phased Rollouts. Nur Rollouts von
    Paketen mit auto_advance=1 werden vom APScheduler-Tick automatisch
    weitergeschaltet. Defaults off — explizites opt-in pro Paket."""
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    await database.update_package_auto_advance(name, body.auto)
    return {"ok": True, "auto_advance": body.auto}


@router.patch("/admin/api/agents/{agent_id}/ring", dependencies=[Depends(_require_admin)])
async def set_agent_ring_endpoint(agent_id: str, body: AgentRingBody):
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungueltige Agent-ID")
    agents = await database.get_agents()
    if not any(a["agent_id"] == agent_id for a in agents):
        raise HTTPException(status_code=404, detail="Agent nicht gefunden")
    await database.set_agent_ring(agent_id, body.ring)
    return {"ok": True, "ring": body.ring}


@router.patch("/admin/api/packages/{name}/notes", dependencies=[Depends(_require_admin)])
async def set_package_notes(name: str, body: PackageNotesBody):
    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    await database.update_package_notes(name, body.notes)
    return {"ok": True}


class WingetVersionPinBody(BaseModel):
    version: str = Field(default="", max_length=50)

    @field_validator("version")
    @classmethod
    def _check_v(cls, v: str) -> str:
        if v and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._\-+]{0,49}", v):
            raise ValueError("Ungueltige Version")
        return v


@router.patch("/admin/api/winget/{name}/version-pin", dependencies=[Depends(_require_admin)])
async def set_winget_version_pin(name: str, body: WingetVersionPinBody):
    if not _WINGET_ID_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungueltige winget-ID")
    pkg = await database.get_package(name)
    if not pkg or pkg.get("type") != "winget":
        raise HTTPException(status_code=404, detail="winget-Paket nicht gefunden")
    # Use update_winget_package to set winget_version
    await database.update_winget_package(
        name=name,
        display_name=pkg["display_name"],
        category=pkg["category"],
        winget_version=body.version or None,
    )
    return {"ok": True, "version": body.version or None}


@router.get("/admin/api/compliance", dependencies=[Depends(_require_admin)])
async def get_compliance():
    """Compliance-Uebersicht: fuer jedes required-Paket welche Agents es haben,
    welche fehlen. Nutzt Tactical Software-Scan als primaere Quelle fuer
    Custom/Choco-Pakete statt nur interne Tracking-Tabellen."""
    overview = await database.get_compliance_overview()

    # Enrichment: fuer Pakete die auf detection_name matchen, den Tactical
    # Software-Scan pro Agent pruefen. Damit werden auch manuell/extern
    # installierte Pakete korrekt als "installiert" erkannt.
    required_with_detection = [
        p for p in overview["required_packages"]
        if p.get("missing") and p.get("type") in ("custom", "choco")
    ]
    if required_with_detection:
        # Pro Agent einmal Tactical-Scan holen (gecached fuer alle Pakete)
        all_agents = await database.get_agents()
        tactical = TacticalClient()
        agent_software_cache: dict[str, list[str]] = {}
        for a in all_agents:
            aid = a["agent_id"]
            try:
                sw = await tactical.get_installed_software(aid)
                # DisplayNames normalisiert cachen
                agent_software_cache[aid] = [
                    (s.get("name") or "").lower() for s in sw
                ]
            except Exception:
                agent_software_cache[aid] = []

        # Pakete mit detection_name gegen Tactical-Scan matchen
        for p in required_with_detection:
            pkg = await database.get_package(p["name"])
            if not pkg:
                continue
            det = (pkg.get("detection_name") or "").lower()
            choco_name = (pkg.get("name") or "").lower() if p["type"] == "choco" else ""
            if not det and not choco_name:
                continue
            still_missing = []
            for miss in p["missing"]:
                aid = miss["agent_id"]
                sw_names = agent_software_cache.get(aid, [])
                # Substring-Match wie in routes/packages.py
                found = any(
                    (det and det in name) or (choco_name and choco_name in name)
                    for name in sw_names
                )
                if not found:
                    still_missing.append(miss)
            removed = len(p["missing"]) - len(still_missing)
            if removed:
                p["missing"] = still_missing
                p["installed_count"] = p["total_agents"] - len(still_missing)

        # Summary neu berechnen
        all_agent_ids = {a["agent_id"] for a in all_agents}
        noncompliant_ids = set()
        for p in overview["required_packages"]:
            for m in p.get("missing", []):
                noncompliant_ids.add(m["agent_id"])
        overview["noncompliant_agents"] = len(noncompliant_ids)
        overview["fully_compliant_agents"] = len(all_agent_ids) - len(noncompliant_ids)

    return overview


@router.post("/admin/api/compliance/fix", dependencies=[Depends(_require_admin)])
async def fix_compliance(stage: str = "all"):
    """Auf allen nicht-compliant Agents die fehlenden required-Pakete nachinstallieren.
    Dispatched ueber shared install-pfad pro Agent+Paket.

    `stage` filtert Agents nach Ring. Staged-Pakete muessen explizit
    Ring haben — sonst wird das Paket uebersprungen und der Skip gemeldet."""
    from routes.install import dispatch_install_for_agent
    _check_stage(stage)
    allowed_agents = {a["agent_id"] for a in
                      await database.get_agents_by_ring(_stage_to_ring_filter(stage))}

    overview = await database.get_compliance_overview()
    dispatched = 0
    failed: list[str] = []
    skipped_staged: list[str] = []
    for p in overview["required_packages"]:
        pkg = await database.get_package(p["name"])
        if not pkg:
            continue
        if pkg.get("staged_rollout") and stage == "all":
            skipped_staged.append(p["name"])
            continue
        for miss in p["missing"]:
            if miss["agent_id"] not in allowed_agents:
                continue
            try:
                await dispatch_install_for_agent(
                    miss["agent_id"], miss.get("hostname") or "", pkg,
                )
                dispatched += 1
            except Exception as e:
                failed.append(f"{miss.get('hostname')}/{p['name']}: {e}")
    return {
        "ok":             True,
        "dispatched":     dispatched,
        "failed":         failed,
        "skipped_staged": skipped_staged,
    }


@router.get("/admin/api/dashboard", dependencies=[Depends(_require_admin)])
async def get_dashboard():
    """Aggregierte Fleet-KPIs + neueste Events fuer die Home-Sicht.
    Eine Request um alles rendern zu koennen — kein N+1 im Frontend."""
    stats = await database.get_fleet_stats()
    errors = await database.get_fleet_errors(limit=10)
    recent_installs = await database.get_recent_installs(limit=15)
    top_outdated = await database.get_top_outdated_packages(limit=8)
    return {
        "stats":           stats,
        "errors":          errors,
        "recent_installs": recent_installs,
        "top_outdated":    top_outdated,
    }


@router.get("/admin/api/fleet-errors", dependencies=[Depends(_require_admin)])
async def get_fleet_errors_endpoint(limit: int = 200, include_acked: bool = False):
    """Liste ALLER aktiven Install-Fehler flottenweit. Fuer den Fehler-Tab.
    Default: nur un-acked. `include_acked=1` zeigt auch bestaetigte."""
    limit = max(1, min(limit, 1000))
    errors = await database.get_fleet_errors(limit=limit, include_acked=include_acked)
    return {"errors": errors, "total": len(errors)}


@router.post("/admin/api/agents/{agent_id}/ack-error",
             dependencies=[Depends(_require_admin)])
async def ack_agent_error_endpoint(agent_id: str):
    """Markiert den letzten Fehler eines Agents als bestaetigt.
    Fehlermeldung + voller Output bleiben zur Einsicht erhalten."""
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungueltige Agent-ID")
    await database.ack_agent_error(agent_id)
    return {"ok": True}


@router.post("/admin/api/fleet-errors/ack-all",
             dependencies=[Depends(_require_admin)])
async def ack_all_errors_endpoint():
    """Bulk-Ack aller offenen Fehler."""
    count = await database.ack_all_errors()
    return {"ok": True, "acked": count}


class BulkWingetImportBody(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=500)
    category: str = Field(default="Allgemein", min_length=1, max_length=40)

    @field_validator("ids", mode="before")
    @classmethod
    def _normalize_ids(cls, v):
        if isinstance(v, str):
            # Textarea: whitespace- oder komma-getrennt
            parts = [line.strip() for line in v.replace(",", "\n").split("\n")]
            return [p for p in parts if p]
        return v

    @field_validator("category")
    @classmethod
    def _check_cat(cls, v: str) -> str:
        if not _TEXT_RE.fullmatch(v):
            raise ValueError("Kategorie enthaelt ungueltige Zeichen")
        return v


@router.post("/admin/api/winget/bulk-activate", dependencies=[Depends(_require_admin)])
async def bulk_activate_winget(body: BulkWingetImportBody):
    """Mehrere winget-IDs in einem Rutsch zur Whitelist. Metadaten werden
    pro ID aus dem lokalen Catalog geholt (display_name, publisher, version).

    Skip-Logik: IDs die schon in der Whitelist sind werden uebersprungen,
    ungueltig formatierte IDs landen in `errors`. Gibt alle drei Listen
    zurueck damit das UI sagen kann „30 hinzugefuegt, 5 skipped, 2 ungueltig".
    """
    added: list[str] = []
    skipped: list[str] = []
    errors: list[dict] = []

    existing = {p["name"] for p in await database.get_packages()}
    default_staged = (
        (await runtime_value("rollout_default_staged")) or "false"
    ).lower() in ("true", "1", "yes", "on")

    for raw in body.ids:
        wid = raw.strip()
        if not _WINGET_ID_RE.fullmatch(wid):
            errors.append({"id": raw, "error": "Ungueltige winget-ID"})
            continue
        if wid in existing:
            skipped.append(wid)
            continue
        try:
            details = await winget_catalog.get_details(wid)
        except Exception:
            details = None
        display_name = (details or {}).get("name") or wid
        publisher    = (details or {}).get("publisher")
        try:
            await database.upsert_winget_package(
                name=wid,
                display_name=display_name,
                category=body.category,
                publisher=publisher,
                winget_version=None,
                winget_scope="auto",
            )
            if default_staged:
                await database.update_package_staged(wid, True)
            added.append(wid)
            existing.add(wid)
        except Exception as e:
            errors.append({"id": wid, "error": str(e)[:200]})

    return {
        "ok":      True,
        "added":   added,
        "skipped": skipped,
        "errors":  errors,
        "totals":  {"added": len(added), "skipped": len(skipped), "errors": len(errors)},
    }


@router.get("/admin/api/agents", dependencies=[Depends(_require_admin)])
async def get_agents():
    return await database.get_agents()


@router.get("/admin/api/agents/{agent_id}/last-action-output",
            dependencies=[Depends(_require_admin)])
async def get_agent_last_action_output(agent_id: str):
    """Voller stdout-Tail der letzten Aktion auf einem Agent — fuer das
    Fehler-Detail-Modal im Admin-UI."""
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungueltige Agent-ID")
    data = await database.get_last_action_output(agent_id)
    if not data:
        raise HTTPException(status_code=404, detail="Keine Aktions-Daten")
    return data


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
async def get_distributions(
    q: str = "",
    type: str = "all",
    outdated_only: bool = False,
    sort: str = "outdated_desc",
    offset: int = 0,
    limit: int = 100,
):
    """
    Paginierte Paket-Uebersicht ueber alle drei Typen (winget/choco/custom).

    Scale-Design: bei 2000+ Paketen wird NICHT mehr alles client-side
    geladen. Das Frontend schickt Filter/Sort/Pagination als Query-Params
    und bekommt summary-only Zeilen zurueck. Agent-Details fuer ein
    einzelnes Paket werden separat via `/admin/api/packages/{name}/agents`
    lazy-geladen wenn der Admin auf eine Zeile klickt.

    Query-Params:
      q             - Substring-Filter auf name + display_name
      type          - 'all' | 'winget' | 'choco' | 'custom'
      outdated_only - True → nur Pakete mit outdated > 0
      sort          - 'outdated_desc' (default) | 'name_asc' | 'devices_desc'
      offset/limit  - Pagination (limit max 500 — clamp)

    Response: {items: [...], total: N, offset, limit} — total ist die
    Gesamtzahl nach Filter (ohne Pagination), das Frontend braucht's fuer
    Infinite-Scroll / „X von Y Pakete".
    """
    if type not in ("all", "winget", "choco", "custom"):
        raise HTTPException(status_code=400, detail="Ungueltiger type-Filter")
    if sort not in ("outdated_desc", "name_asc", "devices_desc"):
        raise HTTPException(status_code=400, detail="Ungueltiger sort-Parameter")
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    needle = (q or "").strip().lower()

    packages = await database.get_packages()

    # Vorfilter by type + query
    if type != "all":
        packages = [p for p in packages if (p.get("type") or "choco") == type]
    if needle:
        packages = [
            p for p in packages
            if needle in (p.get("name") or "").lower()
            or needle in (p.get("display_name") or "").lower()
        ]

    # Summary-Zaehler holen (pro Paket ein leichter DB-Call, aber kein
    # Tactical-Round-Trip — nur agent_*_state Tabellen).
    items = []
    for pkg in packages:
        ptype = pkg.get("type") or "choco"
        total = current = outdated = unknown = 0
        current_label = None

        if ptype == "custom":
            summary = await database.get_agent_installation_summary(pkg["name"])
            total    = summary.get("total", 0)
            current  = summary.get("current", 0)
            outdated = summary.get("outdated", 0)
            unknown  = summary.get("unknown", 0)
            if pkg.get("current_version_id"):
                cv = await database.get_package_version(pkg["current_version_id"])
                if cv:
                    current_label = cv.get("version_label")
        elif ptype == "winget":
            raw = await database.get_agents_with_winget_package(pkg["name"])
            total = len(raw)
            for r in raw:
                iv = r.get("installed_version"); av = r.get("available_version")
                if not iv: unknown += 1
                elif av:   outdated += 1
                else:      current += 1
            current_label = pkg.get("winget_version") or "latest"
        else:  # choco
            raw = await database.get_agents_with_choco_package(pkg["name"])
            total = len(raw)
            for r in raw:
                iv = r.get("installed_version"); av = r.get("available_version")
                if not iv: unknown += 1
                elif av:   outdated += 1
                else:      current += 1
            current_label = "latest"

        if outdated_only and outdated == 0:
            continue

        items.append({
            "name":                  pkg["name"],
            "display_name":          pkg["display_name"],
            "category":              pkg.get("category"),
            "type":                  ptype,
            "current_version_label": current_label,
            "filename":              pkg.get("filename"),
            "size_bytes":            pkg.get("size_bytes"),
            "winget_publisher":      pkg.get("winget_publisher"),
            "winget_scope":          pkg.get("winget_scope") or "auto" if ptype == "winget" else None,
            "has_uninstall":         bool(pkg.get("uninstall_cmd")) if ptype == "custom" else True,
            "summary": {
                "total":    total,
                "current":  current,
                "outdated": outdated,
                "unknown":  unknown,
            },
        })

    # Sort
    if sort == "outdated_desc":
        items.sort(key=lambda x: (
            -(x["summary"]["outdated"]),
            -(x["summary"]["total"]),
            (x.get("display_name") or "").lower(),
        ))
    elif sort == "devices_desc":
        items.sort(key=lambda x: (
            -(x["summary"]["total"]),
            (x.get("display_name") or "").lower(),
        ))
    else:  # name_asc
        items.sort(key=lambda x: (x.get("display_name") or "").lower())

    total_matching = len(items)
    page = items[offset:offset + limit]

    return {
        "items":  page,
        "total":  total_matching,
        "offset": offset,
        "limit":  limit,
    }


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
    Pakets auf einem einzelnen Agent. Dispatch nach packages.type — die ganze
    Logik sitzt im shared `dispatch_install_for_agent` Helper damit Profile-
    Apply und Bulk-Install denselben Pfad benutzen koennen."""
    from routes.install import dispatch_install_for_agent

    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungültige Agent-ID")
    pkg = await database.get_package(package_name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")

    agent = await _resolve_agent(agent_id)
    result = await dispatch_install_for_agent(agent_id, agent["hostname"], pkg)
    return {"ok": True, "agent": agent["hostname"], **result}


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


# ── Profiles + Bulk-Install + Update-All ──────────────────────────────────────

_PROFILE_NAME_RE = re.compile(r"^[\w][\w \-]{0,59}$", re.UNICODE)


class ProfilePackageEntry(BaseModel):
    package_name: str = Field(min_length=1, max_length=200)
    version_pin: Optional[str] = Field(default=None, max_length=50)
    sort_order: int = Field(default=0, ge=0, le=9999)

    @field_validator("package_name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        # winget-IDs (Mozilla.Firefox) und choco-Namen (vscode) muessen beide
        # passen — wir benutzen denselben loose Pattern.
        if not _WINGET_ID_RE.fullmatch(v):
            raise ValueError("Ungueltiger Paketname")
        return v

    @field_validator("version_pin")
    @classmethod
    def _check_pin(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        if not _NO_CTRL_RE.fullmatch(v):
            raise ValueError("Version-Pin enthaelt Steuerzeichen")
        return v


class ProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    description: str = Field(default="", max_length=400)
    color: Optional[str] = Field(default=None, max_length=20)
    auto_update: bool = False
    packages: list[ProfilePackageEntry] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        v = v.strip()
        if not _PROFILE_NAME_RE.fullmatch(v):
            raise ValueError("Profil-Name max 60 Zeichen, nur Buchstaben/Ziffern/Leerzeichen/-/_")
        return v

    @field_validator("description")
    @classmethod
    def _check_desc(cls, v: str) -> str:
        if v and not _NO_CTRL_RE.fullmatch(v):
            raise ValueError("Beschreibung enthaelt Steuerzeichen")
        return v


class ProfileUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=60)
    description: Optional[str] = Field(default=None, max_length=400)
    color: Optional[str] = Field(default=None, max_length=20)
    auto_update: Optional[bool] = None
    packages: Optional[list[ProfilePackageEntry]] = None

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not _PROFILE_NAME_RE.fullmatch(v):
            raise ValueError("Profil-Name max 60 Zeichen, nur Buchstaben/Ziffern/Leerzeichen/-/_")
        return v


class ProfileApplyBody(BaseModel):
    agent_ids: list[str] = Field(min_length=1, max_length=500)

    @field_validator("agent_ids")
    @classmethod
    def _check_ids(cls, v: list[str]) -> list[str]:
        for aid in v:
            if not _AGENT_ID_RE.fullmatch(aid):
                raise ValueError(f"Ungueltige Agent-ID: {aid!r}")
        return v


class ProfileUnassignBody(BaseModel):
    agent_ids: list[str] = Field(min_length=1, max_length=500)
    uninstall_packages: bool = False

    @field_validator("agent_ids")
    @classmethod
    def _check_ids(cls, v: list[str]) -> list[str]:
        for aid in v:
            if not _AGENT_ID_RE.fullmatch(aid):
                raise ValueError(f"Ungueltige Agent-ID: {aid!r}")
        return v


class BulkInstallBody(BaseModel):
    package_names: list[str] = Field(min_length=1, max_length=200)

    @field_validator("package_names")
    @classmethod
    def _check_names(cls, v: list[str]) -> list[str]:
        for n in v:
            if not _WINGET_ID_RE.fullmatch(n):
                raise ValueError(f"Ungueltiger Paketname: {n!r}")
        return v


async def _validate_profile_packages_exist(packages: list[ProfilePackageEntry]) -> list[dict]:
    """Verifiziert dass jedes Paket schon whitelistet ist und gibt die DB-Rows zurueck."""
    resolved = []
    for entry in packages:
        pkg = await database.get_package(entry.package_name)
        if not pkg:
            raise HTTPException(
                status_code=400,
                detail=f"Paket {entry.package_name!r} ist nicht in der Whitelist. "
                       f"Erst aktivieren, dann ins Profil aufnehmen.",
            )
        resolved.append(pkg)
    return resolved


async def _agent_state_snapshot(agent_id: str) -> tuple[dict, dict, set[str], list[str]]:
    """Cacht winget+choco-State + tracked-installations + Tactical Software-
    Scan fuer einen Agent.

    Returns:
      (winget_state, choco_state, tracked_set, tactical_sw_names_lower)

    tactical_sw_names_lower enthaelt die lowercased DisplayNames aus dem
    Tactical Software-Scan — damit koennen Custom/Choco-Pakete auch dann
    als installiert erkannt werden wenn sie nicht ueber Softshelf deployed
    wurden (z.B. manuell oder per GPO installiert).
    """
    winget_state = await database.get_agent_winget_state(agent_id)
    choco_state = await database.get_agent_choco_state(agent_id)
    tracked = {t["package_name"] for t in await database.get_agent_installations(agent_id)}

    # Tactical Software-Scan (best-effort, timeout-tolerant)
    tactical_names: list[str] = []
    try:
        tactical = TacticalClient()
        sw = await tactical.get_installed_software(agent_id)
        tactical_names = [(s.get("name") or "").lower() for s in sw]
    except Exception:
        pass

    return winget_state, choco_state, tracked, tactical_names


def _is_package_satisfied(
    pkg: dict,
    version_pin: str | None,
    winget_state: dict,
    choco_state: dict,
    tracked: set[str],
    tactical_sw_names: list[str] | None = None,
) -> bool:
    """True wenn das Paket bereits in der gewuenschten Form auf dem Agent
    installiert ist und der Profile-Apply nichts dispatchen muss.

    Logik:
      - version_pin gesetzt: nur skip wenn installed_version == pin
      - winget/choco im scan-state mit installed_version: skip
      - in agent_installations (tracked): skip
      - detection_name matched im Tactical Software-Scan: skip
      - sonst: False (= dispatch)
    """
    name = pkg["name"]
    ptype = pkg.get("type") or "choco"

    if ptype == "winget":
        st = winget_state.get(name)
        if st:
            inst = (st.get("installed_version") or "").strip()
            avail = (st.get("available_version") or "").strip()
            if version_pin:
                return inst == version_pin
            if inst and (not avail or inst == avail):
                return True
            return False
        if name in tracked:
            return True

    elif ptype == "choco":
        st = choco_state.get(name)
        if st:
            inst = (st.get("installed_version") or "").strip()
            avail = (st.get("available_version") or "").strip()
            if version_pin:
                return inst == version_pin
            if inst and (not avail or inst == avail):
                return True
            return False
        if name in tracked:
            return True

    else:  # custom
        if name in tracked:
            return True

    # Fallback: detection_name gegen Tactical Software-Scan matchen
    if tactical_sw_names and not version_pin:
        det = (pkg.get("detection_name") or "").lower()
        if det and any(det in n for n in tactical_sw_names):
            return True
        # Choco: Paketname als Substring im DisplayName
        if ptype == "choco" and any(name.lower() in n for n in tactical_sw_names):
            return True

    return False


@router.get("/admin/api/profiles", dependencies=[Depends(_require_admin)])
async def list_profiles_endpoint():
    return {"profiles": await database.list_profiles()}


@router.get("/admin/api/profiles/{profile_id}", dependencies=[Depends(_require_admin)])
async def get_profile_endpoint(profile_id: int):
    profile = await database.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profil nicht gefunden")
    profile["agents"] = await database.get_agents_for_profile(profile_id)
    return profile


@router.post("/admin/api/profiles", dependencies=[Depends(_require_admin)])
async def create_profile_endpoint(body: ProfileCreate, request: Request):
    if await database.get_profile_by_name(body.name):
        raise HTTPException(status_code=409, detail=f"Profil {body.name!r} existiert bereits")
    await _validate_profile_packages_exist(body.packages)
    try:
        profile_id = await database.create_profile(
            body.name, body.description, body.color, auto_update=body.auto_update,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Profil konnte nicht angelegt werden: {e}")
    if body.packages:
        await database.set_profile_packages(
            profile_id,
            [p.model_dump() for p in body.packages],
        )
    user = await _require_admin(request)
    await database.log_audit_event(
        "profile_created",
        actor=user.get("username"),
        details={"profile_id": profile_id, "name": body.name,
                 "package_count": len(body.packages)},
    )
    return {"ok": True, "profile_id": profile_id}


@router.patch("/admin/api/profiles/{profile_id}", dependencies=[Depends(_require_admin)])
async def update_profile_endpoint(profile_id: int, body: ProfileUpdate, request: Request):
    """Updated Profil-Meta und/oder Pakete. Bei Paket-Aenderung: Auto-Propagation
    an alle bereits assignete Agents fuer NEU hinzugefuegte Pakete."""
    profile = await database.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profil nicht gefunden")

    if body.name is not None and body.name.lower() != profile["name"].lower():
        clash = await database.get_profile_by_name(body.name)
        if clash and clash["id"] != profile_id:
            raise HTTPException(status_code=409, detail=f"Profil {body.name!r} existiert bereits")

    await database.update_profile_meta(
        profile_id, name=body.name, description=body.description, color=body.color,
        auto_update=body.auto_update,
    )

    added: set[str] = set()
    if body.packages is not None:
        await _validate_profile_packages_exist(body.packages)
        added, _removed = await database.set_profile_packages(
            profile_id, [p.model_dump() for p in body.packages],
        )

    user = await _require_admin(request)
    await database.log_audit_event(
        "profile_updated",
        actor=user.get("username"),
        details={"profile_id": profile_id, "added": sorted(added)},
    )

    # Auto-Propagation: neu hinzugefuegte Pakete sofort auf alle assigned
    # Agents installieren — mit Smart-Skip wenn das Paket dort schon im
    # gewuenschten State steht.
    propagated = 0
    skipped_existing = 0
    if added:
        from routes.install import dispatch_install_for_agent
        agents = await database.get_agents_for_profile(profile_id)
        # Aktuelle Profile-Pakete mit ihren version_pins fuer Lookup
        profile_now = await database.get_profile(profile_id)
        pin_by_name = {pp["package_name"]: pp.get("version_pin")
                       for pp in profile_now["packages"]}
        for ag in agents:
            wstate, cstate, tracked, tsw = await _agent_state_snapshot(ag["agent_id"])
            for pkg_name in added:
                pkg = await database.get_package(pkg_name)
                if not pkg:
                    continue
                pin = pin_by_name.get(pkg_name)
                if _is_package_satisfied(pkg, pin, wstate, cstate, tracked, tsw):
                    skipped_existing += 1
                    continue
                try:
                    await dispatch_install_for_agent(
                        ag["agent_id"], ag["hostname"], pkg, version_pin=pin,
                    )
                    propagated += 1
                except HTTPException as e:
                    logger.warning(
                        "Auto-propagation failed for agent=%s pkg=%s: %s",
                        ag["agent_id"], pkg_name, e.detail,
                    )
        if propagated or skipped_existing:
            await database.log_audit_event(
                "profile_propagated",
                actor=user.get("username"),
                details={"profile_id": profile_id,
                         "added_packages": sorted(added),
                         "agents_affected": len(agents),
                         "dispatches": propagated,
                         "skipped_already_installed": skipped_existing},
            )

    return {
        "ok": True,
        "propagated_dispatches": propagated,
        "skipped_already_installed": skipped_existing,
    }


async def _run_profile_autoupdate(profile_id: int, actor: str = "scheduler") -> dict:
    """Iteriert ein Profil + alle assigned Agents und dispatched Updates fuer
    Pakete die outdated sind. Smart-Skip via _is_package_satisfied damit
    bereits-aktuelle Pakete kein Tactical-Round-Trip kosten.

    Returns Stats-Dict; auch im Audit-Log gelogged.
    """
    from routes.install import dispatch_install_for_agent

    profile = await database.get_profile(profile_id)
    if not profile or not profile.get("auto_update"):
        return {"profile_id": profile_id, "skipped_reason": "not auto_update"}
    packages = profile.get("packages") or []
    if not packages:
        await database.mark_profile_auto_update_run(profile_id)
        return {"profile_id": profile_id, "skipped_reason": "no packages"}

    agents = await database.get_agents_for_profile(profile_id)
    if not agents:
        await database.mark_profile_auto_update_run(profile_id)
        return {"profile_id": profile_id, "skipped_reason": "no assigned agents"}

    queued = 0
    skipped = 0
    failed = 0
    for ag in agents:
        wstate, cstate, tracked, tsw = await _agent_state_snapshot(ag["agent_id"])
        for pp in packages:
            pkg = await database.get_package(pp["package_name"])
            if not pkg:
                continue
            pin = pp.get("version_pin")
            if _is_package_satisfied(pkg, pin, wstate, cstate, tracked, tsw):
                skipped += 1
                continue
            try:
                await dispatch_install_for_agent(
                    ag["agent_id"], ag["hostname"], pkg, version_pin=pin,
                )
                queued += 1
            except HTTPException as e:
                failed += 1
                logger.warning(
                    "auto-update dispatch failed agent=%s pkg=%s: %s",
                    ag["agent_id"], pp["package_name"], e.detail,
                )

    await database.mark_profile_auto_update_run(profile_id)
    await database.log_audit_event(
        "profile_autoupdate_run",
        actor=actor,
        details={
            "profile_id": profile_id,
            "name": profile["name"],
            "agents": len(agents),
            "packages": len(packages),
            "queued": queued,
            "skipped_already_current": skipped,
            "failed": failed,
        },
    )
    logger.info(
        "Profile auto-update %s: agents=%d queued=%d skipped=%d failed=%d",
        profile["name"], len(agents), queued, skipped, failed,
    )
    return {
        "profile_id": profile_id,
        "agents": len(agents),
        "queued": queued,
        "skipped_already_current": skipped,
        "failed": failed,
    }


async def run_all_profile_autoupdates() -> dict:
    """Iteriert alle auto_update=1 Profile. Wird vom APScheduler nightly + vom
    Admin manuell via POST /admin/api/profiles/run-autoupdate-all gerufen."""
    profiles = await database.list_auto_update_profiles()
    results = []
    for p in profiles:
        try:
            r = await _run_profile_autoupdate(p["id"], actor="scheduler")
            results.append(r)
        except Exception as e:
            logger.exception("auto-update failed for profile %s: %s", p["id"], e)
            results.append({"profile_id": p["id"], "error": str(e)})
    return {"profile_count": len(profiles), "results": results}


@router.post("/admin/api/profiles/{profile_id}/run-autoupdate",
             dependencies=[Depends(_require_admin)])
async def run_profile_autoupdate_endpoint(profile_id: int, request: Request):
    """Manueller Trigger fuer den Auto-Update-Job eines einzelnen Profils.
    Funktioniert auch wenn auto_update=0 — explizit getriggert ueberschreibt
    den Flag-Check."""
    profile = await database.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profil nicht gefunden")
    user = await _require_admin(request)

    # Temporaer auto_update simulieren: wenn Flag nicht gesetzt, bypass-aware
    # _run_profile_autoupdate macht das via direktem Aufruf der inneren Logik.
    from routes.install import dispatch_install_for_agent

    packages = profile.get("packages") or []
    if not packages:
        return {"ok": True, "queued": 0, "message": "Profil hat keine Pakete"}
    agents = await database.get_agents_for_profile(profile_id)
    if not agents:
        return {"ok": True, "queued": 0, "message": "Profil ist keinen Clients zugewiesen"}

    queued = 0
    skipped = 0
    failed = 0
    for ag in agents:
        wstate, cstate, tracked, tsw = await _agent_state_snapshot(ag["agent_id"])
        for pp in packages:
            pkg = await database.get_package(pp["package_name"])
            if not pkg:
                continue
            pin = pp.get("version_pin")
            if _is_package_satisfied(pkg, pin, wstate, cstate, tracked, tsw):
                skipped += 1
                continue
            try:
                await dispatch_install_for_agent(
                    ag["agent_id"], ag["hostname"], pkg, version_pin=pin,
                )
                queued += 1
            except HTTPException as e:
                failed += 1
                logger.warning(
                    "manual auto-update dispatch failed agent=%s pkg=%s: %s",
                    ag["agent_id"], pp["package_name"], e.detail,
                )

    await database.mark_profile_auto_update_run(profile_id)
    await database.log_audit_event(
        "profile_autoupdate_run",
        actor=user.get("username"),
        details={
            "profile_id": profile_id,
            "name": profile["name"],
            "manual_trigger": True,
            "agents": len(agents),
            "packages": len(packages),
            "queued": queued,
            "skipped_already_current": skipped,
            "failed": failed,
        },
    )
    return {
        "ok": True,
        "queued": queued,
        "skipped_already_current": skipped,
        "failed": failed,
        "agents": len(agents),
    }


@router.delete("/admin/api/profiles/{profile_id}", dependencies=[Depends(_require_admin)])
async def delete_profile_endpoint(profile_id: int, request: Request):
    profile = await database.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profil nicht gefunden")
    await database.delete_profile(profile_id)
    user = await _require_admin(request)
    await database.log_audit_event(
        "profile_deleted",
        actor=user.get("username"),
        details={"profile_id": profile_id, "name": profile["name"]},
    )
    return {"ok": True}


@router.post("/admin/api/profiles/{profile_id}/apply", dependencies=[Depends(_require_admin)])
async def apply_profile_endpoint(profile_id: int, body: ProfileApplyBody, request: Request):
    """Assign Profil zu N Agents UND dispatch sofort einen Install fuer jedes
    Profil-Paket auf jedem dieser Agents. Idempotent — bereits installierte
    Pakete laufen einfach durch (dispatch ist fire-and-forget)."""
    from routes.install import dispatch_install_for_agent

    profile = await database.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profil nicht gefunden")
    if not profile["packages"]:
        raise HTTPException(
            status_code=400,
            detail="Profil hat keine Pakete — nichts zu installieren",
        )

    user = await _require_admin(request)
    queued = 0
    skipped_existing = 0
    failed_agents = []
    for agent_id in body.agent_ids:
        try:
            agent = await _resolve_agent(agent_id)
        except HTTPException:
            failed_agents.append(agent_id)
            continue
        await database.assign_profile_to_agent(
            agent_id, profile_id, assigned_by=user.get("username"),
        )
        wstate, cstate, tracked, tsw = await _agent_state_snapshot(agent_id)
        for pp in profile["packages"]:
            pkg = await database.get_package(pp["package_name"])
            if not pkg:
                continue
            pin = pp.get("version_pin")
            if _is_package_satisfied(pkg, pin, wstate, cstate, tracked, tsw):
                skipped_existing += 1
                continue
            try:
                await dispatch_install_for_agent(
                    agent_id, agent["hostname"], pkg, version_pin=pin,
                )
                queued += 1
            except HTTPException as e:
                logger.warning(
                    "Profile apply dispatch failed agent=%s pkg=%s: %s",
                    agent_id, pp["package_name"], e.detail,
                )

    await database.log_audit_event(
        "profile_applied",
        actor=user.get("username"),
        details={"profile_id": profile_id, "name": profile["name"],
                 "agent_ids": body.agent_ids, "queued": queued,
                 "skipped_already_installed": skipped_existing,
                 "failed_agents": failed_agents},
    )
    return {"ok": True, "queued": queued, "agents": len(body.agent_ids),
            "skipped_already_installed": skipped_existing,
            "failed_agents": failed_agents}


@router.post("/admin/api/profiles/{profile_id}/unassign", dependencies=[Depends(_require_admin)])
async def unassign_profile_endpoint(profile_id: int, body: ProfileUnassignBody, request: Request):
    """Loescht die Profil-Zuweisung von N Agents.

    Wenn `uninstall_packages=True` wird zusaetzlich fuer jedes Profil-Paket
    auf jedem Agent ein Uninstall-Dispatch gefeuert. Ohne den Flag bleiben
    die installierten Pakete auf den Agents — nur die Assignment-Verbindung
    geht weg. Audit unterscheidet die zwei Faelle.
    """
    from routes.install import dispatch_uninstall_for_agent

    profile = await database.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profil nicht gefunden")

    user = await _require_admin(request)
    removed = 0
    uninstalls_queued = 0
    failed = []

    for agent_id in body.agent_ids:
        try:
            agent = await _resolve_agent(agent_id)
        except HTTPException:
            failed.append(agent_id)
            continue

        if body.uninstall_packages and profile.get("packages"):
            for pp in profile["packages"]:
                pkg = await database.get_package(pp["package_name"])
                if not pkg:
                    continue
                try:
                    await dispatch_uninstall_for_agent(agent_id, agent["hostname"], pkg)
                    uninstalls_queued += 1
                except HTTPException as e:
                    logger.warning(
                        "Profile unassign uninstall failed agent=%s pkg=%s: %s",
                        agent_id, pp["package_name"], e.detail,
                    )

        if await database.unassign_profile_from_agent(agent_id, profile_id):
            removed += 1

    await database.log_audit_event(
        "profile_unassigned",
        actor=user.get("username"),
        details={
            "profile_id": profile_id,
            "agent_ids": body.agent_ids,
            "removed": removed,
            "with_uninstall": body.uninstall_packages,
            "uninstalls_queued": uninstalls_queued,
            "failed_agents": failed,
        },
    )
    return {
        "ok": True,
        "removed": removed,
        "uninstalls_queued": uninstalls_queued,
        "failed_agents": failed,
    }


@router.get("/admin/api/agents/{agent_id}/profiles", dependencies=[Depends(_require_admin)])
async def list_agent_profiles_endpoint(agent_id: str):
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungueltige Agent-ID")
    return {"profiles": await database.list_agent_profiles(agent_id)}


@router.post("/admin/api/agents/{agent_id}/install-bulk", dependencies=[Depends(_require_admin)])
async def bulk_install_on_agent(agent_id: str, body: BulkInstallBody):
    """Mehrere Pakete in einem Rutsch auf einem Agent installieren — der gleiche
    Type-Dispatch wie der Einzel-Install pro Paket, nur N-fach."""
    from routes.install import dispatch_install_for_agent

    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungueltige Agent-ID")
    agent = await _resolve_agent(agent_id)

    queued = 0
    skipped = []
    for pkg_name in body.package_names:
        pkg = await database.get_package(pkg_name)
        if not pkg:
            skipped.append(pkg_name)
            continue
        try:
            await dispatch_install_for_agent(agent_id, agent["hostname"], pkg)
            queued += 1
        except HTTPException as e:
            logger.warning("Bulk-install dispatch failed pkg=%s: %s", pkg_name, e.detail)
            skipped.append(pkg_name)

    return {"ok": True, "queued": queued, "skipped": skipped, "agent": agent["hostname"]}


@router.post("/admin/api/agents/{agent_id}/update-all", dependencies=[Depends(_require_admin)])
async def update_all_on_agent(agent_id: str):
    """Alle Pakete dieses Agents die ein Update verfuegbar haben upgraden.
    Liest die effektiv updateable-Liste aus dem agent-software endpoint
    (winget_state + choco_state + custom version-tracking)."""
    from routes.install import dispatch_install_for_agent

    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise HTTPException(status_code=400, detail="Ungueltige Agent-ID")
    agent = await _resolve_agent(agent_id)

    queued = 0
    package_names: list[str] = []

    # winget: alle Eintraege wo available_version != installed_version
    winget_state = await database.get_agent_winget_state(agent_id)
    for wid, st in winget_state.items():
        inst = (st.get("installed_version") or "").strip()
        avail = (st.get("available_version") or "").strip()
        if inst and avail and inst != avail:
            pkg = await database.get_package(wid)
            if pkg and (pkg.get("type") == "winget"):
                package_names.append(wid)

    # choco: dito
    choco_state = await database.get_agent_choco_state(agent_id)
    for cname, st in choco_state.items():
        inst = (st.get("installed_version") or "").strip()
        avail = (st.get("available_version") or "").strip()
        if inst and avail and inst != avail:
            pkg = await database.get_package(cname)
            if pkg and (pkg.get("type") or "choco") == "choco":
                package_names.append(cname)

    for pkg_name in package_names:
        pkg = await database.get_package(pkg_name)
        if not pkg:
            continue
        try:
            await dispatch_install_for_agent(agent_id, agent["hostname"], pkg)
            queued += 1
        except HTTPException as e:
            logger.warning("Update-all dispatch failed pkg=%s: %s", pkg_name, e.detail)

    return {"ok": True, "queued": queued, "packages": package_names,
            "agent": agent["hostname"]}


@router.post("/admin/api/packages/{name}/update-all", dependencies=[Depends(_require_admin)])
async def update_all_for_package(name: str, stage: str = "all"):
    """Ein Paket auf jedem Agent upgraden, wo es installiert UND outdated ist.
    Fleet-Update fuer einen einzelnen Paket-Name. Liest aus winget_state /
    choco_state je nach packages.type.

    `stage` filtert nach agents.ring. Staged-Pakete muessen explizit Ring
    setzen statt 'all' — sonst 400."""
    from routes.install import dispatch_install_for_agent

    pkg = await database.get_package(name)
    if not pkg:
        raise HTTPException(status_code=404, detail="Paket nicht gefunden")
    _check_stage(stage)
    _enforce_staged_guard(pkg, stage)
    allowed_agents = {a["agent_id"] for a in
                      await database.get_agents_by_ring(_stage_to_ring_filter(stage))}

    ptype = pkg.get("type") or "choco"

    affected: list[dict] = []
    if ptype == "winget":
        affected = await database.get_agents_with_winget_package(name)
    elif ptype == "choco":
        affected = await database.get_agents_with_choco_package(name)
    else:
        raise HTTPException(
            status_code=400,
            detail="Update-all fuer custom-Pakete laeuft ueber Push-Update auf der Versions-Seite",
        )

    queued = 0
    for ag in affected:
        if ag["agent_id"] not in allowed_agents:
            continue
        inst = (ag.get("installed_version") or "").strip()
        avail = (ag.get("available_version") or "").strip()
        if not (inst and avail and inst != avail):
            continue  # nicht outdated, skip
        try:
            await dispatch_install_for_agent(ag["agent_id"], ag["hostname"], pkg)
            queued += 1
        except HTTPException as e:
            logger.warning("Fleet-update dispatch failed agent=%s: %s",
                           ag["agent_id"], e.detail)

    return {"ok": True, "queued": queued, "agents_outdated": queued}


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
    exe_meta = {}
    if ext == ".msi":
        msi_meta = await file_uploads.parse_msi_metadata(final_path)
    elif ext == ".exe":
        exe_meta = await file_uploads.parse_exe_metadata(final_path)

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

    # Detection-Name: Eingabe → MSI-ProductName → EXE-ProductName (mit
    # CompanyName-Prefix wenn nicht schon enthalten) → vom Paket erben
    eff_detection = detection_name.strip()
    if is_new_package and not eff_detection:
        if msi_meta.get("ProductName"):
            eff_detection = msi_meta["ProductName"]
        elif exe_meta.get("ProductName"):
            pn = exe_meta["ProductName"]
            cn = exe_meta.get("CompanyName", "")
            if cn and cn.lower() not in pn.lower():
                eff_detection = f"{cn} {pn}"
            else:
                eff_detection = pn

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
            "exe_metadata": exe_meta,
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
            "exe_metadata": exe_meta,
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


# ── Branding (App-Icon fuer Apps & Features) ──────────────────────────────────

def _branding_dir() -> str:
    return os.path.join(os.path.dirname(database.DB_PATH), "branding")


def _branding_icon_path() -> str:
    return os.path.join(_branding_dir(), "icon.ico")


_ALLOWED_ICON_EXTS = (".ico", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")
_MAX_ICON_BYTES = 5 * 1024 * 1024  # 5 MB
# Pixel-Limit gegen Decompression-Bombs: 1024x1024 RGBA = ~4 MB RAM, das reicht
# fuer Apps & Features (max sinnvolle Groesse ist 256x256, wir lassen 2x Buffer).
_MAX_ICON_PIXELS = 2 * 1024 * 1024
_ICON_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def _convert_to_ico(raw: bytes) -> bytes:
    """Liest ein beliebiges Bildformat und gibt ein Multi-Resolution ICO zurueck.

    Hardening:
      - Pixel-Limit (~2 Mpx) gegen Decompression-Bomb-DoS
      - DecompressionBombError wird explizit gefangen
      - img.load() forciert vollstaendigen Decode bevor convert() Speicher allokiert
    """
    try:
        img = Image.open(io.BytesIO(raw))
    except UnidentifiedImageError:
        raise HTTPException(status_code=400, detail="Datei ist kein gueltiges Bild")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Bild konnte nicht gelesen werden: {e}")

    if img.size[0] * img.size[1] > _MAX_ICON_PIXELS:
        raise HTTPException(
            status_code=400,
            detail=f"Bild zu gross ({img.size[0]}x{img.size[1]}, max ~2 Megapixel)",
        )
    if img.size[0] < 16 or img.size[1] < 16:
        raise HTTPException(
            status_code=400,
            detail="Bild zu klein (min 16x16 Pixel)",
        )

    try:
        img.load()
    except DecompressionBombError:
        raise HTTPException(status_code=400, detail="Bild als Dekompressionsbombe erkannt")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Bild-Decode fehlgeschlagen: {e}")

    img = img.convert("RGBA")

    # Nur die Groessen behalten die in das Original passen (kein Hochskalieren —
    # Pillow upsampled sonst aliased).
    max_dim = max(img.size)
    sizes = [s for s in _ICON_SIZES if s[0] <= max_dim]

    out = io.BytesIO()
    img.save(out, format="ICO", sizes=sizes)
    return out.getvalue()


def _icon_status() -> dict:
    path = _branding_icon_path()
    if not os.path.isfile(path):
        return {"exists": False, "uploaded_at": None, "size": None}
    stat = os.stat(path)
    return {
        "exists": True,
        "uploaded_at": int(stat.st_mtime),
        "size": stat.st_size,
    }


@router.get("/admin/api/branding", dependencies=[Depends(_require_admin)])
async def get_branding():
    """Status des Branding-Icons (existiert ja/nein, mtime fuer Cache-Busting)."""
    return {"icon": _icon_status()}


@router.post("/admin/api/branding/icon", dependencies=[Depends(_require_admin)])
async def upload_branding_icon(file: UploadFile = File(...)):
    """Nimmt ein Icon (ICO/PNG/JPG/...) entgegen und speichert es als Multi-Res ICO."""
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in _ALLOWED_ICON_EXTS:
        raise HTTPException(
            status_code=400,
            detail=f"Dateityp nicht erlaubt. Erlaubt: {', '.join(_ALLOWED_ICON_EXTS)}",
        )

    raw = await file.read(_MAX_ICON_BYTES + 1)
    if len(raw) > _MAX_ICON_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Datei zu gross (max {_MAX_ICON_BYTES // 1024 // 1024} MB)",
        )
    if not raw:
        raise HTTPException(status_code=400, detail="Datei ist leer")

    ico_bytes = _convert_to_ico(raw)

    os.makedirs(_branding_dir(), exist_ok=True)
    icon_path = _branding_icon_path()
    tmp_path = icon_path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(ico_bytes)
    os.replace(tmp_path, icon_path)

    return {"ok": True, "icon": _icon_status()}


@router.delete("/admin/api/branding/icon", dependencies=[Depends(_require_admin)])
async def delete_branding_icon():
    """Entfernt das hochgeladene Icon (PyInstaller faellt dann auf Default zurueck)."""
    try:
        os.unlink(_branding_icon_path())
    except FileNotFoundError:
        pass
    return {"ok": True, "icon": _icon_status()}


@router.get("/admin/api/branding/icon", dependencies=[Depends(_require_admin)])
async def get_branding_icon():
    """Liefert das gespeicherte Icon zur Vorschau im Admin-UI."""
    path = _branding_icon_path()
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Kein Icon hochgeladen")
    with open(path, "rb") as f:
        data = f.read()
    return Response(content=data, media_type="image/x-icon")


def _read_icon_b64() -> str | None:
    """Liest das Icon vom Disk und gibt es base64-encoded zurueck (oder None)."""
    path = _branding_icon_path()
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


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
    slug        = await runtime_value("product_slug") or "Softshelf"
    publisher   = await runtime_value("publisher") or slug
    app_name    = await runtime_value("client_app_name") or slug
    icon_b64    = _read_icon_b64()  # None wenn kein Icon hochgeladen

    cfg = get_settings()
    version = "2.0.2"  # wird in der EXE angezeigt

    build_id = await database.start_build_log(proxy_url, version)

    # Build im Hintergrund starten, nicht auf Ergebnis warten
    _spawn_bg(_run_build_async(
        build_id, cfg.builder_url, proxy_url, version, slug, publisher,
        app_name, icon_b64,
    ))

    return {"ok": True, "build_id": build_id, "status": "running"}


async def _run_build_async(
    build_id: int,
    builder_url: str,
    proxy_url: str,
    version: str,
    slug: str,
    publisher: str,
    app_name: str,
    icon_b64: str | None,
):
    """Ruft den Builder-Container auf und speichert das Ergebnis im build_log."""
    status = "failed"
    log = ""
    try:
        async with httpx.AsyncClient(timeout=600) as c:
            payload = {
                "proxy_url": proxy_url,
                "version": version,
                "product_slug": slug,
                "publisher": publisher,
                "client_app_name": app_name,
            }
            if icon_b64:
                payload["icon_ico_b64"] = icon_b64
            r = await c.post(f"{builder_url}/build", json=payload)
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
    scope: str = Field(default="auto")

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

    @field_validator("scope")
    @classmethod
    def _check_scope(cls, v: str) -> str:
        if v not in ("auto", "machine", "user"):
            raise ValueError("scope muss auto, machine oder user sein")
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
        winget_scope=body.scope,
    )
    # Policy rollout_default_staged: wenn aktiv, neues winget-Paket
    # automatisch als staged markieren.
    try:
        default_staged = (
            (await runtime_value("rollout_default_staged")) or "false"
        ).lower() in ("true", "1", "yes", "on")
        if default_staged:
            await database.update_package_staged(body.id, True)
    except Exception:
        pass
    rows = await database.get_packages()
    return {"ok": True, "total": len(rows)}


class WingetScopeRequest(BaseModel):
    scope: str

    @field_validator("scope")
    @classmethod
    def _check_scope(cls, v: str) -> str:
        if v not in ("auto", "machine", "user"):
            raise ValueError("scope muss auto, machine oder user sein")
        return v


@router.patch("/admin/api/winget/{name}/scope", dependencies=[Depends(_require_admin)])
async def winget_update_scope(name: str, body: WingetScopeRequest):
    if not _WINGET_ID_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungültige winget-ID")
    pkg = await database.get_package(name)
    if not pkg or pkg.get("type") != "winget":
        raise HTTPException(status_code=404, detail="winget-Paket nicht gefunden")
    await database.update_winget_scope(name, body.scope)
    return {"ok": True, "scope": body.scope}


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
