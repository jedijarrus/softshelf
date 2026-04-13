"""
Admin-User-Verwaltung, Session-Cookies und SSO (Entra ID).

Kernkonzepte:
  - Passwort-Hashing mit hashlib.scrypt (stdlib, kein extra Dependency)
  - Sessions als opaque Token in Cookie + DB-Lookup (revoke-bar)
  - Entra-ID OIDC-Login via Authorization-Code-Flow + JWKS-Verify

Login-Flows:
  1. Lokal:  POST /admin/login {username, password} → Session-Cookie
  2. SSO:    GET /admin/sso/login → Microsoft → Callback → Session-Cookie
"""
import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone

import database
from config import get_settings, runtime_value


# ── Passwort-Hashing ──────────────────────────────────────────────────────────

# Scrypt-Parameter: N=2^14 (~16 MB Memory, ~50ms auf typischer CPU),
# r=8 (Block-Size), p=1 (Parallelism). Alle Werte sind RFC-7914-Empfehlungen
# für interaktive Logins.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64
_SALT_BYTES = 16


def hash_password(plain: str) -> str:
    """Erzeugt einen scrypt-Hash im Format 'scrypt$N$r$p$salt_hex$hash_hex'."""
    salt = secrets.token_bytes(_SALT_BYTES)
    h = hashlib.scrypt(
        plain.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${h.hex()}"


def verify_password(plain: str, stored: str | None) -> bool:
    """Verifiziert ein Passwort gegen den gespeicherten Hash. Timing-safe."""
    if not stored:
        return False
    try:
        parts = stored.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = bytes.fromhex(parts[4])
        expected = bytes.fromhex(parts[5])
        h = hashlib.scrypt(
            plain.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
        )
        return secrets.compare_digest(h, expected)
    except Exception:
        return False


# ── Sessions ──────────────────────────────────────────────────────────────────

SESSION_COOKIE = "softshelf_admin_session"
SESSION_TTL_HOURS = 8


def _now_utc():
    return datetime.now(timezone.utc)


def _format_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


async def create_session(user_id: int, ip: str | None, user_agent: str | None) -> tuple[str, datetime]:
    """Erzeugt eine neue Session für einen User. Gibt Token + expires_at zurück."""
    token = secrets.token_urlsafe(32)
    expires_at = _now_utc() + timedelta(hours=SESSION_TTL_HOURS)
    await database.create_admin_session(
        token=token,
        user_id=user_id,
        expires_at=_format_dt(expires_at),
        ip=ip,
        user_agent=(user_agent or "")[:200],
    )
    return token, expires_at


async def get_session_user(token: str) -> dict | None:
    """
    Validiert ein Session-Token. Lazy-cleanup bei Ablauf.
    Gibt das User-Dict zurück (Session + User), oder None bei ungültig/abgelaufen.
    """
    if not token:
        return None
    sess = await database.get_admin_session(token)
    if not sess:
        return None
    if not sess.get("is_active"):
        return None
    # Ablauf prüfen
    try:
        exp = datetime.strptime(sess["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        return None
    if exp < _now_utc():
        await database.delete_admin_session(token)
        return None
    # last_active updaten (lazy, alle paar Sekunden würde reichen, aber für Audit OK)
    await database.touch_admin_session(token)
    return sess


async def revoke_session(token: str):
    if token:
        await database.delete_admin_session(token)


# ── User-Authentifizierung (Login) ────────────────────────────────────────────

async def authenticate_local(username: str, password: str) -> dict | None:
    """
    Prüft Username + Passwort gegen die admin_users-Tabelle.

    Fallback auf Bootstrap-Credentials aus .env wenn:
      - kein Eintrag in admin_users existiert (frische Installation), ODER
      - der Username dem Bootstrap-Username entspricht UND keine User in der DB sind

    Bootstrap ist NUR aktiv wenn die DB komplett leer ist (Recovery-Pfad).
    """
    if not username or not password:
        return None

    # Normaler DB-Lookup
    user = await database.get_admin_user_by_username(username)
    if user and user.get("is_active"):
        if verify_password(password, user.get("password_hash")):
            await database.touch_admin_login(user["id"])
            return user

    # Bootstrap-Fallback nur wenn KEINE aktiven User existieren
    active_count = await database.count_active_admins()
    if active_count == 0:
        cfg = get_settings()
        if (secrets.compare_digest(username.encode(), cfg.admin_username.encode())
                and secrets.compare_digest(password.encode(), cfg.admin_password.encode())):
            # Bootstrap-User auf-the-fly anlegen, damit künftige Logins über die DB laufen
            user_id = await database.create_admin_user(
                username=cfg.admin_username,
                display_name="Bootstrap Admin",
                email=None,
                password_hash=hash_password(cfg.admin_password),
                is_active=True,
            )
            await database.touch_admin_login(user_id)
            return await database.get_admin_user_by_id(user_id)

    return None


# ── Bootstrap beim Server-Start ───────────────────────────────────────────────

async def ensure_bootstrap_admin():
    """
    Wird beim Server-Start aufgerufen. Wenn noch kein User in der DB ist,
    wird der Bootstrap-Admin aus der .env angelegt, damit der erste Login
    über das neue Login-Formular klappt.
    """
    count = await database.count_active_admins()
    if count > 0:
        return
    cfg = get_settings()
    try:
        await database.create_admin_user(
            username=cfg.admin_username,
            display_name="Bootstrap Admin",
            email=None,
            password_hash=hash_password(cfg.admin_password),
            is_active=True,
        )
    except Exception:
        # Race-Condition mit zweitem Worker o. ä. — ignorieren
        pass


# ── Microsoft Entra ID SSO (OIDC) ─────────────────────────────────────────────

# In-Memory Pending-States (CSRF-Schutz auf OAuth-Callback). Für Single-Worker-
# Setup ausreichend; bei Load-Balancing müsste das in die DB.
_pending_sso: dict[str, float] = {}
_PENDING_TTL_SECONDS = 600


def _cleanup_pending():
    cutoff = time.time() - _PENDING_TTL_SECONDS
    for k, v in list(_pending_sso.items()):
        if v < cutoff:
            _pending_sso.pop(k, None)


def create_sso_state() -> str:
    """Erzeugt einen kurzlebigen State-Token für den OAuth-Flow."""
    _cleanup_pending()
    state = secrets.token_urlsafe(32)
    _pending_sso[state] = time.time()
    return state


def consume_sso_state(state: str) -> bool:
    """Verbraucht einen State-Token (nur einmal verwendbar)."""
    _cleanup_pending()
    if not state or state not in _pending_sso:
        return False
    _pending_sso.pop(state, None)
    return True


async def sso_enabled() -> bool:
    return (await runtime_value("sso_enabled")).lower() in ("1", "true", "yes", "on")


async def sso_authorize_url(redirect_uri: str) -> str | None:
    """
    Baut die Microsoft-Login-URL für den OIDC-Flow.
    Returns None wenn SSO nicht konfiguriert ist.
    """
    if not await sso_enabled():
        return None
    tenant = await runtime_value("sso_tenant_id")
    client_id = await runtime_value("sso_client_id")
    if not tenant or not client_id:
        return None
    state = create_sso_state()
    from urllib.parse import urlencode
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}"


async def sso_exchange_code(code: str, redirect_uri: str) -> dict:
    """
    Tauscht den Authorization-Code gegen Tokens, validiert das ID-Token und
    extrahiert die User-Info. Gibt {oid, email, name} zurück.
    Wirft ValueError bei Problemen.
    """
    import httpx
    import jwt

    tenant = await runtime_value("sso_tenant_id")
    client_id = await runtime_value("sso_client_id")
    client_secret = await runtime_value("sso_client_secret")
    if not (tenant and client_id and client_secret):
        raise ValueError("SSO ist nicht vollständig konfiguriert")

    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            token_url,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "scope": "openid email profile",
            },
        )
        if r.status_code != 200:
            raise ValueError(f"Token-Tausch fehlgeschlagen: HTTP {r.status_code} {r.text[:200]}")
        token_response = r.json()

    id_token = token_response.get("id_token")
    if not id_token:
        raise ValueError("Kein id_token in Microsoft-Antwort")

    # JWKS holen und Signatur prüfen
    jwks_uri = f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
    issuer = f"https://login.microsoftonline.com/{tenant}/v2.0"
    try:
        jwks_client = jwt.PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=issuer,
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
    except Exception as e:
        raise ValueError(f"ID-Token Validation fehlgeschlagen: {e}")

    oid = payload.get("oid") or payload.get("sub")
    # Nur den email-Claim akzeptieren — preferred_username ist NICHT verifiziert
    # in Entra ID und kann von einem Tenant-User auf jede beliebige Adresse
    # gesetzt werden, was sonst Account-Übernahme über E-Mail-Linking ermöglicht.
    email = (payload.get("email") or "").strip()
    email_verified = bool(payload.get("email_verified", False))
    name = payload.get("name") or email or oid
    if not oid:
        raise ValueError("Kein oid/sub im ID-Token")

    return {
        "oid": oid,
        "email": email,
        "email_verified": email_verified,
        "name": name,
    }


async def sso_login_or_provision(
    oid: str, email: str, name: str, email_verified: bool = False
) -> dict | None:
    """
    Findet oder erzeugt einen lokalen admin_user für eine SSO-Identität.

    1. Match auf (sso_provider='entra', sso_subject=oid)
    2. Sonst Match auf email NUR wenn email_verified=true und der bestehende
       User noch keine SSO-Bindung hat → bindet den lokalen User an die
       Entra-Identität
    3. Sonst, wenn sso_auto_create=true: neuer User wird angelegt
    4. Sonst: None (Login abgelehnt)
    """
    if not oid:
        return None

    # 1. Schon mit Entra verknüpft?
    user = await database.get_admin_user_by_sso("entra", oid)
    if user:
        if user.get("is_active"):
            await database.touch_admin_login(user["id"])
            return user
        return None

    # 2. Existierender lokaler User mit gleicher E-Mail — nur bei
    # verifizierter E-Mail UND wenn der bestehende User noch keine
    # SSO-Bindung hat (kein "Account-Hijack via Mailadresse").
    if email and email_verified:
        users = await database.get_admin_users()
        for u in users:
            if (u.get("email") or "").lower() != email.lower():
                continue
            if not u.get("is_active"):
                continue
            if u.get("sso_provider"):
                # Bestehende SSO-Bindung — nicht überschreiben
                continue
            # Verknüpfen
            async with database._db() as db:
                await db.execute(
                    "UPDATE admin_users SET sso_provider='entra', sso_subject=? "
                    "WHERE id = ?",
                    (oid, u["id"]),
                )
                await db.commit()
            await database.touch_admin_login(u["id"])
            return await database.get_admin_user_by_id(u["id"])

    # 3. Auto-Create wenn aktiviert
    auto_create = (await runtime_value("sso_auto_create")).lower() in ("1", "true", "yes", "on")
    if auto_create:
        # Username aus E-Mail-Local-Part oder OID
        base_username = (email.split("@")[0] if email else oid)[:50]
        # Eindeutigen Username finden
        username = base_username
        n = 1
        while await database.get_admin_user_by_username(username):
            n += 1
            username = f"{base_username}-{n}"
        user_id = await database.create_admin_user(
            username=username,
            display_name=name or username,
            email=email or None,
            password_hash=None,  # SSO-only User
            sso_provider="entra",
            sso_subject=oid,
            is_active=True,
        )
        await database.touch_admin_login(user_id)
        return await database.get_admin_user_by_id(user_id)

    return None
