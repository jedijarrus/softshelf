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


# ── API-Tokens (Bearer-Auth fuer /admin/api/*) ────────────────────────────────

# Token-Layout: 32 zufaellige Bytes -> urlsafe-base64 (~43 chars). Wir speichern
# nur den SHA-256-Hash, der Raw-Token wird genau einmal beim Anlegen
# zurueckgegeben. Damit ist die DB auch bei Leak unschuldig.

def _hash_api_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_api_token() -> tuple[str, str]:
    """Erzeugt einen neuen Raw-Token + seinen SHA-256-Hash."""
    raw = secrets.token_urlsafe(32)
    return raw, _hash_api_token(raw)


async def authenticate_bearer(raw_token: str) -> tuple[dict | None, str]:
    """
    Validiert einen Bearer-Token. Gibt (token_row_with_user, scope) zurueck
    oder (None, '') bei ungueltig/abgelaufen/widerrufen/inaktiver-User.

    token_row enthaelt via JOIN auch username/display_name/role des Users —
    kann direkt wie ein Session-User-Dict benutzt werden.
    """
    if not raw_token:
        return None, ""
    digest = _hash_api_token(raw_token)
    tok = await database.get_admin_api_token_by_hash(digest)
    if not tok:
        return None, ""
    if tok.get("revoked_at"):
        return None, ""
    if not tok.get("user_is_active"):
        return None, ""
    if tok.get("expires_at"):
        try:
            exp = datetime.strptime(
                tok["expires_at"], "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
            if exp < _now_utc():
                return None, ""
        except Exception:
            return None, ""
    await database.touch_admin_api_token(tok["id"])
    return tok, tok.get("scope") or "read"


def format_api_token_expiry(ttl_hours: int | None) -> str | None:
    """ttl_hours None|<=0 = unbefristet; sonst 'YYYY-MM-DD HH:MM:SS' UTC."""
    if not ttl_hours or ttl_hours <= 0:
        return None
    return _format_dt(_now_utc() + timedelta(hours=ttl_hours))


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


# ── Microsoft Entra ID SSO ────────────────────────────────────────────────────
# Der alte OIDC-Server-Redirect-Flow (create_sso_state/consume_sso_state/
# sso_enabled/sso_authorize_url/sso_exchange_code) wurde entfernt — ersetzt durch
# MSAL-Popup + id_token-Verify (verify_azure_id_token, weiter unten), Config via
# ENV GRAPH_* (config.azure_sso_active). Geblieben ist nur das User-Provisioning.


async def sso_login_or_provision(
    oid: str, email: str, name: str, email_verified: bool = False,
    auto_create: bool | None = None,
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

    # 3. Auto-Create. auto_create=None => Runtime-Setting lesen (Legacy).
    # Der MSAL/ENV-Flow ruft mit auto_create=True: die Zugriffskontrolle laeuft
    # ueber die Entra Enterprise-App ("Assignment required") — ein gueltiges
    # Token bedeutet, der Nutzer ist zugewiesen. Neue User werden als operator
    # angelegt (niedrigste Rolle), ein Admin hebt die Rolle bei Bedarf an.
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


# ── Microsoft Entra ID SSO (MSAL-SPA / id_token-Verify) ───────────────────────
# Neuer Flow: das Frontend macht MSAL-loginPopup und schickt das id_token an
# POST /api/auth/azure/verify. Hier wird es per JWKS validiert. Kein Server-
# Redirect, kein Client-Secret noetig (Public Client). Konfiguration via ENV
# (GRAPH_TENANT_ID / GRAPH_CLIENT_ID), siehe config.azure_sso_active().

_JWKS_CACHE: dict[str, tuple[object, float]] = {}
_JWKS_TTL_SECONDS = 3600


def _get_jwks_client(tenant: str):
    """PyJWKClient pro Tenant, ~1h gecacht (PyJWKClient cached die Keys zusaetzlich)."""
    import jwt
    now = time.time()
    entry = _JWKS_CACHE.get(tenant)
    if entry and (now - entry[1]) < _JWKS_TTL_SECONDS:
        return entry[0]
    jwks_uri = f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
    client = jwt.PyJWKClient(jwks_uri)
    _JWKS_CACHE[tenant] = (client, now)
    return client


def verify_azure_id_token(token: str) -> dict:
    """
    Validiert ein Entra-id_token aus dem MSAL-Popup. Wirft ValueError bei
    ungueltig. Prueft: Signatur (JWKS/RS256), aud==GRAPH_CLIENT_ID,
    iss==login.microsoftonline.com/{tenant}/v2.0 (sts-Variante erlaubt),
    tid==GRAPH_TENANT_ID, exp/iat. Gibt Claims-Dict zurueck.
    """
    import jwt
    from config import get_settings

    s = get_settings()
    tenant = s.graph_tenant_id
    client_id = s.graph_client_id
    if not (tenant and client_id):
        raise ValueError("SSO nicht konfiguriert (GRAPH_TENANT_ID/GRAPH_CLIENT_ID fehlen)")
    if not token or not isinstance(token, str):
        raise ValueError("Kein Token")

    try:
        signing_key = _get_jwks_client(tenant).get_signing_key_from_jwt(token)
    except Exception as e:
        raise ValueError(f"Signing-Key nicht auffindbar: {e}")

    try:
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=client_id,
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
    except Exception as e:
        raise ValueError(f"Token-Validierung fehlgeschlagen: {e}")

    allowed_iss = {
        f"https://login.microsoftonline.com/{tenant}/v2.0",
        f"https://sts.windows.net/{tenant}/",
    }
    if payload.get("iss") not in allowed_iss:
        raise ValueError(f"Unerwarteter Issuer: {payload.get('iss')}")
    if payload.get("tid") != tenant:
        raise ValueError("tid stimmt nicht mit Tenant ueberein")

    oid = payload.get("oid") or payload.get("sub")
    if not oid:
        raise ValueError("Kein oid/sub im Token")

    return {
        "oid": oid,
        "name": payload.get("name") or "",
        "email": (payload.get("email") or "").strip(),
        "email_verified": bool(payload.get("email_verified", False)),
        "preferred_username": payload.get("preferred_username") or "",
        "upn": payload.get("upn") or "",
    }


def azure_display_name(claims: dict) -> str:
    """Anzeigename aus name / preferred_username / upn / email / oid."""
    return (
        claims.get("name")
        or claims.get("preferred_username")
        or claims.get("upn")
        or claims.get("email")
        or claims.get("oid")
        or "Microsoft-Nutzer"
    )
