"""
Machine Token Authentifizierung.

Jeder Kiosk-Client bekommt beim Deployment ein signiertes Token mit:
  - agent_id    (Tactical RMM Agent ID des Geräts)
  - hostname    (zur Anzeige / Logging)
  - iat         (Issued At – Unix Timestamp)
  - exp         (Ablaufzeit – nach token_ttl_days, optional)
  - tv          (Token-Version – wird beim Re-Register hochgezählt → Revocation)

Das Token ist ein HS256-signiertes JWT. Der Secret Key liegt NUR auf dem Proxy.
Eine Re-Registrierung des selben Agents invalidiert alle vorherigen Tokens
(über die Token-Version in der DB).
"""
import time
import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import database
from config import get_settings, runtime_int

bearer_scheme = HTTPBearer()


async def create_machine_token(agent_id: str, hostname: str) -> str:
    """Erstellt ein neues Machine Token. Liest die aktuelle token_version aus der DB."""
    cfg = get_settings()
    tv = await database.get_token_version(agent_id)
    ttl_days = await runtime_int("token_ttl_days")
    now = int(time.time())
    payload = {
        "agent_id": agent_id,
        "hostname": hostname,
        "iat": now,
        "tv": tv,
    }
    if ttl_days > 0:
        payload["exp"] = now + ttl_days * 86400
    return jwt.encode(payload, cfg.secret_key, algorithm="HS256")


def create_download_token(sha256: str, agent_id: str, ttl_seconds: int = 300) -> str:
    """
    Kurzlebiger Download-Token für eine custom-File, gebunden an Hash + Agent-ID.

    Wird in die Download-URL als ?token=... gepackt. Der Tactical-Agent dieses
    PCs lädt mit dieser URL die Datei und installiert sie. Token läuft nach
    ttl_seconds ab (default 5 min) – lange genug für den Download, kurz genug
    um Replay-Attacken zu begrenzen.
    """
    cfg = get_settings()
    now = int(time.time())
    payload = {
        "typ": "dl",
        "sha": sha256,
        "agent_id": agent_id,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, cfg.secret_key, algorithm="HS256")


def verify_download_token(token: str, sha256: str) -> dict:
    """
    Validiert einen Download-Token gegen den erwarteten Hash.
    Wirft HTTPException bei jedem Fehler.
    """
    cfg = get_settings()
    try:
        payload = jwt.decode(token, cfg.secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=403, detail="Download-Token abgelaufen")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=403, detail=f"Ungültiger Download-Token: {e}")

    if payload.get("typ") != "dl":
        raise HTTPException(status_code=403, detail="Falscher Token-Typ")
    if payload.get("sha") != sha256:
        raise HTTPException(status_code=403, detail="Token-Hash stimmt nicht")
    if "agent_id" not in payload:
        raise HTTPException(status_code=403, detail="Token fehlt agent_id")
    return payload


async def verify_machine_token(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> dict:
    """
    FastAPI Dependency: Validiert das Bearer Token, prüft Ablauf + Revocation,
    aktualisiert last_seen. Gibt das dekodierte Payload zurück.
    """
    cfg = get_settings()
    try:
        payload = jwt.decode(
            credentials.credentials,
            cfg.secret_key,
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token abgelaufen – Software Center bitte neu installieren.",
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Ungültiges Token: {e}")

    if "agent_id" not in payload or "hostname" not in payload:
        raise HTTPException(status_code=401, detail="Token fehlt Pflichtfelder")

    # Banned? — überschreibt alles andere, gilt auch wenn der agent_id-Eintrag
    # längst gelöscht wurde
    if await database.is_agent_banned(payload["agent_id"]):
        raise HTTPException(
            status_code=403,
            detail="Dieses Gerät wurde vom Self-Service Center gesperrt.",
        )

    # Token-Version gegen DB prüfen → Revocation nach Re-Register
    current_tv = await database.get_token_version(payload["agent_id"])
    if payload.get("tv", 0) != current_tv:
        raise HTTPException(
            status_code=401,
            detail="Token wurde widerrufen – Software Center bitte neu installieren.",
        )

    await database.update_agent_seen(payload["agent_id"], payload["hostname"])
    return payload
