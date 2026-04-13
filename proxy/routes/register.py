"""
POST /api/v1/register
Self-Registration für neue Kiosk-Clients.

Ablauf:
  1. Deployment-Script schickt: agent_id + hostname + registration_secret
  2. Proxy prüft das registration_secret (timing-safe)
  3. Proxy verifiziert, dass die agent_id wirklich in Tactical RMM existiert
  4. Proxy bumpt token_version → vorherige Tokens sind ungültig
  5. Proxy stellt ein signiertes Machine Token aus und gibt es zurück

Das registration_secret wird NICHT auf dem Client gespeichert.
"""
import re
import secrets
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import database
from auth import create_machine_token
from config import runtime_value
from tactical_client import TacticalClient

router = APIRouter()

# Tactical-Agent-IDs sind UUID-ähnliche Strings (Hex + Bindestriche).
# Hier bewusst etwas großzügiger (8–64 Zeichen alphanumerisch + "-").
_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9\-]{8,64}$")
# Hostnames: alphanumerisch, Bindestrich, Punkt, Underscore (Windows-tolerant).
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,253}$")


class RegisterRequest(BaseModel):
    agent_id: str = Field(min_length=8, max_length=64)
    hostname: str = Field(min_length=1, max_length=253)
    registration_secret: str = Field(min_length=1, max_length=512)


class RegisterResponse(BaseModel):
    token: str
    message: str


@router.post("/register", response_model=RegisterResponse)
async def register_client(body: RegisterRequest):
    # 1. Format-Validierung (Schutz vor URL-Injection in Tactical-Calls)
    if not _AGENT_ID_RE.fullmatch(body.agent_id):
        raise HTTPException(status_code=400, detail="Ungültiges Agent-ID-Format")
    if not _HOSTNAME_RE.fullmatch(body.hostname):
        raise HTTPException(status_code=400, detail="Ungültiges Hostname-Format")

    # 2. Registration-Secret aus DB prüfen (timing-safe)
    expected = await runtime_value("registration_secret")
    if not expected:
        raise HTTPException(status_code=503, detail="Proxy noch nicht konfiguriert (registration_secret fehlt)")
    if not secrets.compare_digest(body.registration_secret, expected):
        raise HTTPException(status_code=403, detail="Ungültiges Registration-Secret")

    # 2b. Banned? — Eintrag im agent_blocklist überschreibt jede Re-Registrierung,
    # auch wenn der Agent zwischenzeitlich aus der agents-Tabelle gelöscht wurde
    if await database.is_agent_banned(body.agent_id):
        raise HTTPException(
            status_code=403,
            detail="Dieses Gerät wurde vom Self-Service Center gesperrt.",
        )

    # 3. Agent-ID in Tactical RMM verifizieren
    try:
        await TacticalClient().get_installed_software(body.agent_id)
    except Exception:
        raise HTTPException(
            status_code=404,
            detail=f"Agent '{body.agent_id}' nicht in Tactical RMM gefunden",
        )

    # 4. Agent in der DB upserten und Token-Version hochzählen → alte Tokens sind tot
    await database.upsert_agent(body.agent_id, body.hostname)
    await database.bump_token_version(body.agent_id)

    # 5. Frisches Machine Token ausstellen
    token = await create_machine_token(body.agent_id, body.hostname)

    return RegisterResponse(
        token=token,
        message=f"Registriert: {body.hostname}",
    )
