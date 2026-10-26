"""
Kiosk-Mitteilungen (v2.10) — Machine-Token-Endpoints fuer den Tray.

- GET  /api/v1/messages                         → Verlauf (Kiosk-Tab), 30 Tage
- POST /api/v1/messages/{occurrence_id}/receipt → Quittung shown|acked

Offene Mitteilungen kommen ueber /api/v1/health (Feld `messages`), damit der
Tray keinen zusaetzlichen Poll braucht. Der Windows-User kommt — wie beim
Health-Poll — aus dem Header X-Softshelf-User.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

import messages
from auth import verify_machine_token

router = APIRouter()

_USER_RE = re.compile(r'[^\x00-\x1f\x7f<>"\'`]{1,60}')


def win_user_from(request: Request) -> str:
    u = request.headers.get("x-softshelf-user", "").strip()[:60]
    return u if u and _USER_RE.fullmatch(u) else ""


class ReceiptBody(BaseModel):
    event: str


@router.get("/messages")
async def list_kiosk_messages(request: Request, token: dict = Depends(verify_machine_token)):
    return await messages.history_for_agent(token["agent_id"], win_user_from(request))


@router.post("/messages/{occurrence_id}/receipt")
async def post_receipt(occurrence_id: int, body: ReceiptBody, request: Request,
                       token: dict = Depends(verify_machine_token)):
    ok = await messages.record_receipt(
        token["agent_id"], win_user_from(request), occurrence_id, body.event)
    if not ok:
        raise HTTPException(status_code=404, detail="Mitteilung nicht gefunden")
    return {"ok": True}
