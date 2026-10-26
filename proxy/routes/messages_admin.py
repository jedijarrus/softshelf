"""
Admin-Endpoints fuer Mitteilungen + Zielgruppen (v2.10).

Mitteilungen:
- GET    /admin/api/messages                     Liste mit Status + Zaehlern
- POST   /admin/api/messages                     anlegen
- GET    /admin/api/messages/{id}                Detail inkl. Ausgaben
- PATCH  /admin/api/messages/{id}                bearbeiten
- POST   /admin/api/messages/{id}/status         aktiv | pausiert | zurueckgezogen
- POST   /admin/api/messages/{id}/duplicate      Kopie (pausiert) anlegen
- GET    /admin/api/messages/occurrences/{oid}   Quittungen + fehlende Geraete
- GET    /admin/api/messages/refs                Geraete + Profile fuer Editor (v2.11)
- GET    /admin/api/messages/{id}/export.xlsx    Excel-Export (v2.11)

Zielgruppen:
- GET/POST          /admin/api/target-groups
- PATCH/DELETE      /admin/api/target-groups/{id}
- POST              /admin/api/target-groups/preview   trifft aktuell auf N Geraete zu
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

import database
import message_export
import messages
from routes.admin import _require_admin
from winget_catalog import is_outdated

logger = logging.getLogger(__name__)
router = APIRouter()

MESSAGE_MIN_TRAY = "2.10.0"


# ── Models ────────────────────────────────────────────────────────────────────

class MessageBody(BaseModel):
    header: str = Field("IT informiert", max_length=60)
    title: str = Field(..., min_length=1, max_length=120)
    body: str = Field("", max_length=2000)
    severity: str = "info"
    link_url: str = Field("", max_length=500)
    link_label: str = Field("", max_length=40)
    target_group_id: int | None = None
    schedule: dict = {"mode": "once"}
    show_hours: int = Field(24, ge=1, le=168)
    valid_from: str | None = None      # datetime-local (Europe/Berlin); leer = sofort
    valid_until: str | None = None


class StatusBody(BaseModel):
    status: str


class TargetGroupBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    kind: str = "dynamic"
    agent_ids: list[str] = []
    rules: list[dict] = []


# ── Helpers ───────────────────────────────────────────────────────────────────

def _actor(user: dict) -> str:
    return (user or {}).get("username") or "admin"


async def _validated(body: MessageBody) -> dict:
    if body.severity not in messages.SEVERITIES:
        raise HTTPException(status_code=400, detail="Ungültige Stufe")
    link = body.link_url.strip()
    if link and not link.lower().startswith("https://"):
        raise HTTPException(status_code=400, detail="Link muss mit https:// beginnen")
    if body.target_group_id is not None and not await database.get_target_group(body.target_group_id):
        raise HTTPException(status_code=400, detail="Zielgruppe nicht gefunden")
    try:
        sched = messages.validate_schedule(body.schedule or {})
        vf = messages.local_to_utc(body.valid_from) if body.valid_from else messages.now_utc()
        vu = messages.local_to_utc(body.valid_until) if body.valid_until else None
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if vu and vu <= vf:
        raise HTTPException(status_code=400, detail="'Gültig bis' muss nach 'Anzeigen ab' liegen")
    if sched["mode"] == "once" and vu and vu < vf + timedelta(minutes=5):
        raise HTTPException(status_code=400, detail="Anzeigezeitraum zu kurz")
    return {
        "header": body.header.strip() or "IT informiert",
        "title": body.title.strip(),
        "body": body.body.replace("\r\n", "\n").strip(),
        "severity": body.severity,
        "link_url": link or None,
        "link_label": body.link_label.strip() or None,
        "target_group_id": body.target_group_id,
        "schedule": json.dumps(sched),
        "show_hours": body.show_hours,
        "valid_from": messages.to_db(vf),
        "valid_until": messages.to_db(vu) if vu else None,
    }


def _state(m: dict) -> str:
    """geplant | aktiv | beendet | pausiert | zurueckgezogen"""
    if m["status"] == "cancelled":
        return "zurueckgezogen"
    if m["status"] == "paused":
        return "pausiert"
    now = messages.now_utc()
    vf, vu = messages.from_db(m["valid_from"]), messages.from_db(m.get("valid_until"))
    if vu and now >= vu:
        return "beendet"
    try:
        once = json.loads(m.get("schedule") or "{}").get("mode", "once") == "once"
    except Exception:
        once = True
    if once and m.get("occurrence_count") and m.get("last_fire_at"):
        end = messages.from_db(m["last_fire_at"]) + timedelta(hours=int(m.get("show_hours") or 24))
        if vu:
            end = min(end, vu)
        if now >= end:
            return "beendet"
    return "geplant" if vf and now < vf else "aktiv"


def _present(m: dict) -> dict:
    try:
        sched = json.loads(m.get("schedule") or "{}")
    except Exception:
        sched = {"mode": "once"}
    out = dict(m)
    out["schedule"] = sched
    out["schedule_text"] = messages.describe_schedule(sched)
    out["valid_from_local"] = messages.utc_to_local_str(m.get("valid_from"))
    out["valid_until_local"] = messages.utc_to_local_str(m.get("valid_until"))
    out["state"] = _state(m)
    return out


async def _target_ids(target_group_id: int | None) -> set[str]:
    return await messages.target_ids(target_group_id)


def _receipt_agents(receipts: list[dict]) -> dict[int, set[str]]:
    out: dict[int, set[str]] = {}
    for r in receipts:
        out.setdefault(r["occurrence_id"], set()).add(r["agent_id"])
    return out


async def _old_tray_count(ids: set[str]) -> int:
    agents = {a["agent_id"]: a for a in await database.get_target_agents()}
    return sum(1 for i in ids if i in agents and (
        not agents[i].get("client_version")
        or is_outdated(agents[i]["client_version"], MESSAGE_MIN_TRAY)))


# ── Mitteilungen ──────────────────────────────────────────────────────────────

@router.get("/admin/api/messages", dependencies=[Depends(_require_admin)])
async def list_messages():
    return [_present(m) for m in await database.list_messages()]


@router.get("/admin/api/messages/refs", dependencies=[Depends(_require_admin)])
async def message_refs():
    """Schlanke Geraete- und Profilliste fuer Zielgruppen-Editor und Empfaenger.
    Eigener Endpoint, damit die Rolle 'messages' nicht die volle Agent-Liste braucht."""
    agents = [{k: a.get(k) for k in ("agent_id", "hostname", "logged_in_user", "client_version", "banned")}
              for a in await database.get_agents()]
    profiles = [{"id": p["id"], "name": p["name"]} for p in await database.list_profiles()]
    return {"agents": agents, "profiles": profiles}


@router.post("/admin/api/messages", dependencies=[Depends(_require_admin)])
async def create_message(body: MessageBody, request: Request):
    user = await _require_admin(request)
    fields = await _validated(body)
    mid = await database.create_message(**fields, status="active", created_by=_actor(user))
    await messages.tick()  # "sofort" ohne auf den Minuten-Tick zu warten
    await database.log_audit_event(
        "message_created", actor=_actor(user),
        details={"message_id": mid, "title": fields["title"], "severity": fields["severity"]},
    )
    return {"ok": True, "id": mid}


@router.get("/admin/api/messages/{message_id}", dependencies=[Depends(_require_admin)])
async def get_message(message_id: int):
    m = await database.get_message(message_id)
    if not m:
        raise HTTPException(status_code=404, detail="Mitteilung nicht gefunden")
    occs = await database.list_occurrences(message_id)
    out = _present({**m, "occurrence_count": len(occs),
                    "last_fire_at": occs[0]["fire_at"] if occs else None})
    seen = _receipt_agents(await database.list_message_receipts(message_id))
    out["occurrences"] = []
    for o in occs:
        targets = await messages.occurrence_targets(
            {**o, "target_group_id": m.get("target_group_id")}, seen.get(o["id"], ()))
        o = {k: v for k, v in o.items() if k != "target_ids"}
        out["occurrences"].append({
            **o, "target_count": len(targets),
            "fire_at_local": messages.utc_to_local_str(o["fire_at"]),
            "expires_at_local": messages.utc_to_local_str(o["expires_at"]),
        })
    ids = await _target_ids(m.get("target_group_id"))
    out["target_count"] = len(ids)
    out["old_tray_count"] = await _old_tray_count(ids)
    if m.get("target_group_id"):
        g = await database.get_target_group(m["target_group_id"])
        out["target_group_name"] = (g or {}).get("name")
    return out


@router.patch("/admin/api/messages/{message_id}", dependencies=[Depends(_require_admin)])
async def update_message(message_id: int, body: MessageBody, request: Request):
    user = await _require_admin(request)
    if not await database.get_message(message_id):
        raise HTTPException(status_code=404, detail="Mitteilung nicht gefunden")
    fields = await _validated(body)
    await database.update_message(message_id, **fields)
    await messages.tick()
    await database.log_audit_event(
        "message_updated", actor=_actor(user), details={"message_id": message_id},
    )
    return {"ok": True}


@router.post("/admin/api/messages/{message_id}/status", dependencies=[Depends(_require_admin)])
async def set_message_status(message_id: int, body: StatusBody, request: Request):
    user = await _require_admin(request)
    if body.status not in ("active", "paused", "cancelled"):
        raise HTTPException(status_code=400, detail="Ungültiger Status")
    m = await database.get_message(message_id)
    if not m:
        raise HTTPException(status_code=404, detail="Mitteilung nicht gefunden")
    if m["status"] == "cancelled":
        raise HTTPException(status_code=409, detail="Zurückgezogene Mitteilungen lassen sich nicht reaktivieren — bitte duplizieren.")
    await database.update_message(message_id, status=body.status)
    if body.status != "active":
        await database.expire_open_occurrences(message_id)
    else:
        await messages.tick()
    await database.log_audit_event(
        "message_status", actor=_actor(user),
        details={"message_id": message_id, "status": body.status},
    )
    return {"ok": True}


@router.post("/admin/api/messages/{message_id}/duplicate", dependencies=[Depends(_require_admin)])
async def duplicate_message(message_id: int, request: Request):
    user = await _require_admin(request)
    m = await database.get_message(message_id)
    if not m:
        raise HTTPException(status_code=404, detail="Mitteilung nicht gefunden")
    fields = {k: m[k] for k in ("header", "body", "severity", "link_url", "link_label",
                                "target_group_id", "schedule", "show_hours")}
    new_id = await database.create_message(
        **fields, title=(m["title"] + " (Kopie)")[:120],
        valid_from=messages.to_db(messages.now_utc()), valid_until=None,
        status="paused", created_by=_actor(user),
    )
    return {"ok": True, "id": new_id}


@router.get("/admin/api/messages/occurrences/{occurrence_id}", dependencies=[Depends(_require_admin)])
async def occurrence_receipts(occurrence_id: int):
    occ = await database.get_occurrence(occurrence_id)
    if not occ:
        raise HTTPException(status_code=404, detail="Ausgabe nicht gefunden")
    receipts = await database.list_receipts(occurrence_id)
    for r in receipts:
        for k in ("delivered_at", "shown_at", "acked_at"):
            r[k + "_local"] = messages.utc_to_local_str(r.get(k))
    seen = {r["agent_id"] for r in receipts}
    agents = {a["agent_id"]: a for a in await database.get_agents()}
    missing = sorted(agents[i]["hostname"] for i in await messages.occurrence_targets(occ)
                     if i not in seen and i in agents)
    return {"receipts": receipts, "missing": missing}


@router.get("/admin/api/messages/{message_id}/export.xlsx", dependencies=[Depends(_require_admin)])
async def export_message(message_id: int, request: Request):
    user = await _require_admin(request)
    m = await database.get_message(message_id)
    if not m:
        raise HTTPException(status_code=404, detail="Mitteilung nicht gefunden")
    occs = sorted(await database.list_occurrences(message_id, limit=100000), key=lambda o: o["fire_at"])
    receipts = await database.list_message_receipts(message_id)
    agents = {a["agent_id"]: a for a in await database.get_agents()}
    critical = m["severity"] == "kritisch"
    by_occ: dict[int, list[dict]] = {}
    for r in receipts:
        by_occ.setdefault(r["occurrence_id"], []).append(r)

    dt = messages.utc_to_local_dt
    occ_rows, rows = [], []
    for o in occs:
        recs = by_occ.get(o["id"], [])
        targets = await messages.occurrence_targets(
            {**o, "target_group_id": m.get("target_group_id")}, (r["agent_id"] for r in recs))
        fire = dt(o["fire_at"])
        occ_rows.append({
            "fire_at": fire, "expires_at": dt(o["expires_at"]), "targets": len(targets),
            "delivered": len({r["agent_id"] for r in recs if r.get("delivered_at")}),
            "shown": len({r["agent_id"] for r in recs if r.get("shown_at") or r.get("acked_at")}),
            "acked": len({r["agent_id"] for r in recs if r.get("acked_at")}),
        })
        for r in recs:
            a = agents.get(r["agent_id"], {})
            rows.append({
                "fire_at": fire, "hostname": a.get("hostname") or r["agent_id"], "user": r["win_user"] or "",
                "status": message_export.receipt_status(r, critical),
                "delivered_at": dt(r.get("delivered_at")), "shown_at": dt(r.get("shown_at")),
                "acked_at": dt(r.get("acked_at")), "tray": a.get("client_version") or "",
            })
        for aid in targets - {r["agent_id"] for r in recs}:
            a = agents.get(aid, {})
            rows.append({
                "fire_at": fire, "hostname": a.get("hostname") or aid, "user": "",
                "status": "Nicht zugestellt", "delivered_at": None, "shown_at": None,
                "acked_at": None, "tray": a.get("client_version") or "",
            })
    rows.sort(key=lambda x: (x["fire_at"], x["hostname"].lower(), x["user"].lower()))

    p = _present({**m, "occurrence_count": len(occs), "last_fire_at": occs[-1]["fire_at"] if occs else None})
    group = await database.get_target_group(m["target_group_id"]) if m.get("target_group_id") else None
    link = m.get("link_url") or ""
    if link and m.get("link_label"):
        link = f"{m['link_label']}: {link}"
    meta = [
        ("Titel", m["title"]),
        ("Kopfzeile", m["header"]),
        ("Text", m["body"] or ""),
        ("Stufe", message_export.SEVERITY_LABEL.get(m["severity"], m["severity"])),
        ("Link", link),
        ("Zielgruppe", (group or {}).get("name") or "Alle Geräte"),
        ("Zeitplan", p["schedule_text"]),
        ("Anzeigen ab", dt(m["valid_from"])),
        ("Gültig bis", dt(m.get("valid_until")) or "unbegrenzt"),
        ("Anzeigedauer", f"{m['show_hours']} Std. je Ausgabe"),
        ("Status", message_export.STATE_LABEL.get(p["state"], p["state"])),
        ("Angelegt von", m.get("created_by") or ""),
        ("Angelegt am", dt(m.get("created_at"))),
        ("Exportiert am", dt(messages.to_db(messages.now_utc()))),
    ]
    data = await asyncio.to_thread(message_export.build_workbook, meta, occ_rows, rows, critical)
    await database.log_audit_event(
        "message_exported", actor=_actor(user), details={"message_id": message_id},
    )
    fname = message_export.filename(message_id, m["title"], messages.now_utc().astimezone(messages.TZ))
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename=\"{fname}\"; filename*=UTF-8''{quote(fname)}"},
    )


# ── Zielgruppen ───────────────────────────────────────────────────────────────

async def _validated_group(body: TargetGroupBody) -> tuple[str, str, str]:
    if body.kind not in ("static", "dynamic"):
        raise HTTPException(status_code=400, detail="Ungültige Gruppenart")
    try:
        rules = messages.validate_rules(body.rules) if body.kind == "dynamic" else []
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    if body.kind == "dynamic" and not rules:
        raise HTTPException(status_code=400, detail="Mindestens eine Regel angeben")
    agent_ids = sorted(set(body.agent_ids)) if body.kind == "static" else []
    if body.kind == "static" and not agent_ids:
        raise HTTPException(status_code=400, detail="Mindestens ein Gerät auswählen")
    return body.kind, json.dumps(agent_ids), json.dumps(rules)


@router.get("/admin/api/target-groups", dependencies=[Depends(_require_admin)])
async def list_target_groups():
    out = []
    for g in await database.list_target_groups():
        g["agent_ids"] = json.loads(g.get("agent_ids") or "[]")
        g["rules"] = json.loads(g.get("rules") or "[]")
        members = await messages.group_members(g["id"])
        g["member_ids"] = sorted(members)  # Empfaengerliste im Mitteilungs-Editor
        g["member_count"] = len(members)
        out.append(g)
    return out


@router.post("/admin/api/target-groups/preview", dependencies=[Depends(_require_admin)])
async def preview_target_group(body: TargetGroupBody):
    kind, agent_ids, rules = await _validated_group(body)
    ids = await messages.evaluate(kind, json.loads(agent_ids), json.loads(rules))
    agents = {a["agent_id"]: a["hostname"] for a in await database.get_target_agents()}
    return {"count": len(ids), "hostnames": sorted(agents[i] for i in ids if i in agents),
            "agent_ids": sorted(i for i in ids if i in agents)}


@router.post("/admin/api/target-groups", dependencies=[Depends(_require_admin)])
async def create_target_group(body: TargetGroupBody, request: Request):
    user = await _require_admin(request)
    kind, agent_ids, rules = await _validated_group(body)
    try:
        gid = await database.create_target_group(body.name.strip(), kind, agent_ids, rules, _actor(user))
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(status_code=409, detail="Eine Zielgruppe mit diesem Namen existiert bereits.")
        logger.exception("Zielgruppe anlegen fehlgeschlagen")
        raise HTTPException(status_code=500, detail="Zielgruppe konnte nicht angelegt werden")
    await database.log_audit_event("target_group_created", actor=_actor(user),
                                   details={"id": gid, "name": body.name})
    return {"ok": True, "id": gid}


@router.patch("/admin/api/target-groups/{group_id}", dependencies=[Depends(_require_admin)])
async def update_target_group(group_id: int, body: TargetGroupBody, request: Request):
    user = await _require_admin(request)
    if not await database.get_target_group(group_id):
        raise HTTPException(status_code=404, detail="Zielgruppe nicht gefunden")
    kind, agent_ids, rules = await _validated_group(body)
    try:
        await database.update_target_group(group_id, body.name.strip(), kind, agent_ids, rules)
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(status_code=409, detail="Eine Zielgruppe mit diesem Namen existiert bereits.")
        logger.exception("Zielgruppe aendern fehlgeschlagen")
        raise HTTPException(status_code=500, detail="Zielgruppe konnte nicht gespeichert werden")
    await database.log_audit_event("target_group_updated", actor=_actor(user), details={"id": group_id})
    return {"ok": True}


@router.delete("/admin/api/target-groups/{group_id}", dependencies=[Depends(_require_admin)])
async def delete_target_group(group_id: int, request: Request):
    user = await _require_admin(request)
    if await database.count_messages_for_group(group_id):
        raise HTTPException(status_code=409, detail="Zielgruppe wird noch von Mitteilungen genutzt.")
    await database.delete_target_group(group_id)
    await database.log_audit_event("target_group_deleted", actor=_actor(user), details={"id": group_id})
    return {"ok": True}
