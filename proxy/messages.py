"""
Mitteilungen an Benutzer (v2.10).

- Zielgruppen: statisch (feste Agent-Liste) oder dynamisch (Regeln ueber den
  Softwarestand, UND-verknuepft). Dynamische Gruppen werden beim Zustellen
  ausgewertet, nicht vorab materialisiert — "Postman veraltet" verschwindet
  von selbst, sobald das Geraet aktualisiert ist.
- Zeitplan: einmalig / taeglich / woechentlich / monatlich in Europe/Berlin.
  Jeder Termin wird eine eigene Ausgabe (message_occurrences) mit eigenen
  Quittungen. tick() legt faellige Ausgaben an (APScheduler, jede Minute).
- Zustellung: GET /api/v1/health liefert pending_for_agent() mit; der Tray
  meldet shown/acked ueber /api/v1/messages/{occurrence_id}/receipt.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import database
from winget_catalog import is_outdated

logger = logging.getLogger(__name__)

TZ = ZoneInfo("Europe/Berlin")
SEVERITIES = ("info", "wichtig", "kritisch")
SCHEDULE_MODES = ("once", "daily", "weekly", "monthly")
RULE_TYPES = (
    "installed", "not_installed", "outdated", "version_lt",
    "tray_lt", "profile", "ring", "hostname",
)
_DB_FMT = "%Y-%m-%d %H:%M:%S"
_MAX_PENDING = 5


# ── Zeit-Helfer ───────────────────────────────────────────────────────────────

def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def to_db(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(_DB_FMT)


def from_db(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.strptime(s[:19], _DB_FMT).replace(tzinfo=timezone.utc)


def local_to_utc(s: str) -> datetime:
    """'2026-10-27T09:00' (datetime-local aus dem Admin-UI, Europe/Berlin) → UTC."""
    dt = datetime.fromisoformat(s.strip()[:16])
    return dt.replace(tzinfo=TZ).astimezone(timezone.utc)


def utc_to_local_str(s: str | None) -> str | None:
    dt = from_db(s)
    return dt.astimezone(TZ).strftime("%Y-%m-%dT%H:%M") if dt else None


def utc_to_local_dt(s: str | None) -> datetime | None:
    """Naive Ortszeit (Europe/Berlin), z. B. fuer Excel-Datumszellen."""
    dt = from_db(s)
    return dt.astimezone(TZ).replace(tzinfo=None) if dt else None


# ── Zeitplan ──────────────────────────────────────────────────────────────────

def validate_schedule(sched: dict) -> dict:
    """Normalisiert + prueft einen Zeitplan. ValueError mit deutschem Text."""
    mode = sched.get("mode", "once")
    if mode not in SCHEDULE_MODES:
        raise ValueError("Unbekannter Zeitplan")
    if mode == "once":
        return {"mode": "once"}
    t = str(sched.get("time") or "09:00")
    try:
        hh, mm = (int(x) for x in t.split(":"))
        assert 0 <= hh < 24 and 0 <= mm < 60
    except Exception:
        raise ValueError("Uhrzeit im Format HH:MM angeben")
    out = {"mode": mode, "time": f"{hh:02d}:{mm:02d}"}
    if mode == "daily":
        out["weekdays_only"] = bool(sched.get("weekdays_only"))
    elif mode == "weekly":
        days = sorted({int(d) for d in sched.get("days") or []})
        if not days or any(d < 0 or d > 6 for d in days):
            raise ValueError("Mindestens einen Wochentag wählen")
        out["days"] = days
    elif mode == "monthly":
        if sched.get("nth"):
            nth, wd = int(sched["nth"]), int(sched.get("weekday", 0))
            if not (1 <= nth <= 4 and 0 <= wd <= 6):
                raise ValueError("Ungültiger Monatstermin")
            out.update(nth=nth, weekday=wd)
        else:
            day = int(sched.get("day") or 1)
            if not 1 <= day <= 28:
                raise ValueError("Monatstag 1–28 wählen")
            out["day"] = day
    return out


def _day_matches(sched: dict, d) -> bool:
    mode = sched["mode"]
    if mode == "daily":
        return not sched.get("weekdays_only") or d.weekday() < 5
    if mode == "weekly":
        return d.weekday() in sched["days"]
    if mode == "monthly":
        if "nth" in sched:
            return d.weekday() == sched["weekday"] and (d.day - 1) // 7 + 1 == sched["nth"]
        return d.day == sched["day"]
    return False


def next_fire_after(sched: dict, after: datetime) -> datetime | None:
    """Naechster Termin strikt nach `after` (UTC). None bei 'once'."""
    if sched.get("mode") == "once":
        return None
    hh, mm = (int(x) for x in sched["time"].split(":"))
    local_after = after.astimezone(TZ)
    day = local_after.date()
    for _ in range(400):
        if _day_matches(sched, day):
            cand = datetime(day.year, day.month, day.day, hh, mm, tzinfo=TZ).astimezone(timezone.utc)
            if cand > after:
                return cand
        day += timedelta(days=1)
    return None


def describe_schedule(sched: dict) -> str:
    mode = sched.get("mode", "once")
    if mode == "once":
        return "Einmalig"
    names = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"]
    t = sched.get("time", "")
    if mode == "daily":
        return f"Werktags {t}" if sched.get("weekdays_only") else f"Täglich {t}"
    if mode == "weekly":
        return f"Wöchentlich {', '.join(names[d] for d in sched.get('days', []))} {t}"
    if "nth" in sched:
        return f"Monatlich {sched['nth']}. {names[sched['weekday']]} {t}"
    return f"Monatlich am {sched.get('day')}. {t}"


# ── Ausgaben anlegen (Scheduler) ──────────────────────────────────────────────

async def tick():
    """Legt faellige Ausgaben an. Idempotent; nach Ausfallzeit wird nur der
    juengste verpasste Termin nachgeholt (keine Flut alter Ausgaben)."""
    now = now_utc()
    for m in await database.list_active_messages():
        try:
            vf = from_db(m["valid_from"])
            vu = from_db(m.get("valid_until"))
            if not vf or now < vf:
                continue
            try:
                sched = json.loads(m.get("schedule") or "{}")
            except Exception:
                sched = {"mode": "once"}
            show = timedelta(hours=max(1, int(m.get("show_hours") or 24)))
            last = await database.get_last_occurrence(m["id"])

            if sched.get("mode", "once") == "once":
                if last:
                    continue
                due = vf
            else:
                base = from_db(last["fire_at"]) if last else vf - timedelta(seconds=1)
                due, cand = None, next_fire_after(sched, base)
                for _ in range(400):
                    if not cand or cand > now:
                        break
                    due, cand = cand, next_fire_after(sched, cand)
                if not due or (vu and due > vu):
                    continue

            expires = due + show
            if vu and expires > vu:
                expires = vu
            if expires <= now:
                continue
            snapshot = json.dumps(sorted(await target_ids(m.get("target_group_id"))))
            occ = await database.create_occurrence(m["id"], to_db(due), to_db(expires), snapshot)
            if occ:
                logger.info("Mitteilung %d: Ausgabe %d (%s bis %s)",
                            m["id"], occ, to_db(due), to_db(expires))
        except Exception:
            logger.exception("Mitteilung %s: tick fehlgeschlagen", m.get("id"))


# ── Zielgruppen ───────────────────────────────────────────────────────────────

def validate_rules(rules: list) -> list[dict]:
    out = []
    for r in rules or []:
        t = r.get("type")
        if t not in RULE_TYPES:
            raise ValueError(f"Unbekannte Regel: {t}")
        item: dict = {"type": t}
        if t in ("installed", "not_installed", "outdated", "version_lt"):
            ident = str(r.get("ident") or "").strip()
            if not ident or len(ident) > 200:
                raise ValueError("Software-ID fehlt")
            item["ident"] = ident
        if t in ("version_lt", "tray_lt"):
            v = str(r.get("version") or "").strip()
            if not v or len(v) > 50:
                raise ValueError("Version fehlt")
            item["version"] = v
        if t == "profile":
            item["profile_id"] = int(r.get("profile_id"))
        if t == "ring":
            item["ring"] = int(r.get("ring"))
        if t == "hostname":
            p = str(r.get("pattern") or "").strip()
            if not p or len(p) > 100:
                raise ValueError("Hostname-Muster fehlt")
            item["pattern"] = p
        out.append(item)
    return out


async def _rule_agents(rule: dict, agents: list[dict]) -> set[str]:
    t = rule["type"]
    all_ids = {a["agent_id"] for a in agents}
    if t in ("installed", "not_installed", "outdated", "version_lt"):
        rows = await database.get_software_rows(rule["ident"])
        if t == "installed":
            return {r["agent_id"] for r in rows} & all_ids
        if t == "not_installed":
            return all_ids - {r["agent_id"] for r in rows}
        if t == "outdated":
            hit = set()
            for r in rows:
                if r["source"] == "custom":
                    if r.get("custom_outdated"):
                        hit.add(r["agent_id"])
                elif is_outdated(r.get("installed_version"), r.get("available_version")):
                    hit.add(r["agent_id"])
            return hit & all_ids
        return {r["agent_id"] for r in rows
                if is_outdated(r.get("installed_version"), rule["version"])} & all_ids
    if t == "tray_lt":
        return {a["agent_id"] for a in agents
                if not a.get("client_version") or is_outdated(a["client_version"], rule["version"])}
    if t == "profile":
        return await database.get_profile_agent_ids(rule["profile_id"]) & all_ids
    if t == "ring":
        return {a["agent_id"] for a in agents if a.get("ring") == rule["ring"]}
    if t == "hostname":
        pat = rule["pattern"].lower()
        return {a["agent_id"] for a in agents if fnmatch.fnmatch((a["hostname"] or "").lower(), pat)}
    return set()


async def evaluate(kind: str, agent_ids: list[str], rules: list[dict]) -> set[str]:
    agents = await database.get_target_agents()
    if kind == "static":
        return set(agent_ids) & {a["agent_id"] for a in agents}
    result = {a["agent_id"] for a in agents}
    for rule in rules:
        result &= await _rule_agents(rule, agents)
        if not result:
            break
    return result


_group_cache: dict[int, tuple[float, str, set[str]]] = {}
_GROUP_TTL = 60.0


async def group_members(group_id: int) -> set[str]:
    """Mitglieder einer Zielgruppe, 60 s gecacht (Health-Poll-Pfad)."""
    g = await database.get_target_group(group_id)
    if not g:
        return set()
    hit = _group_cache.get(group_id)
    if hit and hit[1] == g["updated_at"] and time.monotonic() - hit[0] < _GROUP_TTL:
        return hit[2]
    members = await evaluate(
        g["kind"], json.loads(g.get("agent_ids") or "[]"), json.loads(g.get("rules") or "[]"),
    )
    _group_cache[group_id] = (time.monotonic(), g["updated_at"], members)
    return members


async def _targets_agent(target_group_id: int | None, agent_id: str) -> bool:
    if target_group_id is None:
        return True
    return agent_id in await group_members(target_group_id)


async def target_ids(target_group_id: int | None) -> set[str]:
    """Aktuelle Zielgeraete: alle nicht gesperrten oder die Gruppenmitglieder."""
    if target_group_id is None:
        return {a["agent_id"] for a in await database.get_target_agents()}
    return await group_members(target_group_id)


async def occurrence_targets(occ: dict, receipt_agent_ids=()) -> set[str]:
    """Zielgeraete einer Ausgabe: Snapshot vom Ausgabezeitpunkt plus alle Geraete
    mit Rueckmeldung (spaeter dazugekommene Gruppenmitglieder bekommen die
    Ausgabe auch). Ausgaben vor v2.11 haben keinen Snapshot -> aktuelle Gruppe."""
    raw = occ.get("target_ids")
    if raw:
        try:
            ids = set(json.loads(raw))
        except (ValueError, TypeError):
            ids = await target_ids(occ.get("target_group_id"))
    else:
        ids = await target_ids(occ.get("target_group_id"))
    return ids | set(receipt_agent_ids)


# ── Zustellung ────────────────────────────────────────────────────────────────

def _payload(o: dict) -> dict:
    return {
        "id": o["occurrence_id"],
        "header": o.get("header") or "",
        "title": o.get("title") or "",
        "body": o.get("body") or "",
        "severity": o.get("severity") or "info",
        "link_url": o.get("link_url") or "",
        "link_label": o.get("link_label") or "",
        "fire_at": o.get("fire_at"),
    }


async def pending_for_agent(agent_id: str, win_user: str) -> list[dict]:
    """Offene Mitteilungen fuer Geraet+User: Info/Wichtig bis gesehen,
    Kritisch bis bestaetigt. Markiert neu zugestellte als delivered."""
    live = [o for o in await database.get_live_occurrences()
            if await _targets_agent(o.get("target_group_id"), agent_id)]
    if not live:
        return []
    receipts = await database.get_receipts_for_user(
        agent_id, win_user, [o["occurrence_id"] for o in live])
    out = []
    for o in live:
        rc = receipts.get(o["occurrence_id"])
        done = rc and (rc.get("acked_at") if o["severity"] == "kritisch" else rc.get("shown_at"))
        if done:
            continue
        if not rc:
            await database.touch_receipt(o["occurrence_id"], agent_id, win_user, "delivered")
        out.append(_payload(o))
        if len(out) >= _MAX_PENDING:
            break
    return out


async def record_receipt(agent_id: str, win_user: str, occurrence_id: int, event: str) -> bool:
    """Quittung vom Tray. False = Ausgabe unbekannt oder nicht fuer dieses Geraet."""
    if event not in ("shown", "acked"):
        return False
    occ = await database.get_occurrence(occurrence_id)
    if not occ or not await _targets_agent(occ.get("target_group_id"), agent_id):
        return False
    await database.touch_receipt(occurrence_id, agent_id, win_user, event)
    return True


async def history_for_agent(agent_id: str, win_user: str) -> list[dict]:
    rows = await database.get_message_history_for_user(agent_id, win_user)
    return [{**_payload(r), "shown": bool(r.get("shown_at")), "acked": bool(r.get("acked_at"))}
            for r in rows]
