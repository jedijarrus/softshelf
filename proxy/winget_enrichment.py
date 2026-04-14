"""
winget Discovery Enrichment

Bonus-Feature für die Fleet-Discovery: nimmt die Tactical-software-scan
Display-Namen die in der Flotte installiert sind und versucht jeden gegen
das winget-Catalog-REST-Endpoint zu matchen. Ergebnis landet in
discovery_enrichment-Cache mit einem Confidence-Label.

Wird täglich vom APScheduler aufgerufen (`run_enrichment_job()`).

Confidence-Heuristik:
  high   – PackageName aus winget-Catalog matched exakt den normalisierten
           Display-Namen (lowercase, collapsed whitespace, Klammer-Suffixe
           entfernt).
  medium – Publisher kommt im Display-Namen vor UND Substring-Match auf
           PackageName.
  low    – Substring-Match ohne Publisher-Bestätigung.
  none   – Kein Treffer in manifestSearch.
"""
import asyncio
import logging
import re
from collections import Counter
from typing import Any

import database
import winget_catalog
from tactical_client import TacticalClient

logger = logging.getLogger("softshelf.winget.enrichment")

# Klammer-/Suffix-Cleanup für Normalisierung
_PAREN_RE = re.compile(r"\s*[\(\[].*?[\)\]]\s*")
_VERSION_TAIL_RE = re.compile(r"\s+\d+(\.\d+)+\S*\s*$")
_TRAILING_BITS_RE = re.compile(
    r"\s+(x86|x64|ia64|arm64|32-bit|64-bit|de-de|de|en-us|en|deutsch|german|english)\b",
    re.IGNORECASE,
)
_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_name(name: str) -> str:
    """
    Normalisiert einen Display-Namen für den Match-Vergleich.
    Entfernt Klammer-Suffixe, Versions-Tails und Locale-Marker.
    """
    if not name:
        return ""
    s = name.strip()
    # Mehrfach durchlaufen falls geschachtelt
    for _ in range(3):
        new = _PAREN_RE.sub(" ", s)
        if new == s:
            break
        s = new
    s = _VERSION_TAIL_RE.sub("", s)
    s = _TRAILING_BITS_RE.sub("", s)
    s = _WHITESPACE_RE.sub(" ", s).strip()
    return s.lower()


def _confidence_for_match(
    needle_display: str,
    needle_publisher: str,
    candidate_name: str,
    candidate_publisher: str,
) -> str:
    """Berechnet das Confidence-Label für einen einzelnen Catalog-Treffer."""
    nd = _normalize_name(needle_display)
    cn = _normalize_name(candidate_name)
    if not nd or not cn:
        return "none"

    # high: exakter normalisierter Match
    if nd == cn:
        return "high"

    # Beide Richtungen Substring
    contains = nd in cn or cn in nd
    if not contains:
        return "none"

    # Publisher-Vergleich (loose)
    pub_n = _normalize_name(needle_publisher)
    pub_c = _normalize_name(candidate_publisher)
    if pub_n and pub_c and (pub_n in pub_c or pub_c in pub_n):
        return "medium"

    return "low"


async def _match_display_name(
    display_name: str, publisher: str
) -> tuple[str | None, str]:
    """
    Sucht im Catalog einen passenden Treffer für einen Display-Namen.
    Returns: (winget_id_or_None, confidence)
    """
    normalized = _normalize_name(display_name)
    if not normalized:
        return None, "none"

    # Suche im Catalog. Wir nutzen den normalisierten Namen als Query —
    # das gibt die meisten relevanten Treffer.
    try:
        results = await winget_catalog.search(normalized, limit=10)
    except Exception as e:
        logger.warning("catalog search failed for %r: %s", display_name, e)
        return None, "none"

    if not results:
        return None, "none"

    # Ranke alle Treffer und nimm den besten
    best_id: str | None = None
    best_confidence_rank = 99
    confidence_order = {"high": 0, "medium": 1, "low": 2, "none": 99}

    for r in results:
        c = _confidence_for_match(
            display_name, publisher, r["name"], r["publisher"],
        )
        rank = confidence_order.get(c, 99)
        if rank < best_confidence_rank:
            best_confidence_rank = rank
            best_id = r["id"]
            best_confidence = c
            if rank == 0:
                break

    if best_id is None:
        return None, "none"
    return best_id, best_confidence


async def _collect_fleet_software() -> dict[str, dict[str, Any]]:
    """
    Holt von Tactical pro online-Agent die installierte Software-Liste und
    aggregiert über die Flotte zu einem dict[normalized_name → {display_name,
    publisher, count}]. Verwendet `agents.last_seen` als Online-Filter.
    """
    candidates = await database.get_agents_due_for_scan(
        online_threshold_seconds=300
    )
    if not candidates:
        return {}

    agg: dict[str, dict[str, Any]] = {}
    sem = asyncio.Semaphore(15)
    tactical = TacticalClient()

    async def _fetch(agent: dict):
        async with sem:
            try:
                items = await tactical.get_installed_software(agent["agent_id"])
            except Exception as e:
                logger.warning(
                    "tactical software-scan failed for %s: %s",
                    agent.get("agent_id"), e,
                )
                return []
            return items or []

    results = await asyncio.gather(
        *(_fetch(a) for a in candidates),
        return_exceptions=False,
    )

    for items in results:
        for item in items:
            if not isinstance(item, dict):
                continue
            display_name = (item.get("name") or "").strip()
            if not display_name or len(display_name) > 200:
                continue
            publisher = (item.get("publisher") or "").strip()
            key = _normalize_name(display_name)
            if not key:
                continue
            if key not in agg:
                agg[key] = {
                    "display_name": display_name,
                    "publisher":    publisher,
                    "count":        0,
                }
            agg[key]["count"] += 1
            # Erste Variante mit gefülltem Publisher behalten
            if publisher and not agg[key]["publisher"]:
                agg[key]["publisher"] = publisher

    return agg


async def run_enrichment_job(
    rate_limit_per_sec: float = 5.0,
) -> dict[str, Any]:
    """
    Täglicher Enrichment-Job:
      1. Tactical-software-scan über alle online Agents → fleet histogram
      2. Reset aller install_counts
      3. Pro distinct display_name: catalog match → upsert mit count
      4. Cleanup stale entries

    Rate-Limiting gegen das öffentliche Microsoft-Endpoint:
    `rate_limit_per_sec` requests pro Sekunde im Mittel.
    """
    fleet = await _collect_fleet_software()
    if not fleet:
        logger.info("enrichment job: no fleet software collected")
        return {"items": 0, "matched": 0, "skipped": 0}

    logger.info("enrichment job: %d distinct display names from fleet", len(fleet))

    # Liste der bereits whitelisteten winget_ids — die brauchen wir nicht zu
    # matchen, denn sie können eh nicht in Discovery auftauchen.
    whitelisted = await database.get_whitelisted_winget_ids()

    await database.reset_enrichment_counts()

    # Einfache Rate-Begrenzung: warte zwischen Calls
    delay = 1.0 / max(rate_limit_per_sec, 0.1)
    matched = 0
    skipped = 0

    for key, info in fleet.items():
        display = info["display_name"]
        publisher = info["publisher"]
        count = info["count"]

        # Cache-Hit prüfen — wenn der Eintrag aktuell und nicht-stale ist,
        # nur den count updaten ohne erneuten Catalog-Call
        cached = await database.get_enrichment(display)
        if cached and cached.get("checked_at"):
            # checked_at als String aus SQLite — vergleichen mit "-7 days"
            # via DB-Side wäre ideal, aber wir machen einen einfachen
            # Re-Lookup wenn entweder kein winget_id da ist oder stale.
            # Hier vereinfacht: wenn winget_id in whitelist, einfach skip.
            if cached.get("winget_id") and cached["winget_id"] in whitelisted:
                # Whitelisted — wir tracken den count trotzdem nicht weiter,
                # weil das Discovery-UI ohnehin whitelisted Treffer rausfiltert.
                # Trotzdem upserten damit checked_at frisch ist.
                await database.upsert_enrichment(
                    display, cached["winget_id"], cached["confidence"], count,
                )
                skipped += 1
                continue

        # Catalog-Match mit Rate-Limit
        winget_id, confidence = await _match_display_name(display, publisher)
        await database.upsert_enrichment(display, winget_id, confidence, count)
        if winget_id:
            matched += 1
        await asyncio.sleep(delay)

    await database.cleanup_stale_enrichment(days=30)

    logger.info(
        "enrichment job done: %d items, %d matched, %d skipped (whitelisted)",
        len(fleet), matched, skipped,
    )
    return {
        "items":   len(fleet),
        "matched": matched,
        "skipped": skipped,
    }
