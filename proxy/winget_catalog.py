"""
winget Catalog Wrapper

Lädt die offizielle Microsoft winget-Source-Datei (`source.msix` von
`cdn.winget.microsoft.com/cache/`) einmal pro Tag und queryed die darin
enthaltene SQLite-Index-DB lokal. Das ist die selbe Datei die `winget`
auf jeder Windows-Maschine periodisch zieht — wir umgehen damit komplett
den Tactical-Round-Trip für Catalog-Suchen und bekommen den vollständigen
winget-Source (im Gegensatz zum öffentlichen storeedgefd-Endpoint, das
nur MSStore-Pakete liefert die meist user-scope-only sind).

Cache:
  - Pfad: /app/data/winget_index.db (im Docker-Volume, persistent)
  - TTL:  24 Stunden (passt zum APScheduler-Daily-Job)

Query-API:
  - search(query, limit)  → Liste von dicts mit id/name/publisher/latest_version
  - get_details(id)       → Einzelner dict mit derselben Struktur, oder None
"""
import asyncio
import io
import logging
import os
import re
import sqlite3
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("softshelf.winget.catalog")

# Microsoft CDN URL des offiziellen winget-Source-Caches
_CATALOG_URL = "https://cdn.winget.microsoft.com/cache/source.msix"

# winget-PackageIdentifiers von Software die von Windows / Microsoft Update
# gepflegt wird und sich NICHT via `winget upgrade` in-place updaten lässt.
# Symptom wenn man's trotzdem versucht:
#   - „A newer version was found, but the install technology is different
#     from the current version installed."
#   - Exit-Code -1978335189 (INSTALL_NOTHING_TO_UPGRADE) trotz vorhandenem
#     update.
# Diese Pakete bekommen NIE ein "Update verfügbar"-Flag in der Kiosk-Sicht
# und im Admin-Detail. Sie tauchen weiterhin in der installierten Software-
# Liste auf, aber als „wird über Microsoft Update gepflegt".
WINGET_OS_MANAGED = frozenset({
    "Microsoft.Edge",
    "Microsoft.EdgeWebView2Runtime",
    "Microsoft.OneDrive",
    "Microsoft.Office",
    "Microsoft.Office365",
    "Microsoft.365.Apps",
    "Microsoft.VSTOR",
    "Microsoft.VSTOR2010",
    "Microsoft.VisualStudio.2010.OfficeRuntime",
    "Microsoft.Teams",
    "Microsoft.Teams.Classic",
    "Microsoft.MSStore",
    "Microsoft.WindowsTerminal",
    "Microsoft.WindowsStore",
    "Microsoft.PowerShell",
    "Microsoft.DotNet.Runtime.6",
    "Microsoft.DotNet.Runtime.7",
    "Microsoft.DotNet.Runtime.8",
    "Microsoft.DotNet.DesktopRuntime.6",
    "Microsoft.DotNet.DesktopRuntime.7",
    "Microsoft.DotNet.DesktopRuntime.8",
    "Microsoft.DotNet.AspNetCore.6",
    "Microsoft.DotNet.AspNetCore.7",
    "Microsoft.DotNet.AspNetCore.8",
    "Microsoft.VCRedist.2010.x64",
    "Microsoft.VCRedist.2010.x86",
    "Microsoft.VCRedist.2012.x64",
    "Microsoft.VCRedist.2012.x86",
    "Microsoft.VCRedist.2013.x64",
    "Microsoft.VCRedist.2013.x86",
    "Microsoft.VCRedist.2015+.x64",
    "Microsoft.VCRedist.2015+.x86",
})


def is_os_managed(winget_id: str) -> bool:
    """True wenn das Paket zu der Liste OS-managed Microsoft-Pakete gehört
    die nicht via winget in-place upgradable sind. Verwendet in packages.py
    und routes/admin.py um available_version/update_available zu unterdrücken."""
    return (winget_id or "") in WINGET_OS_MANAGED

# Wir cachen die extrahierte SQLite im Docker-data-Volume damit der Cache
# Container-Restarts überlebt
_CACHE_DIR = Path(os.environ.get("WINGET_CACHE_DIR") or "/app/data")
_CACHE_DB = _CACHE_DIR / "winget_index.db"

# Cache-TTL: 24 Stunden — passend zum APScheduler-Daily-Refresh
_CACHE_TTL_SECONDS = 24 * 3600

# Lock damit nicht zwei concurrent Refreshes parallel die Datei zerschießen
_refresh_lock = asyncio.Lock()


def _cache_age_seconds() -> float:
    """Alter des Cache-Files in Sekunden. inf wenn nicht vorhanden."""
    try:
        st = _CACHE_DB.stat()
    except FileNotFoundError:
        return float("inf")
    return time.time() - st.st_mtime


def _is_fresh() -> bool:
    return _cache_age_seconds() < _CACHE_TTL_SECONDS


async def refresh_cache(force: bool = False) -> bool:
    """
    Lädt source.msix runter und extrahiert Public/index.db nach _CACHE_DB.
    Idempotent — bei nicht-stale Cache ein no-op (außer force=True).

    Returns True wenn der Cache nach dem Aufruf fresh ist, False bei
    Download-/Extract-Fehler.
    """
    if not force and _is_fresh():
        return True
    async with _refresh_lock:
        if not force and _is_fresh():
            return True
        logger.info("downloading winget source from %s", _CATALOG_URL)
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as c:
                r = await c.get(_CATALOG_URL)
                r.raise_for_status()
                msix_bytes = r.content
        except httpx.HTTPError as e:
            logger.warning("winget source download failed: %s", e)
            return False
        try:
            with zipfile.ZipFile(io.BytesIO(msix_bytes)) as z:
                db_bytes = z.read("Public/index.db")
        except (zipfile.BadZipFile, KeyError) as e:
            logger.warning("winget source extract failed: %s", e)
            return False
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp_path = _CACHE_DB.with_suffix(".db.tmp")
        try:
            tmp_path.write_bytes(db_bytes)
            tmp_path.replace(_CACHE_DB)
        except OSError as e:
            logger.warning("winget cache write failed: %s", e)
            return False
        logger.info(
            "winget source cached: %d bytes (msix), %d bytes (db)",
            len(msix_bytes), len(db_bytes),
        )
        return True


async def _ensure_cache() -> bool:
    """Stellt sicher, dass _CACHE_DB existiert und fresh ist. Returns False
    wenn der Cache unbenutzbar ist (Download fehlgeschlagen UND keine alte
    Datei vorhanden)."""
    if _is_fresh():
        return True
    ok = await refresh_cache()
    if ok:
        return True
    # Stale aber existierend → wir nutzen die alte Datei trotzdem
    return _CACHE_DB.exists()


def _publisher_from_id(package_id: str) -> str:
    """Leitet den Publisher aus der PackageIdentifier ab.

    PackageIdentifiers folgen dem Schema 'Publisher.Name' oder
    'Publisher.Name.Variant'. Wir nehmen den Teil vor dem ersten Punkt.
    """
    if "." in package_id:
        return package_id.split(".", 1)[0]
    return ""


_VERSION_PART_RE = re.compile(r"^(\d+)(.*)$")


def _version_key(version: str) -> tuple:
    """Best-effort semver-Sort-Key. Vergleicht Versions-Strings nach
    semantischen Regeln: numerische Komponenten werden numerisch verglichen,
    nicht lex (so dass "100.0" > "99.0.1" gilt). Reine Strings sortieren
    nach allen numerischen Komponenten."""
    parts = []
    for segment in (version or "").split("."):
        m = _VERSION_PART_RE.match(segment)
        if m:
            parts.append((0, int(m.group(1)), m.group(2)))
        else:
            parts.append((1, 0, segment))
    return tuple(parts)


def _latest_version(versions: list[str]) -> str:
    """Wählt aus einer Liste Versions-Strings die größte (semver-aware)."""
    if not versions:
        return ""
    try:
        return max(versions, key=_version_key)
    except Exception:
        return versions[0]


def _query_search(query: str, limit: int) -> list[dict[str, Any]]:
    """Synchroner SQLite-Query gegen den lokalen Cache."""
    if not _CACHE_DB.exists():
        return []
    norm = (query or "").lower().strip()
    if not norm:
        return []
    pattern_substr = f"%{norm}%"
    pattern_prefix = f"{norm}%"
    pattern_id_suffix = f"%.{norm}"
    pattern_id_prefix_seg = f"{norm}.%"

    conn = sqlite3.connect(str(_CACHE_DB))
    try:
        cur = conn.cursor()
        # Schritt 1: passende IDs finden + ranken. Wir nehmen pro ID irgendeinen
        # Repräsentanten (max manifest rowid) nur damit die Joins für die
        # Sortierung funktionieren — die Version-Spalte ignorieren wir hier.
        # Ranking-Strategie:
        #   0 = exakter Id- oder Name-Match
        #   1 = Last-Segment der Id matched (z. B. "firefox" → "Mozilla.Firefox")
        #   1 = First-Segment der Id matched (Publisher-Match)
        #   2 = Name beginnt mit Query
        #   3 = Id beginnt mit Query
        #   4 = sonst (Substring-Match)
        cur.execute(
            """
            SELECT i.id, n.name
            FROM manifest m
            JOIN ids   i ON i.rowid = m.id
            JOIN names n ON n.rowid = m.name
            WHERE m.rowid IN (
                SELECT MAX(rowid) FROM manifest GROUP BY id
            )
            AND (LOWER(i.id) LIKE :pat OR LOWER(n.name) LIKE :pat)
            ORDER BY
                CASE
                    WHEN LOWER(i.id)   = :exact THEN 0
                    WHEN LOWER(n.name) = :exact THEN 0
                    WHEN LOWER(i.id)   LIKE :id_suffix THEN 1
                    WHEN LOWER(i.id)   LIKE :id_prefix_seg THEN 1
                    WHEN LOWER(n.name) LIKE :prefix THEN 2
                    WHEN LOWER(i.id)   LIKE :prefix THEN 3
                    ELSE 4
                END,
                i.id
            LIMIT :limit
            """,
            {
                "pat":             pattern_substr,
                "exact":           norm,
                "id_suffix":       pattern_id_suffix,
                "id_prefix_seg":   pattern_id_prefix_seg,
                "prefix":          pattern_prefix,
                "limit":           max(1, min(limit, 100)),
            },
        )
        ranked = cur.fetchall()

        # Schritt 2: für jeden gerankten Treffer die echte neueste Version per
        # semver-Vergleich nachziehen. SQLite hat keine semver-Sortierung, also
        # holen wir alle Versionen pro ID und picken die größte in Python.
        results = []
        for pid, name in ranked:
            cur.execute(
                """
                SELECT v.version
                FROM manifest m
                JOIN ids i ON i.rowid = m.id
                JOIN versions v ON v.rowid = m.version
                WHERE i.id = ?
                """,
                (pid,),
            )
            versions = [r[0] for r in cur.fetchall() if r[0]]
            latest = _latest_version(versions)
            results.append({
                "id":             pid,
                "name":           name or pid,
                "publisher":      _publisher_from_id(pid),
                "latest_version": latest,
                "source":         "winget",
            })
    finally:
        conn.close()

    return results


def _query_details(package_id: str) -> dict[str, Any] | None:
    if not _CACHE_DB.exists():
        return None
    pid = (package_id or "").strip()
    if not pid:
        return None
    conn = sqlite3.connect(str(_CACHE_DB))
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT i.id, n.name, v.version
            FROM manifest m
            JOIN ids   i ON i.rowid = m.id
            JOIN names n ON n.rowid = m.name
            JOIN versions v ON v.rowid = m.version
            WHERE LOWER(i.id) = LOWER(?)
            """,
            (pid,),
        )
        rows = cur.fetchall()
    finally:
        conn.close()
    if not rows:
        return None
    real_id = rows[0][0]
    real_name = next((r[1] for r in rows if r[1]), real_id)
    versions = [r[2] for r in rows if r[2]]
    return {
        "id":             real_id,
        "name":           real_name,
        "publisher":      _publisher_from_id(real_id),
        "latest_version": _latest_version(versions),
        "source":         "winget",
    }


async def search(query: str, limit: int = 30) -> list[dict[str, Any]]:
    """Sucht im Microsoft winget-Catalog. Triggert bei Bedarf einen
    Cache-Refresh."""
    q = (query or "").strip()
    if not q:
        return []
    ok = await _ensure_cache()
    if not ok:
        logger.warning("winget catalog cache unavailable")
        return []
    return await asyncio.to_thread(_query_search, q, limit)


async def get_details(package_id: str) -> dict[str, Any] | None:
    """Holt die Details zu einer spezifischen PackageIdentifier."""
    pid = (package_id or "").strip()
    if not pid:
        return None
    ok = await _ensure_cache()
    if not ok:
        return None
    return await asyncio.to_thread(_query_details, pid)
