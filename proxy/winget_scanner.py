"""
winget Scanner

Triggert via Tactical-`run_command` einen `winget list` und `winget upgrade`
auf einem Windows-Agent, parsed das Text-Output und schreibt das Ergebnis
in `agent_winget_state` + `agent_scan_meta`.

Zwei Entry-Points:
  - scan_agent(agent_id)        → Targeted Re-Scan eines einzelnen Agents
                                  (z. B. nach einer User-Aktion im Kiosk)
  - run_nightly_scan()          → Fleet-wide Batch via APScheduler
                                  (Pre-Filter via kiosk-client last_seen,
                                   Semaphore-bounded Concurrency)

Parser-Strategie:
  Windows PowerShell 5.1 (auf jedem Win11 vorhanden). Buffer-Breite wird auf
  512 chars aufgerissen damit winget lange Namen/IDs nicht mit '…' truncated.
  Header-Zeile wird über die `---`-Trennzeile lokalisiert (sprachunabhängig).
  Spalten-Offsets aus dem Header dynamisch ermittelt, dann Substring-Slice
  pro Datenzeile. Truncation wird erkannt und als Scan-Warning markiert.
"""
import asyncio
import json
import logging
import re
from typing import Any

import database
from tactical_client import TacticalClient

logger = logging.getLogger("softshelf.winget.scanner")


# ── PowerShell-Skript für den Scan ────────────────────────────────────────────

_SCAN_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Buffer-Breite aufreissen, damit winget lange Namen/IDs nicht abkuerzt.
try {
    $raw = $Host.UI.RawUI
    $sz  = $raw.BufferSize
    $sz.Width = 512
    $raw.BufferSize = $sz
} catch {}
$env:COLUMNS = 512

$wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
if (-not $wingetCmd) {
    $err = @{ ok = $false; error = 'winget_not_installed' } | ConvertTo-Json -Compress
    Write-Output $err
    exit 0
}

try {
    $installed  = (& winget list    --source winget --accept-source-agreements --disable-interactivity 2>&1) -join "`n"
} catch {
    $installed = ""
}
try {
    $upgradable = (& winget upgrade --source winget --accept-source-agreements --disable-interactivity 2>&1) -join "`n"
} catch {
    $upgradable = ""
}

$result = @{
    ok         = $true
    installed  = $installed
    upgradable = $upgradable
} | ConvertTo-Json -Compress

Write-Output $result
"""


# ── Text-Parser ───────────────────────────────────────────────────────────────


_ELLIPSIS = "\u2026"  # ...


def _find_header_and_offsets(text: str) -> tuple[list[str], list[int], int] | None:
    """
    Findet die Header-Zeile + Spalten-Offsets im winget-Text-Output.

    Strategie: suche eine Zeile die zu mindestens 80 % aus '-' und Whitespace
    besteht (das ist die Trennzeile direkt unter dem Header). Die Zeile direkt
    darüber ist dann der Header. Aus dem Header lesen wir die Spalten-Namen
    und ihre Byte-Offsets.

    Returns: (column_names, column_offsets, line_index_of_first_data_row)
    oder None wenn keine Tabelle gefunden wurde.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if i == 0:
            continue
        stripped = line.strip()
        if len(stripped) < 4:
            continue
        # Zähle '-' Anteil ignoriere Whitespace
        non_space = [c for c in stripped if c != " "]
        if not non_space:
            continue
        dash_ratio = sum(1 for c in non_space if c == "-") / len(non_space)
        if dash_ratio < 0.8:
            continue
        # Diese Zeile ist die Trennzeile. Header ist eine Zeile drüber.
        header_line = lines[i - 1]
        # Spalten-Offsets ermitteln: jede Spalte beginnt da wo nach einem
        # Leerzeichen ein Nicht-Leerzeichen folgt.
        offsets: list[int] = []
        names: list[str] = []
        in_word = False
        word_start = 0
        for j, ch in enumerate(header_line):
            if not ch.isspace() and not in_word:
                in_word = True
                word_start = j
                offsets.append(j)
            elif ch.isspace() and in_word:
                in_word = False
                names.append(header_line[word_start:j].strip())
        if in_word:
            names.append(header_line[word_start:].strip())
        if len(names) < 2 or len(offsets) != len(names):
            continue
        return names, offsets, i + 1
    return None


def _slice_row(line: str, offsets: list[int]) -> list[str]:
    """Schneidet eine Datenzeile anhand der Header-Offsets in Felder."""
    fields = []
    for k, start in enumerate(offsets):
        end = offsets[k + 1] if k + 1 < len(offsets) else len(line)
        if start >= len(line):
            fields.append("")
        else:
            fields.append(line[start:end].strip())
    return fields


def _parse_winget_table(text: str) -> tuple[list[dict[str, str]], list[str]]:
    """
    Parsed eine winget list / winget upgrade Text-Tabelle.

    Returns: (rows, warnings). Jede row ist ein dict mit den Header-Spalten als
    Keys (z. B. 'Name', 'Id', 'Version', 'Available', 'Source'). Truncated Rows
    landen NICHT in `rows` sondern erzeugen eine Warning.
    """
    if not text:
        return [], []

    found = _find_header_and_offsets(text)
    if not found:
        return [], []
    names, offsets, first_data_idx = found

    # Welche Spalte ist welche? winget hat (ENG): Name, Id, Version, Available, Source
    # (DE): Name, ID, Version, Verfügbar, Quelle
    # Die ID ist *immer* die zweite Spalte. Verfügbar ist die vierte (kann fehlen
    # in `winget list`-Output wenn keine Updates da sind — dann gibt es nur
    # 4 Spalten: Name | Id | Version | Source).
    rows: list[dict[str, str]] = []
    warnings: list[str] = []

    lines = text.splitlines()
    for line in lines[first_data_idx:]:
        if not line.strip():
            continue
        # Trenner-Zeilen, Progress-Bar-Reste, Status-Texte → skip
        if all(c in " -=_/\\|.*" for c in line.strip()):
            continue
        # Zeilen die mit Whitespace beginnen sind oft Fortsetzungen, skip
        if line and not line[0].isalnum():
            continue

        fields = _slice_row(line, offsets)
        if len(fields) < 2:
            continue

        # Truncation-Check: jedes Feld das auf '…' endet ist abgeschnitten
        truncated = any(f.endswith(_ELLIPSIS) for f in fields if f)
        if truncated:
            warnings.append(f"truncated: {line.strip()[:80]}")
            continue

        row = {}
        for k, name in enumerate(names):
            row[name] = fields[k] if k < len(fields) else ""
        rows.append(row)

    return rows, warnings


def _row_value(row: dict[str, str], *candidates: str) -> str:
    """Tolerant-Lookup: probiert mehrere mögliche Spalten-Namen
    (englisch + deutsch) und liefert den ersten Treffer."""
    for c in candidates:
        if c in row:
            return row[c]
    # Case-insensitive Fallback
    lower_row = {k.lower(): v for k, v in row.items()}
    for c in candidates:
        if c.lower() in lower_row:
            return lower_row[c.lower()]
    return ""


def parse_scan_payload(payload: str) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Parsed das von `_SCAN_SCRIPT` gelieferte JSON.

    Tactical liefert die stdout des `run_command`-Aufrufs als JSON-encoded
    String zurück (also `"{\\"a\\":1}\\r\\n"` statt `{"a":1}`). Wir decoden
    deshalb potenziell doppelt: erst die äußere String-Hülle, dann das
    innere JSON-Objekt.

    Returns: (state_rows, warnings) wo state_rows die Liste an dicts mit den
    Keys ist die `database.replace_agent_winget_state` erwartet:
    `winget_id, installed_version, available_version, source`.
    """
    if not payload:
        raise ValueError("empty scan payload")

    payload = payload.strip()

    # Doppel-Decode: wenn payload mit `"` beginnt, ist es eine JSON-string-Hülle
    if payload.startswith('"'):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as e:
            raise ValueError(f"invalid outer string JSON: {e}")
        payload = payload.strip()

    # PowerShell ConvertTo-Json kann mehrere Zeilen vor dem JSON ausgeben
    # (Warnings, Banner). Wir suchen das erste '{' und nehmen ab da.
    brace_idx = payload.find("{")
    if brace_idx > 0:
        payload = payload[brace_idx:]

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid scan payload JSON: {e}")

    if not isinstance(data, dict):
        raise ValueError(f"scan payload not a dict: {type(data)}")

    if not data.get("ok"):
        err = data.get("error") or "unknown_scan_error"
        raise ValueError(f"agent reported scan error: {err}")

    installed_text = data.get("installed") or ""
    upgradable_text = data.get("upgradable") or ""

    installed_rows, w1 = _parse_winget_table(installed_text)
    upgradable_rows, w2 = _parse_winget_table(upgradable_text)
    warnings = w1 + w2

    # Mappen auf state-rows. installed_rows hat: Name, Id, Version, Source
    # (manchmal auch Available wenn winget bereits weiß dass Updates da sind)
    # upgradable_rows hat zusätzlich Available.
    upgradable_lookup: dict[str, str] = {}
    for row in upgradable_rows:
        wid = _row_value(row, "Id", "ID")
        avail = _row_value(row, "Available", "Verfügbar", "Verfuegbar")
        if wid and avail:
            upgradable_lookup[wid] = avail

    state_rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for row in installed_rows:
        wid = _row_value(row, "Id", "ID")
        if not wid or wid in seen_ids:
            continue
        # winget zeigt manchmal Display-Namen mit Whitespace im Id-Feld wenn
        # die Spalte schmal ist — defensives Filtering
        if " " in wid or len(wid) > 200:
            continue
        seen_ids.add(wid)
        installed_version = _row_value(row, "Version")
        # Available kann auch direkt im list-Output sein
        available = (
            upgradable_lookup.get(wid)
            or _row_value(row, "Available", "Verfügbar", "Verfuegbar")
            or None
        )
        source = _row_value(row, "Source", "Quelle") or "winget"
        state_rows.append({
            "winget_id":         wid,
            "installed_version": installed_version or None,
            "available_version": available or None,
            "source":            source,
        })

    return state_rows, warnings


# ── Scan-Orchestrierung ───────────────────────────────────────────────────────


# Default-Timeout pro Agent: 120s — winget list/upgrade ist normalerweise
# unter 30s, aber erste Calls auf einem frischen Agent (Source-Sync) können
# länger dauern.
_DEFAULT_TIMEOUT = 120


async def scan_agent(agent_id: str, timeout: int = _DEFAULT_TIMEOUT) -> dict[str, Any]:
    """
    Targeted Re-Scan eines einzelnen Agents. Wird nach User-Aktionen
    aufgerufen (Install/Update/Uninstall) und vom manuellen Re-Scan-Button
    im Admin-UI.

    Returns: ein dict mit keys `ok` (bool), `count` (int), `warnings` (list),
    `error` (str|None). Schreibt das Ergebnis in agent_winget_state und
    agent_scan_meta — ein Caller muss das Ergebnis nicht selbst persistieren.
    """
    try:
        text = await TacticalClient().run_command(
            agent_id, _SCAN_SCRIPT, timeout=timeout
        )
    except Exception as e:
        msg = str(e)[:200]
        logger.warning("winget scan failed for agent %s: %s", agent_id, msg)
        await database.upsert_scan_meta(agent_id, status="error", error=msg)
        return {"ok": False, "count": 0, "warnings": [], "error": msg}

    try:
        state_rows, warnings = parse_scan_payload(text)
    except ValueError as e:
        msg = str(e)[:200]
        # Known cases die wir nicht als Fehler werten:
        if "winget_not_installed" in msg:
            logger.info("agent %s has no winget installed", agent_id)
            await database.replace_agent_winget_state(agent_id, [])
            await database.upsert_scan_meta(
                agent_id, status="no_winget",
                error="App Installer / winget nicht installiert",
            )
            return {"ok": True, "count": 0, "warnings": [], "error": None}
        logger.warning("winget scan parse failed for agent %s: %s", agent_id, msg)
        await database.upsert_scan_meta(agent_id, status="parse_error", error=msg)
        return {"ok": False, "count": 0, "warnings": [], "error": msg}

    await database.replace_agent_winget_state(agent_id, state_rows)
    error_for_meta = None
    if warnings:
        error_for_meta = f"{len(warnings)} truncated rows"
    await database.upsert_scan_meta(
        agent_id,
        status="ok",
        error=error_for_meta,
    )
    logger.info(
        "winget scan ok for agent %s: %d rows, %d warnings",
        agent_id, len(state_rows), len(warnings),
    )
    return {
        "ok":       True,
        "count":    len(state_rows),
        "warnings": warnings,
        "error":    None,
    }


async def run_nightly_scan(
    concurrency: int = 20,
    online_threshold: int = 300,
    timeout_per_agent: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Fleet-wide nightly Scan. Wird vom APScheduler einmal pro Tag aufgerufen.

    Pre-Filter via eigener `agents.last_seen` (kostenlos, kein Tactical-Call).
    Bounded concurrency via Semaphore. Offline-Agents werden geskipped.
    """
    candidates = await database.get_agents_due_for_scan(
        online_threshold_seconds=online_threshold
    )
    if not candidates:
        logger.info("nightly winget scan: no candidates (no online agents)")
        return {"scanned": 0, "ok": 0, "failed": 0}

    sem = asyncio.Semaphore(concurrency)
    ok_count = 0
    fail_count = 0

    async def _one(agent: dict):
        nonlocal ok_count, fail_count
        async with sem:
            try:
                result = await scan_agent(
                    agent["agent_id"], timeout=timeout_per_agent
                )
                if result.get("ok"):
                    ok_count += 1
                else:
                    fail_count += 1
            except Exception as e:
                fail_count += 1
                logger.warning(
                    "nightly scan exception for %s: %s",
                    agent.get("agent_id"), e,
                )

    logger.info(
        "nightly winget scan starting: %d candidates, concurrency=%d",
        len(candidates), concurrency,
    )
    await asyncio.gather(*(_one(a) for a in candidates))
    logger.info(
        "nightly winget scan done: %d ok, %d failed",
        ok_count, fail_count,
    )
    return {
        "scanned": len(candidates),
        "ok":      ok_count,
        "failed":  fail_count,
    }
