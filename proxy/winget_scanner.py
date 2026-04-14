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

# winget-Resolver: Tactical run_command läuft als SYSTEM. winget ist auf
# Windows 11 zwar installiert, der CLI-Shim `winget.exe` liegt aber per-user
# in %LocalAppData%\Microsoft\WindowsApps\winget.exe und ist deshalb unter
# SYSTEM nicht im PATH. Die echte Binary liegt in
# C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__*\winget.exe
# und ist von SYSTEM aus zugreifbar (regulärer User nicht). Wir resolven
# beide Pfade und fallen auf die WindowsApps-Variante zurück.
_PS_FIND_WINGET = r"""
function Find-WingetExe {
    $cmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $base = 'C:\Program Files\WindowsApps'
    if (-not (Test-Path -LiteralPath $base)) { return $null }
    $dirs = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue `
        | Where-Object { $_.Name -like 'Microsoft.DesktopAppInstaller_*_x64__*' } `
        | Sort-Object Name -Descending
    foreach ($d in $dirs) {
        $exe = Join-Path $d.FullName 'winget.exe'
        if (Test-Path -LiteralPath $exe) { return $exe }
    }
    return $null
}
"""

_SCAN_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Buffer-Breite aufreissen wo es geht — wirkt nur in interaktiven Hosts.
# Unter Tactical (headless) wird der try-Block stillschweigend geskippt.
try {
    $raw = $Host.UI.RawUI
    $sz  = $raw.BufferSize
    $sz.Width = 512
    $raw.BufferSize = $sz
} catch {}
$env:COLUMNS = 512

""" + _PS_FIND_WINGET + r"""

$wingetExe = Find-WingetExe
if (-not $wingetExe) {
    $err = @{ ok = $false; error = 'winget_not_installed' } | ConvertTo-Json -Compress
    Write-Output $err
    exit 0
}

# Installed Liste via `winget export`: liefert strukturiertes JSON, kein
# Console-Truncation, kein lokalisierter Header. Inkl. installierter Versionen.
# Wir lesen die Datei mit [System.IO.File]::ReadAllText, weil PowerShell 5.1's
# Get-Content -Raw beim spaeteren ConvertTo-Json zu einem PSObject-Wrapper
# ({"value":"..."}) wird statt zu einem plain String.
$exportPath = Join-Path $env:TEMP ('winget_export_' + [System.Guid]::NewGuid().ToString('N') + '.json')
$installedJson = ''
try {
    & $wingetExe export `
        -o $exportPath `
        --source winget `
        --accept-source-agreements `
        --disable-interactivity `
        --include-versions 2>&1 | Out-Null
    if (Test-Path -LiteralPath $exportPath) {
        $installedJson = [System.IO.File]::ReadAllText($exportPath)
    }
} catch {
    $installedJson = ''
} finally {
    Remove-Item -LiteralPath $exportPath -ErrorAction SilentlyContinue
}
# Defensive: sicherstellen dass es ein plain string ist
$installedJson = [string]$installedJson

# Upgradable Liste hat keinen Export-Equivalent, wir parsen weiter den Text.
# Truncated rows werden serverseitig gegen die installed-Liste aufgeloest
# (Prefix-Match), so dass wir trotzdem die echten IDs treffen.
try {
    $upgradable = (& $wingetExe upgrade --source winget --accept-source-agreements --disable-interactivity 2>&1) -join "`n"
} catch {
    $upgradable = ""
}

$result = @{
    ok            = $true
    installed_json = $installedJson
    upgradable    = $upgradable
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


def _parse_winget_export(installed_json: str) -> list[dict[str, Any]]:
    """
    Parsed das JSON-Format von `winget export`. Schema:
    {
      "Sources": [
        {
          "Packages": [{"PackageIdentifier": "...", "Version": "..."}, ...]
        }, ...
      ]
    }
    """
    if not installed_json:
        return []
    try:
        data = json.loads(installed_json)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    sources = data.get("Sources") or []
    if not isinstance(sources, list):
        return []
    rows: list[dict[str, Any]] = []
    for src in sources:
        if not isinstance(src, dict):
            continue
        packages = src.get("Packages") or []
        if not isinstance(packages, list):
            continue
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            wid = (pkg.get("PackageIdentifier") or "").strip()
            if not wid:
                continue
            version = (pkg.get("Version") or "").strip()
            rows.append({
                "winget_id":         wid,
                "installed_version": version or None,
            })
    return rows


def _resolve_truncated_id(truncated: str, full_ids: list[str]) -> str | None:
    """
    Findet die volle winget-ID die zum truncated Prefix passt. Eindeutig
    wenn genau eine ID matched, sonst None.
    """
    if not truncated:
        return None
    if truncated.endswith(_ELLIPSIS):
        prefix = truncated[:-1]
    else:
        prefix = truncated
    matches = [fid for fid in full_ids if fid.startswith(prefix)]
    if len(matches) == 1:
        return matches[0]
    return None


def parse_scan_payload(payload: str) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Parsed das von `_SCAN_SCRIPT` gelieferte JSON.

    Tactical liefert die stdout des `run_command`-Aufrufs als JSON-encoded
    String zurück (also `"{\\"a\\":1}\\r\\n"` statt `{"a":1}`). Wir decoden
    deshalb potenziell doppelt: erst die äußere String-Hülle, dann das
    innere JSON-Objekt.

    `installed_json` ist der Inhalt von `winget export` (strukturiertes JSON,
    kein Truncation). `upgradable` ist weiterhin der Text-Output von
    `winget upgrade`, dessen truncated IDs wir gegen die installed-Liste
    via Prefix-Match auflösen.

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

    installed_json = data.get("installed_json") or ""
    upgradable_text = data.get("upgradable") or ""

    # Schritt 1: installierte Pakete aus dem JSON-Export ziehen (kanonische IDs)
    installed_pkgs = _parse_winget_export(installed_json)
    full_ids = [r["winget_id"] for r in installed_pkgs]

    # Schritt 2: Upgrade-Text parsen, truncated IDs gegen installed_pkgs auflösen
    upgradable_rows, warnings = _parse_winget_table(upgradable_text)
    upgradable_lookup: dict[str, str] = {}
    unresolved_warnings: list[str] = []
    for row in upgradable_rows:
        wid_raw = _row_value(row, "Id", "ID").strip()
        avail = _row_value(row, "Available", "Verfügbar", "Verfuegbar").strip()
        if not wid_raw or not avail:
            continue
        # Truncation auflösen
        if wid_raw.endswith(_ELLIPSIS) or " " in wid_raw:
            resolved = _resolve_truncated_id(wid_raw, full_ids)
            if not resolved:
                unresolved_warnings.append(
                    f"unresolved truncated upgrade id: {wid_raw}"
                )
                continue
            wid_raw = resolved
        if avail.endswith(_ELLIPSIS):
            unresolved_warnings.append(
                f"truncated available version for {wid_raw}: {avail}"
            )
            continue
        upgradable_lookup[wid_raw] = avail

    # Schritt 3: state-rows zusammenbauen
    state_rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pkg in installed_pkgs:
        wid = pkg["winget_id"]
        if wid in seen:
            continue
        seen.add(wid)
        state_rows.append({
            "winget_id":         wid,
            "installed_version": pkg.get("installed_version"),
            "available_version": upgradable_lookup.get(wid),
            "source":            "winget",
        })

    # _parse_winget_table truncation-warnings filtern wir hier raus weil wir
    # sie via Prefix-Match aufgelöst haben — nur noch echte ungelöste
    # warnings übrig lassen.
    real_warnings = [w for w in warnings if not w.startswith("truncated:")]
    real_warnings.extend(unresolved_warnings)

    return state_rows, real_warnings


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
