"""
choco Scanner

Triggert via Tactical-`run_command` `choco list --limit-output` und
`choco outdated --limit-output` auf einem Windows-Agent, parsed das
pipe-separierte Output und schreibt das Ergebnis in `agent_choco_state`
+ `agent_scan_meta`.

Spiegelt das Schema-Pattern von `winget_scanner.py` ab:
  - scan_agent(agent_id)        → Targeted Re-Scan eines einzelnen Agents
  - run_nightly_scan()          → Fleet-wide Batch via APScheduler

choco-Output-Format mit `--limit-output`:
  list:     name|version
  outdated: name|installed|available|pinned
"""
import asyncio
import logging
from typing import Any

import database
from tactical_client import TacticalClient

logger = logging.getLogger("softshelf.choco.scanner")


# choco wird typischerweise in `C:\ProgramData\chocolatey\bin\choco.exe`
# installiert. Das ist auch unter SYSTEM-Kontext zugreifbar (im Gegensatz
# zu winget). PATH-Lookup funktioniert auch wenn der Tactical-Agent
# entsprechend konfiguriert ist; der explizite Pfad ist ein Fallback.
_SCAN_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$choco = $null
$cmd = Get-Command choco -ErrorAction SilentlyContinue
if ($cmd) { $choco = $cmd.Source }
if (-not $choco) {
    $candidate = 'C:\ProgramData\chocolatey\bin\choco.exe'
    if (Test-Path -LiteralPath $candidate) { $choco = $candidate }
}
if (-not $choco) {
    $err = @{ ok = $false; error = 'choco_not_installed' } | ConvertTo-Json -Compress
    Write-Output $err
    exit 0
}

try {
    $listOut = (& $choco list --limit-output --no-progress 2>&1) -join "`n"
} catch {
    $listOut = ""
}
try {
    $outdatedOut = (& $choco outdated --limit-output --no-progress 2>&1) -join "`n"
} catch {
    $outdatedOut = ""
}

$result = @{
    ok            = $true
    list_text     = $listOut
    outdated_text = $outdatedOut
} | ConvertTo-Json -Compress

Write-Output $result
"""


def _parse_pipe_lines(text: str, expected_min_fields: int = 2) -> list[list[str]]:
    """Parsed pipe-separated `choco --limit-output` Zeilen. Skipped Banner-
    Zeilen, Warnings, Leerzeilen. Returns Liste von Field-Listen."""
    if not text:
        return []
    rows: list[list[str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Banner / status lines starten mit Großbuchstaben gefolgt von Doppelpunkt
        # oder enthalten keinen Pipe — wir filtern grob alles raus was kein
        # erkennbares choco-Datenformat ist.
        if "|" not in line:
            continue
        fields = line.split("|")
        if len(fields) < expected_min_fields:
            continue
        # Erstes Feld ist immer der Paketname; muss alphanumerisch beginnen
        if not fields[0] or not (fields[0][0].isalnum()):
            continue
        rows.append(fields)
    return rows


def parse_scan_payload(payload: str) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Parsed das von `_SCAN_SCRIPT` gelieferte JSON.

    Tactical wrappt stdout als JSON-string — wir entpacken doppelt wenn nötig.

    Returns: (state_rows, warnings) wo state_rows die Liste an dicts mit den
    Keys ist die `database.replace_agent_choco_state` erwartet:
    `choco_name, installed_version, available_version`.
    """
    import json
    if not payload:
        raise ValueError("empty scan payload")

    payload = payload.strip()
    if payload.startswith('"'):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as e:
            raise ValueError(f"invalid outer string JSON: {e}")
        payload = payload.strip()

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

    list_text = data.get("list_text") or ""
    outdated_text = data.get("outdated_text") or ""

    # `choco list` mit --limit-output gibt: name|version pro Zeile
    list_rows = _parse_pipe_lines(list_text, expected_min_fields=2)
    installed: dict[str, str] = {}
    for fields in list_rows:
        name = fields[0].strip()
        version = fields[1].strip() if len(fields) > 1 else ""
        if name and name.lower() != "chocolatey":
            installed[name] = version

    # `choco outdated` mit --limit-output gibt: name|installed|available|pinned
    outdated_rows = _parse_pipe_lines(outdated_text, expected_min_fields=3)
    upgradable: dict[str, str] = {}
    for fields in outdated_rows:
        name = fields[0].strip()
        # fields[1] = installed, fields[2] = available
        if len(fields) >= 3 and fields[2].strip():
            upgradable[name] = fields[2].strip()

    state_rows: list[dict[str, Any]] = []
    for name, version in installed.items():
        state_rows.append({
            "choco_name":        name,
            "installed_version": version or None,
            "available_version": upgradable.get(name),
        })

    warnings: list[str] = []
    return state_rows, warnings


_DEFAULT_TIMEOUT = 180


async def scan_agent(agent_id: str, timeout: int = _DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Targeted Re-Scan eines einzelnen Agents. Wird nach choco-User-Aktionen
    und vom manuellen Re-Scan-Button getriggert.

    Returns: dict mit `ok`, `count`, `error`. Schreibt agent_choco_state und
    bumpt scan_meta.last_scan_at."""
    try:
        text = await TacticalClient().run_command(
            agent_id, _SCAN_SCRIPT, timeout=timeout
        )
    except Exception as e:
        msg = str(e)[:200]
        logger.warning("choco scan failed for agent %s: %s", agent_id, msg)
        return {"ok": False, "count": 0, "error": msg}

    try:
        state_rows, _warnings = parse_scan_payload(text)
    except ValueError as e:
        msg = str(e)[:200]
        if "choco_not_installed" in msg:
            logger.info("agent %s has no choco installed", agent_id)
            await database.replace_agent_choco_state(agent_id, [])
            return {"ok": True, "count": 0, "error": None}
        logger.warning("choco scan parse failed for agent %s: %s", agent_id, msg)
        return {"ok": False, "count": 0, "error": msg}

    await database.replace_agent_choco_state(agent_id, state_rows)
    # Bump scan_meta.last_scan_at — dieselbe Tabelle wie winget, weil das
    # Frontend-Polling auf last_scan_at OR last_action_at schaut. Beide
    # Scanner-Typen müssen den Timestamp anfassen damit das Polling triggert.
    await database.upsert_scan_meta(agent_id, status="ok")
    logger.info(
        "choco scan ok for agent %s: %d rows", agent_id, len(state_rows)
    )
    return {"ok": True, "count": len(state_rows), "error": None}


async def run_nightly_scan(
    concurrency: int = 20,
    online_threshold: int = 300,
    timeout_per_agent: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Fleet-wide nightly choco-Scan. Wird vom APScheduler 1× pro Tag
    aufgerufen. Pre-Filter wie beim winget-Scanner — online via eigener
    last_seen, gebannte/abgelaufene Agents skippen."""
    candidates = await database.get_agents_due_for_scan(
        online_threshold_seconds=online_threshold
    )
    if not candidates:
        logger.info("nightly choco scan: no candidates (no online agents)")
        return {"scanned": 0, "ok": 0, "failed": 0}

    sem = asyncio.Semaphore(concurrency)
    ok_count = 0
    fail_count = 0

    async def _one(agent: dict):
        nonlocal ok_count, fail_count
        async with sem:
            try:
                result = await scan_agent(agent["agent_id"], timeout=timeout_per_agent)
                if result.get("ok"):
                    ok_count += 1
                else:
                    fail_count += 1
            except Exception as e:
                fail_count += 1
                logger.warning(
                    "nightly choco scan exception for %s: %s",
                    agent.get("agent_id"), e,
                )

    logger.info(
        "nightly choco scan starting: %d candidates, concurrency=%d",
        len(candidates), concurrency,
    )
    await asyncio.gather(*(_one(a) for a in candidates))
    logger.info(
        "nightly choco scan done: %d ok, %d failed",
        ok_count, fail_count,
    )
    return {"scanned": len(candidates), "ok": ok_count, "failed": fail_count}
