"""
POST /api/v1/install   → Paket installieren
POST /api/v1/uninstall → Paket deinstallieren

Beide Endpoints prüfen:
  1. Paketname ist in der whitelist (vom Admin freigeschaltet)
  2. Agent-ID kommt aus dem signierten Machine Token (kein Cross-Agent-Zugriff)

Choco-Pakete laufen über Tactical's /software/{id}/-Endpoint.
Custom-Pakete (MSI/EXE) werden via /agents/{id}/cmd/ als PowerShell-Job
ausgeführt — Download via signierter URL, dann Install/Uninstall mit den
beim Upload gespeicherten Argumenten.
Winget-Pakete laufen ebenfalls via /agents/{id}/cmd/ mit einem PowerShell-
Wrapper um winget install/upgrade/uninstall. Nach erfolgreicher Aktion
wird ein targeted Re-Scan getriggert damit der Kiosk-State sofort frisch ist.
"""
import asyncio
import logging
import re
import secrets as _secrets
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import choco_scanner
import database
import winget_scanner
from auth import create_download_token, verify_machine_token
from config import get_settings, runtime_value
from tactical_client import TacticalClient

router = APIRouter()
logger = logging.getLogger("softshelf")

_bg_tasks: set[asyncio.Task] = set()


def _spawn_bg(coro) -> asyncio.Task:
    t = asyncio.create_task(coro)
    _bg_tasks.add(t)
    t.add_done_callback(_bg_tasks.discard)
    return t


async def _run_custom_command_bg(
    agent_id: str,
    hostname: str,
    package_name: str,
    display_name: str,
    cmd: str,
    action: str,
    version_id: int | None = None,
):
    """
    Background-Task für custom install/uninstall via Tactical run-cmd.
    Dauert Minuten (Download + msiexec), daher nicht synchron am Request hängen.
    Bei Erfolg wird agent_installations aktualisiert. Bei Fehler wird die
    Meldung in scan_meta.last_action_error persistiert damit das Admin-UI
    sie als Banner im Agent-Detail zeigen kann (gleicher Mechanismus wie
    bei winget und choco).
    """
    error_msg: str | None = None
    try:
        await TacticalClient().run_command(agent_id, cmd, timeout=600)
        logger.info("custom %s ok: %s auf %s", action, display_name, hostname)
        if action == "install":
            await database.set_agent_installation(agent_id, package_name, version_id)
        elif action == "uninstall":
            await database.delete_agent_installation(agent_id, package_name)
    except Exception as e:
        # run_command schmeisst bei Non-200 von Tactical bzw. Non-Zero-Exit
        # vom Agent-Script. Letztes Stück Output landet meist in str(e).
        error_msg = str(e)[:300] or "unbekannter Fehler"
        logger.warning("custom %s fehlgeschlagen: %s auf %s — %s",
                       action, display_name, hostname, error_msg)

    try:
        await database.upsert_action_result(agent_id, package_name, error_msg)
    except Exception as e:
        logger.warning("upsert_action_result custom failed: %s", e)


class SoftwareRequest(BaseModel):
    package_name: str


class SoftwareResponse(BaseModel):
    status: str
    message: str


def _is_safe_package_name(name: str) -> bool:
    return bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,99}", name))


async def _public_proxy_url() -> str:
    cfg = get_settings()
    url = await runtime_value("proxy_public_url")
    if url:
        return url.rstrip("/")
    return f"http://{cfg.host}:{cfg.port}"


def _ps_quote(s: str) -> str:
    """Escape für PowerShell-Single-Quoted-Strings: ' → ''"""
    return s.replace("'", "''")


def _ps_arg_array(args_str: str) -> str:
    """Splittet Args an Whitespace und baut ein PowerShell-Array-Literal daraus."""
    items = [f"'{_ps_quote(a)}'" for a in args_str.split()]
    return ", ".join(items)


async def _build_install_command(pkg: dict, agent_id: str) -> str:
    """
    Baut den PowerShell-Command, der auf dem Agent läuft, um ein custom-Paket
    herunterzuladen und silent zu installieren.

    Drei Varianten je nach archive_type / Dateiendung:
      • single MSI    → msiexec /i <tmp> <args>
      • single EXE    → Start-Process <tmp> <args>
      • archive (zip) → Expand-Archive nach tmp-dir, Start-Process <entry_point>
    """
    sha = pkg["sha256"]
    filename = pkg["filename"] or f"{sha}.bin"
    ext = filename.rsplit(".", 1)[-1].lower()
    install_args = pkg.get("install_args") or ""
    archive_type = pkg.get("archive_type") or "single"

    token = create_download_token(sha, agent_id)
    base = await _public_proxy_url()
    url = f"{base}/api/v1/file/{sha}?token={token}"
    url_quoted = _ps_quote(url)

    nonce = _secrets.token_hex(4)

    if archive_type == "archive":
        entry_point = (pkg.get("entry_point") or "").strip()
        if not entry_point:
            raise HTTPException(
                status_code=500, detail="Archive-Paket ohne entry_point"
            )
        # Backslashes für Windows
        entry_win = entry_point.replace("/", "\\")
        ep_quoted = _ps_quote(entry_win)
        args_array = _ps_arg_array(install_args)
        args_line = (
            f"$proc = Start-Process -FilePath $exe -ArgumentList {args_array} "
            f"-WorkingDirectory $workDir -Wait -PassThru -NoNewWindow"
            if args_array
            else
            f"$proc = Start-Process -FilePath $exe "
            f"-WorkingDirectory $workDir -Wait -PassThru -NoNewWindow"
        )
        return f"""$ErrorActionPreference = 'Stop'
$zipPath = Join-Path $env:TEMP 'kiosk_install_{nonce}.zip'
$extPath = Join-Path $env:TEMP 'kiosk_install_{nonce}'
Invoke-WebRequest -Uri '{url_quoted}' -OutFile $zipPath -UseBasicParsing
Expand-Archive -LiteralPath $zipPath -DestinationPath $extPath -Force
$exe = Join-Path $extPath '{ep_quoted}'
if (-not (Test-Path -LiteralPath $exe)) {{
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $extPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Error "Entry-Point nicht gefunden im Archiv: {ep_quoted}"
    exit 1
}}
$workDir = Split-Path -LiteralPath $exe -Parent
{args_line}
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Remove-Item $extPath -Recurse -Force -ErrorAction SilentlyContinue
if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {{
    Write-Error "Installer beendete mit ExitCode $($proc.ExitCode)"
    exit $proc.ExitCode
}}
Write-Output 'Installation abgeschlossen.'
"""

    # ── single MSI / EXE (Legacy-Pfad) ──
    tmp_var = "$tmp"
    tmp_init = f"{tmp_var} = Join-Path $env:TEMP 'kiosk_install_{nonce}.{ext}'"

    if ext == "msi":
        extra = [f"'{_ps_quote(a)}'" for a in install_args.split()]
        arg_items = ["'/i'", tmp_var] + extra
        args_line = ", ".join(arg_items)
        install_line = (
            f"$proc = Start-Process -FilePath msiexec "
            f"-ArgumentList {args_line} "
            f"-Wait -PassThru -NoNewWindow"
        )
    else:
        extra = [f"'{_ps_quote(a)}'" for a in install_args.split()]
        if extra:
            args_line = ", ".join(extra)
            install_line = (
                f"$proc = Start-Process -FilePath {tmp_var} "
                f"-ArgumentList {args_line} "
                f"-Wait -PassThru -NoNewWindow"
            )
        else:
            install_line = (
                f"$proc = Start-Process -FilePath {tmp_var} "
                f"-Wait -PassThru -NoNewWindow"
            )

    return f"""$ErrorActionPreference = 'Stop'
{tmp_init}
Invoke-WebRequest -Uri '{url_quoted}' -OutFile {tmp_var} -UseBasicParsing
{install_line}
Remove-Item {tmp_var} -Force -ErrorAction SilentlyContinue
if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {{
    Write-Error "Installer beendete mit ExitCode $($proc.ExitCode)"
    exit $proc.ExitCode
}}
Write-Output 'Installation abgeschlossen.'
"""


def _build_uninstall_command(uninstall_cmd: str) -> str:
    """PowerShell-Wrapper für ein Uninstall-Command — propagiert ExitCode
    sauber und akzeptiert reboot-required-Codes (3010) und not-installed (1605)."""
    safe = uninstall_cmd.replace("'", "''")
    return f"""$ErrorActionPreference = 'Stop'
$proc = Start-Process -FilePath cmd.exe -ArgumentList '/c','{safe}' -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010 -and $proc.ExitCode -ne 1605) {{
    Write-Error "Uninstaller beendete mit ExitCode $($proc.ExitCode)"
    exit $proc.ExitCode
}}
Write-Output 'Deinstallation abgeschlossen.'
"""


# ── Winget Dispatch ───────────────────────────────────────────────────────────

# winget PackageIdentifier ist konservativ alphanumerisch + Punkt + Bindestrich.
# Defense-in-depth: keine Quotes, kein Whitespace, keine Shell-Metas
_WINGET_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,199}$")


def _check_winget_id(wid: str) -> str:
    if not _WINGET_ID_RE.fullmatch(wid):
        raise HTTPException(
            status_code=400, detail=f"Ungültige winget-PackageIdentifier: {wid!r}"
        )
    return wid


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


def _build_winget_command(action: str, winget_id: str, version: str | None = None) -> str:
    """
    Baut den PowerShell-Wrapper für winget install/upgrade/uninstall.
    Akzeptierte action-Werte: 'install', 'upgrade', 'uninstall'.

    Tactical run_command läuft als SYSTEM, der user-shim winget.exe ist
    nicht im PATH. Wir resolven die Binary aus C:\Program Files\WindowsApps.

    winget Exit-Codes die wir als Erfolg werten:
      0           → ok
      -1978335212 → bereits installiert
      -1978335189 → kein Upgrade verfügbar
    """
    if action not in ("install", "upgrade", "uninstall"):
        raise ValueError(f"unsupported winget action: {action}")
    _check_winget_id(winget_id)
    safe_id = winget_id  # Regex-validiert, kein extra Escape nötig
    version_arg = ""
    if version and action in ("install", "upgrade"):
        # Defense-in-depth: Version nur alphanumerisch + Punkt + Bindestrich
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._\-]{0,49}", version):
            raise HTTPException(status_code=400, detail="Ungültige winget-Version")
        version_arg = f"--version '{version}' "
    if action == "uninstall":
        # --force erlaubt uninstall auch bei fehlender ARP-UninstallString
        # (z. B. Store-Apps), --accept-source-agreements für frische Sources.
        winget_args = (
            f"uninstall --id '{safe_id}' --silent --force "
            f"--accept-source-agreements --disable-interactivity -h"
        )
    else:
        winget_args = (
            f"{action} --id '{safe_id}' --scope machine --silent "
            f"--accept-package-agreements --accept-source-agreements "
            f"--disable-interactivity -h "
            f"{version_arg}"
        ).strip()

    return f"""$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
{_PS_FIND_WINGET}
$wingetExe = Find-WingetExe
if (-not $wingetExe) {{
    Write-Error "winget ist nicht installiert (App Installer fehlt)"
    exit 9009
}}
$out = (& $wingetExe {winget_args} 2>&1) -join "`n"
Write-Output $out
$code = $LASTEXITCODE
if ($code -eq 0) {{
    exit 0
}}
# Bekannte 'eigentlich erfolgreich' Codes:
#   -1978335212 (0x8a150014) NO_APPLICABLE_INSTALLER bzw. installiert
#   -1978335189 (0x8a15002B) INSTALL_NOTHING_TO_UPGRADE
if ($code -eq -1978335212 -or $code -eq -1978335189) {{
    exit 0
}}
# -1978335162 (0x8a150046) APPINSTALLER_CLI_ERROR_NO_UNINSTALL_INFO_FOUND
# Tritt typischerweise auf wenn das Paket per-user installiert ist und
# winget unter SYSTEM keine Maschinen-Registry-UninstallString findet.
if ($code -eq -1978335162) {{
    Write-Error "winget hat keine Uninstall-Information gefunden — das Paket ist vermutlich per-user oder als Store-App installiert und kann nicht aus dem SYSTEM-Kontext entfernt werden. (ExitCode $code)"
    exit $code
}}
Write-Error "winget {action} beendete mit ExitCode $code"
exit $code
"""


# winget druckt für manche „kann nicht upgraden, aber ich exitte trotzdem mit
# nothing-to-upgrade-Code" Fälle eine Soft-Error-Message in stdout. Ohne
# diese Erkennung würden wir die Aktion als Erfolg werten, der nachgelagerte
# Re-Scan würde den unveränderten State zeigen, und der Admin sieht keinen
# Hinweis warum nichts passiert ist. Hier matchen wir bekannte Patterns und
# heben sie aus dem stdout in agent_scan_meta.last_action_error.
_WINGET_SOFT_ERROR_PATTERNS: list[tuple[str, str]] = [
    (
        "install technology is different",
        "winget kann nicht in-place upgraden — die neue Version verwendet "
        "eine andere Installer-Technologie als die installierte. Vorher "
        "deinstallieren oder ein anderes Update-Verfahren nutzen.",
    ),
    (
        "no available upgrade found",
        "winget meldet kein verfügbares Upgrade — das Paket ist vermutlich "
        "per-user installiert (--scope machine filtert es weg) oder die "
        "Installer-Manifest-Version stimmt nicht mit der installierten Version überein.",
    ),
    (
        "no installed package found matching input criteria",
        "winget findet das Paket nicht als installiert (vermutlich per-user "
        "Install den SYSTEM nicht sieht).",
    ),
    (
        "no uninstall information found",
        "winget hat keine Uninstall-Information gefunden — typisch bei "
        "per-user oder Microsoft-Store-Apps die SYSTEM nicht entfernen kann.",
    ),
]


def _detect_winget_soft_error(output: str) -> str | None:
    """Sucht im winget-Output nach bekannten 'fake success' Mustern. Returns
    eine human-readable Fehlermeldung wenn ein Pattern matcht, sonst None."""
    if not output:
        return None
    lower = output.lower()
    for needle, message in _WINGET_SOFT_ERROR_PATTERNS:
        if needle in lower:
            return message
    return None


# ── Choco Dispatch ────────────────────────────────────────────────────────────

# Choco's exit codes:
#   0    - success
#   1    - generic error
#   1641 - reboot initiated
#   3010 - reboot required (success)
#   404  - download failure (was the 3cx case)
# Wir werten 0/1641/3010 als Erfolg.
_CHOCO_SUCCESS_CODES = {0, 1641, 3010}

# Bekannte Choco-Soft-Error Patterns im stdout (selbst wenn exit != 0)
_CHOCO_SOFT_ERROR_PATTERNS: list[tuple[str, str]] = [
    (
        "likely broken for foss users",
        "Das Chocolatey-Paket ist auf der Community-Version nicht installierbar — der Installer-Download verlangt einen Lizenzschlüssel oder ein privates CDN. Auf https://docs.chocolatey.org/en-us/features/private-cdn dokumentiert.",
    ),
    (
        "the remote server returned an error: (404)",
        "Der Installer-Download von der Hersteller-URL ist 404 — das Paket ist im Chocolatey-Repo aufgeführt, der Download-Link beim Hersteller existiert aber nicht mehr.",
    ),
    (
        "the install of",
        "Choco-Install fehlgeschlagen — siehe Choco-Log auf dem Agent (C:\\ProgramData\\chocolatey\\logs\\chocolatey.log).",
    ),
]


def _detect_choco_soft_error(output: str, exit_code: int | None) -> str | None:
    """Bestimmt ob ein Choco-Lauf trotz technischem 'Erfolg' inhaltlich
    fehlgeschlagen ist. Returns Fehlermeldung oder None."""
    if exit_code is not None and exit_code not in _CHOCO_SUCCESS_CODES:
        # Echter Fehler. Wir picken die hilfreichste bekannte Meldung
        # oder fallen auf die letzten paar Zeilen zurück.
        if output:
            lower = output.lower()
            for needle, message in _CHOCO_SOFT_ERROR_PATTERNS:
                if needle in lower:
                    return f"{message} (ExitCode {exit_code})"
        return f"choco beendete mit ExitCode {exit_code}"
    if not output:
        return None
    lower = output.lower()
    if "0/1 packages" in lower or "1/1 packages failed" in lower:
        for needle, message in _CHOCO_SOFT_ERROR_PATTERNS:
            if needle in lower:
                return message
        return "Choco-Install fehlgeschlagen — Detail im Choco-Log auf dem Agent"
    return None


_CHOCO_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,99}$")


def _build_choco_command(action: str, package_name: str) -> str:
    """
    Baut den PowerShell-Wrapper für `choco install/uninstall <name>`. Wird
    via Tactical run_command als SYSTEM ausgeführt, output kommt zurück
    damit wir Soft-Errors detecten und im UI zeigen können.
    """
    if action not in ("install", "uninstall"):
        raise ValueError(f"unsupported choco action: {action}")
    if not _CHOCO_NAME_RE.fullmatch(package_name):
        raise HTTPException(status_code=400, detail=f"Ungültiger choco-Paketname: {package_name!r}")
    safe = package_name  # regex-validiert, keine Escapes nötig
    if action == "install":
        choco_args = f"install '{safe}' -y --no-progress --limit-output"
    else:
        choco_args = f"uninstall '{safe}' -y --no-progress --limit-output"

    return f"""$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$choco = $null
$cmd = Get-Command choco -ErrorAction SilentlyContinue
if ($cmd) {{ $choco = $cmd.Source }}
if (-not $choco) {{
    $candidate = 'C:\\ProgramData\\chocolatey\\bin\\choco.exe'
    if (Test-Path -LiteralPath $candidate) {{ $choco = $candidate }}
}}
if (-not $choco) {{
    Write-Error "choco ist nicht installiert (Chocolatey fehlt auf dem Agent)"
    exit 9009
}}
$out = (& $choco {choco_args} 2>&1) -join "`n"
Write-Output $out
$code = $LASTEXITCODE
# choco success codes: 0 ok, 1641 reboot initiated, 3010 reboot required
if ($code -eq 0 -or $code -eq 1641 -or $code -eq 3010) {{
    exit 0
}}
Write-Error "choco {action} beendete mit ExitCode $code"
exit $code
"""


async def _run_choco_command_bg(
    agent_id: str,
    hostname: str,
    package_name: str,
    display_name: str,
    cmd: str,
    action: str,
):
    """Background-Task für choco install/uninstall via Tactical run-cmd. Spiegelt
    `_run_winget_command_bg`: capture output, detect soft errors, persist
    last_action_error in scan_meta, chain targeted re-scan."""
    error_msg: str | None = None
    raw_output = ""
    exit_code: int | None = None
    try:
        raw_output = await TacticalClient().run_command(agent_id, cmd, timeout=600)
        if raw_output and raw_output.startswith('"'):
            try:
                import json as _json
                raw_output = _json.loads(raw_output)
            except Exception:
                pass
        # Bei Erfolg gibt's keinen ExitCode im stdout — wir vertrauen dass
        # run_command nicht raised heißt exit 0
        soft_err = _detect_choco_soft_error(raw_output, exit_code=0)
        if soft_err:
            error_msg = soft_err
            logger.warning(
                "choco %s soft-error für %s auf %s: %s",
                action, display_name, hostname, soft_err,
            )
        else:
            logger.info("choco %s ok: %s auf %s", action, display_name, hostname)
            # Bei Erfolg auch das Tracking aktualisieren
            try:
                if action == "install":
                    await database.set_agent_installation(agent_id, package_name, None)
                else:
                    await database.delete_agent_installation(agent_id, package_name)
            except Exception as e:
                logger.warning("agent_installations update failed: %s", e)
    except Exception as e:
        # run_command raised — Tactical hat Non-200 zurückgegeben, wahrscheinlich
        # Choco exit non-zero. Die Exception-Message enthält oft den letzten Output.
        msg = str(e)
        soft_err = _detect_choco_soft_error(msg, exit_code=1)
        error_msg = soft_err or msg[:300]
        logger.warning(
            "choco %s fehlgeschlagen: %s auf %s — %s",
            action, display_name, hostname, error_msg,
        )

    try:
        await database.upsert_action_result(agent_id, package_name, error_msg)
    except Exception as e:
        logger.warning("upsert_action_result choco failed: %s", e)

    # Targeted Re-Scan via choco_scanner — refresht agent_choco_state
    try:
        await choco_scanner.scan_agent(agent_id)
    except Exception as e:
        logger.warning("post-action choco rescan failed for %s: %s", agent_id, e)


async def _run_winget_command_bg(
    agent_id: str,
    hostname: str,
    package_name: str,
    display_name: str,
    cmd: str,
    action: str,
    winget_id: str,
):
    """
    Background-Task für winget install/upgrade/uninstall via Tactical run-cmd.
    Nach Completion (egal ob ok oder Fehler) wird ein targeted Re-Scan
    getriggert damit der Kiosk-State frisch ist — bei Fehler dokumentiert
    der Re-Scan dass das Paket NICHT installiert ist. Bei „Soft-Errors"
    (winget exited mit Success-Code aber druckt einen Fehler in stdout)
    wird die Meldung in agent_scan_meta.last_action_error persistiert
    damit das Admin-UI sie als Banner anzeigen kann.
    """
    error_msg: str | None = None
    raw_output = ""
    try:
        raw_output = await TacticalClient().run_command(agent_id, cmd, timeout=600)
        # Tactical wrappt stdout als JSON-string — entpacken wenn nötig
        if raw_output and raw_output.startswith('"'):
            try:
                import json as _json
                raw_output = _json.loads(raw_output)
            except Exception:
                pass
        soft_err = _detect_winget_soft_error(raw_output)
        if soft_err:
            error_msg = soft_err
            logger.warning(
                "winget %s soft-error für %s auf %s: %s",
                action, display_name, hostname, soft_err,
            )
        else:
            logger.info("winget %s ok: %s auf %s", action, display_name, hostname)
    except Exception as e:
        error_msg = str(e)[:300]
        logger.warning(
            "winget %s fehlgeschlagen: %s auf %s — %s",
            action, display_name, hostname, e,
        )

    # Action-Result in scan_meta persistieren (auch bei Erfolg, dann mit error=None,
    # damit der vorherige Fehler-Banner weggeht)
    try:
        await database.upsert_action_result(agent_id, package_name, error_msg)
    except Exception as e:
        logger.warning("upsert_action_result failed for %s: %s", agent_id, e)

    # Targeted Re-Scan — egal ob Erfolg oder Fehler, damit DB-State korrekt ist
    try:
        await winget_scanner.scan_agent(agent_id)
    except Exception as e:
        logger.warning("post-action winget rescan failed for %s: %s", agent_id, e)


@router.post("/install", response_model=SoftwareResponse)
async def install_package(
    body: SoftwareRequest,
    token: dict = Depends(verify_machine_token),
):
    agent_id = token["agent_id"]
    hostname = token["hostname"]

    # winget-IDs enthalten Punkte und können länger sein als das choco-Schema
    # erlaubt. Wir prüfen den richtigen Regex je nachdem ob das DB-Paket
    # ein winget-Paket ist.
    pkg = await database.get_package(body.package_name)
    if not pkg:
        raise HTTPException(status_code=403, detail="Paket nicht freigegeben")

    ptype = pkg.get("type") or "choco"

    if ptype == "winget":
        _check_winget_id(body.package_name)
        # winget hat eigenes Update-Verhalten: wir wählen install vs. upgrade
        # anhand des aktuellen state. Wenn schon installiert + available_version
        # gesetzt → upgrade. Sonst install.
        state = await database.get_agent_winget_state(agent_id)
        st = state.get(body.package_name)
        if st and st.get("installed_version") and st.get("available_version"):
            action = "upgrade"
        else:
            action = "install"
        cmd = _build_winget_command(action, body.package_name, pkg.get("winget_version"))
        _spawn_bg(_run_winget_command_bg(
            agent_id, hostname, body.package_name, pkg["display_name"],
            cmd, action, body.package_name,
        ))
        verb = "Aktualisierung" if action == "upgrade" else "Installation"
        msg = (
            f"{verb} von '{pkg['display_name']}' auf {hostname} gestartet. "
            f"Das kann einige Minuten dauern."
        )
        await database.log_install(
            agent_id, hostname, body.package_name, pkg["display_name"], "install"
        )
        return SoftwareResponse(status="started", message=msg)

    if not _is_safe_package_name(body.package_name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")

    if ptype == "custom":
        if not pkg.get("sha256"):
            raise HTTPException(status_code=500, detail="Custom-Paket ohne Datei-Hash")
        cmd = await _build_install_command(pkg, agent_id)
        # Fire-and-forget: der softshelf-Client soll nicht auf den Install warten
        _spawn_bg(_run_custom_command_bg(
            agent_id, hostname, body.package_name, pkg["display_name"], cmd, "install",
            pkg.get("current_version_id"),
        ))
        msg = (
            f"Installation von '{pkg['display_name']}' auf {hostname} gestartet. "
            f"Das kann einige Minuten dauern."
        )
    else:
        # Choco via run_command (statt /software/{id}/) damit wir stdout sehen
        # und Soft-Errors wie 3cx-404 in scan_meta.last_action_error landen können.
        cmd = _build_choco_command("install", body.package_name)
        _spawn_bg(_run_choco_command_bg(
            agent_id, hostname, body.package_name, pkg["display_name"],
            cmd, "install",
        ))
        msg = (
            f"Installation von '{pkg['display_name']}' auf {hostname} gestartet. "
            f"Das kann einige Minuten dauern."
        )

    await database.log_install(
        agent_id, hostname, body.package_name, pkg["display_name"], "install"
    )

    return SoftwareResponse(
        status="started",
        message=msg or f"Installation von '{pkg['display_name']}' auf {hostname} gestartet.",
    )


@router.post("/uninstall", response_model=SoftwareResponse)
async def uninstall_package(
    body: SoftwareRequest,
    token: dict = Depends(verify_machine_token),
):
    agent_id = token["agent_id"]
    hostname = token["hostname"]

    pkg = await database.get_package(body.package_name)
    if not pkg:
        raise HTTPException(status_code=403, detail="Paket nicht freigegeben")

    ptype = pkg.get("type") or "choco"

    if ptype == "winget":
        _check_winget_id(body.package_name)
        cmd = _build_winget_command("uninstall", body.package_name)
        _spawn_bg(_run_winget_command_bg(
            agent_id, hostname, body.package_name, pkg["display_name"],
            cmd, "uninstall", body.package_name,
        ))
        msg = (
            f"Deinstallation von '{pkg['display_name']}' auf {hostname} gestartet. "
            f"Das kann einige Minuten dauern."
        )
        await database.log_install(
            agent_id, hostname, body.package_name, pkg["display_name"], "uninstall"
        )
        return SoftwareResponse(status="started", message=msg)

    if not _is_safe_package_name(body.package_name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")

    if ptype == "custom":
        uninstall_cmd = pkg.get("uninstall_cmd")
        if not uninstall_cmd:
            raise HTTPException(
                status_code=400,
                detail="Für dieses Paket wurde kein Uninstall-Command hinterlegt.",
            )
        ps_cmd = _build_uninstall_command(uninstall_cmd)
        # Fire-and-forget auch hier
        _spawn_bg(_run_custom_command_bg(
            agent_id, hostname, body.package_name, pkg["display_name"], ps_cmd, "uninstall",
            pkg.get("current_version_id"),
        ))
        msg = (
            f"Deinstallation von '{pkg['display_name']}' auf {hostname} gestartet. "
            f"Das kann einige Minuten dauern."
        )
    else:
        # Choco via run_command (gleicher Pfad wie install) — kein Vorab-Check
        # auf Tactical-Scan mehr nötig, choco selber sagt uns ob das Paket
        # da war oder nicht (over stdout / exit code). Das spart auch den
        # 409-Fall der nur an Heuristik-Matches lag.
        cmd = _build_choco_command("uninstall", body.package_name)
        _spawn_bg(_run_choco_command_bg(
            agent_id, hostname, body.package_name, pkg["display_name"],
            cmd, "uninstall",
        ))
        msg = (
            f"Deinstallation von '{pkg['display_name']}' auf {hostname} gestartet. "
            f"Das kann einige Minuten dauern."
        )

    await database.log_install(
        agent_id, hostname, body.package_name, pkg["display_name"], "uninstall"
    )

    return SoftwareResponse(
        status="started",
        message=msg or f"Deinstallation von '{pkg['display_name']}' auf {hostname} gestartet.",
    )
