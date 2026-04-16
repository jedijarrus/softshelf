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
    raw_output = ""
    try:
        raw_output = await TacticalClient().run_command(agent_id, cmd, timeout=600)
        if raw_output and raw_output.startswith('"'):
            try:
                import json as _json
                raw_output = _json.loads(raw_output)
            except Exception:
                pass
        logger.info("custom %s ok: %s auf %s", action, display_name, hostname)
        if action == "install":
            await database.set_agent_installation(agent_id, package_name, version_id)
        elif action == "uninstall":
            await database.delete_agent_installation(agent_id, package_name)
    except Exception as e:
        error_msg = str(e)[:300] or "unbekannter Fehler"
        raw_output = raw_output or error_msg
        logger.warning("custom %s fehlgeschlagen: %s auf %s — %s",
                       action, display_name, hostname, error_msg)

    try:
        full_out = (
            f"=== custom {action} {package_name} ===\n\n"
            f"{raw_output or '(kein Output)'}"
        )
        await database.upsert_action_result(
            agent_id, package_name, error_msg,
            full_output=full_out, action=action,
        )
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
_WINGET_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-+]{0,199}$")


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


def _build_winget_command(
    action: str,
    winget_id: str,
    version: str | None = None,
    include_scope_machine: bool = True,
) -> str:
    """
    Baut den PowerShell-Wrapper für winget install/upgrade/uninstall.
    Akzeptierte action-Werte: 'install', 'upgrade', 'uninstall'.

    `include_scope_machine=True` (Default) haengt `--scope machine` an —
    passt fuer machine-wide Installer. Bei per-user-only Paketen
    (LastPass, Bitwarden, Firefox-per-user) fuehrt das zum „No applicable
    installer found" Fehler. Layer-2 Fallback-Pfad setzt das dann auf
    False und laesst winget den Installer selbst picken, zusammen mit
    run_as_user=True damit der User-Kontext greift.

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
        scope_arg = "--scope machine " if include_scope_machine else ""
        winget_args = (
            f"{action} --id '{safe_id}' {scope_arg}--silent "
            f"--accept-package-agreements --accept-source-agreements "
            f"--disable-interactivity -h "
            f"{version_arg}"
        ).strip()

    # Selbe Marker-Strategie wie beim choco-Wrapper: wir exitieren IMMER
    # mit 0 und kodieren den echten winget-ExitCode in einer
    # ===SOFTSHELF_EXIT=== Marker-Zeile am Ende. Damit landet der gesamte
    # winget-stdout (inkl. Soft-Error-Texten wie „install technology is
    # different" oder „No available upgrade found") garantiert bei uns,
    # statt von einem PowerShell Write-Error-Record überdeckt zu werden.
    return f"""$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
{_PS_FIND_WINGET}
$wingetExe = Find-WingetExe
if (-not $wingetExe) {{
    Write-Output "winget ist nicht installiert (App Installer fehlt)"
    Write-Output "===SOFTSHELF_EXIT=== 9009"
    exit 0
}}
$out = (& $wingetExe {winget_args} 2>&1) -join "`n"
$code = $LASTEXITCODE
Write-Output $out
Write-Output "===SOFTSHELF_EXIT=== $code"
exit 0
"""


# winget druckt für manche „kann nicht upgraden, aber ich exitte trotzdem mit
# nothing-to-upgrade-Code" Fälle eine Soft-Error-Message in stdout. Ohne
# diese Erkennung würden wir die Aktion als Erfolg werten, der nachgelagerte
# Re-Scan würde den unveränderten State zeigen, und der Admin sieht keinen
# Hinweis warum nichts passiert ist. Hier matchen wir bekannte Patterns und
# heben sie aus dem stdout in agent_scan_meta.last_action_error.

# Patterns die "ist eigentlich Erfolg, kein Fehler-Toast bitte" bedeuten.
# Werden VOR den Hard-Error-Patterns geprueft.
_WINGET_SUCCESS_HINTS: list[str] = [
    "no newer package versions are available",   # 1Password-Case: installiert, nichts zu tun
    "no installed package found matching input criteria for upgrade",  # gleicher Effekt
]

# Patterns die als HARD ERROR gewertet werden (auch bei "Erfolgs"-ExitCode).
_WINGET_SOFT_ERROR_PATTERNS: list[tuple[str, str]] = [
    (
        "install technology is different",
        "winget kann nicht in-place upgraden — die neue Version verwendet "
        "eine andere Installer-Technologie als die installierte. Vorher "
        "deinstallieren oder ein anderes Update-Verfahren nutzen.",
    ),
    (
        "does not apply to your system or requirements",
        "Eine neuere Version existiert im winget-Catalog, passt aber nicht "
        "zu diesem System (Architektur, Windows-Version oder Dependencies). "
        "Paket aus dem Profil entfernen oder eine andere Version pinnen.",
    ),
    (
        "no applicable installer found",
        "winget hat keinen passenden Installer fuer dieses System gefunden. "
        "Bei --scope machine: das Paket ist nur per-user installierbar — "
        "winget_scope auf 'auto' oder 'user' aendern.",
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
    """Sucht im winget-Output nach bekannten 'fake success' Mustern.

    Reihenfolge:
      1. Erfolgs-Hints (z.B. "no newer package versions are available") → None
      2. Hard-Error-Patterns → Fehlermeldung
      3. Sonst → None
    """
    if not output:
        return None
    lower = output.lower()
    # 1. Erst die echten Erfolgs-Hints raussortieren — sonst landen sie in
    #    den Hard-Error-Patterns die "no installed package found" matchen.
    for hint in _WINGET_SUCCESS_HINTS:
        if hint in lower:
            return None
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

# winget exit codes die als "ist eigentlich Erfolg" gewertet werden:
#   0           - normaler Erfolg
#   -1978335212 - schon installiert / kein anwendbarer Installer
#   -1978335189 - kein Upgrade verfügbar (= bereits aktuell)
_WINGET_SUCCESS_CODES = {0, -1978335212, -1978335189}

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
        "please also run the command",
        "Choco hat ein abhängiges Sub-Paket nicht entfernen können (typisch bei Metapaketen wie 'vlc' → 'vlc.install'). Müsste eigentlich von --remove-dependencies abgedeckt sein — falls nicht, manuell auf dem Agent das Sub-Paket hinterher uninstallen.",
    ),
    (
        "is not installed. cannot uninstall",
        "Choco meldet das Paket als nicht installiert — entweder schon entfernt, oder als Metapaket nur ein Marker für eine andere Choco-Variante (z.B. 'vlc' vs 'vlc.install').",
    ),
    (
        "the install of",
        "Choco-Install fehlgeschlagen — siehe Choco-Log auf dem Agent (C:\\ProgramData\\chocolatey\\logs\\chocolatey.log).",
    ),
]

# Pattern für „Chocolatey installed X/Y packages" wo X < Y (partial success)
_CHOCO_PARTIAL_RE = re.compile(
    r"chocolatey\s+(?:installed|uninstalled)\s+(\d+)/(\d+)\s+packages?"
)


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

    # Partial success: „Chocolatey uninstalled 1/2 packages" — exit ist 0
    # weil mindestens eines erfolgreich war, aber wir wollen den User
    # informieren dass nicht alles weg ist.
    m = _CHOCO_PARTIAL_RE.search(lower)
    if m:
        done = int(m.group(1))
        total = int(m.group(2))
        if done < total:
            for needle, message in _CHOCO_SOFT_ERROR_PATTERNS:
                if needle in lower:
                    return f"Nur {done} von {total} Choco-Paketen erledigt — {message}"
            return f"Nur {done} von {total} Choco-Paketen erledigt — siehe Choco-Log auf dem Agent."

    if "0/1 packages" in lower or "1/1 packages failed" in lower:
        for needle, message in _CHOCO_SOFT_ERROR_PATTERNS:
            if needle in lower:
                return message
        return "Choco-Install fehlgeschlagen — Detail im Choco-Log auf dem Agent"

    # Choco hat einen interaktiven Prompt aufgerufen (passiert bei
    # Metapaketen wenn --remove-dependencies trotzdem nicht greift)
    if "timeout or your choice of" in lower or "is not a valid selection" in lower:
        return "Choco wartete auf eine interaktive Antwort und hat den Timeout abgewartet — wahrscheinlich ein Metapaket bei dem ein abhängiges Sub-Paket geprüft werden sollte. Im Choco-Log auf dem Agent steht der Kontext."
    return None


_CHOCO_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,99}$")

# Marker den unsere PowerShell-Wrapper am Ende des stdout schreiben damit
# wir den echten ExitCode kennen ohne dass wir uns auf nicht-200-Responses
# von Tactical verlassen müssen
_EXIT_MARKER_RE = re.compile(r"===SOFTSHELF_EXIT===\s*(-?\d+)")


def _extract_exit_marker(output: str) -> tuple[int | None, str]:
    """Sucht im stdout den Marker `===SOFTSHELF_EXIT=== <code>` und
    entfernt die Marker-Zeile aus dem Output. Returns (code, cleaned_output).
    Wenn kein Marker gefunden wird, returns (None, original_output)."""
    if not output:
        return None, output
    m = _EXIT_MARKER_RE.search(output)
    if not m:
        return None, output
    code = int(m.group(1))
    cleaned = output[:m.start()] + output[m.end():]
    return code, cleaned.rstrip()


_CHOCO_VERSION_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-+]{0,49}$")


def _build_choco_command(action: str, package_name: str, version: str | None = None) -> str:
    """
    Baut den PowerShell-Wrapper für `choco install/uninstall <name>`. Wird
    via Tactical run_command als SYSTEM ausgeführt, output kommt zurück
    damit wir Soft-Errors detecten und im UI zeigen können.

    Optional version pin (nur bei install): erzwingt eine bestimmte choco-
    Paket-Version via `--version=...`.
    """
    if action not in ("install", "uninstall"):
        raise ValueError(f"unsupported choco action: {action}")
    if not _CHOCO_NAME_RE.fullmatch(package_name):
        raise HTTPException(status_code=400, detail=f"Ungültiger choco-Paketname: {package_name!r}")
    if version is not None and not _CHOCO_VERSION_RE.fullmatch(version):
        raise HTTPException(status_code=400, detail=f"Ungültige choco-Version: {version!r}")
    safe = package_name  # regex-validiert, keine Escapes nötig
    if action == "install":
        ver_arg = f" --version='{version}'" if version else ""
        choco_args = f"install '{safe}' -y --no-progress --limit-output{ver_arg}"
    else:
        # --remove-dependencies (-x) entfernt zusätzlich alle Sub-Pakete die
        # NUR von diesem Paket benötigt wurden. Wichtig für Metapakete wie
        # 'vlc' das eigentlich 'vlc.install' wrappt — ohne diesen Flag
        # bleibt 'vlc.install' nach `choco uninstall vlc` zurück und choco
        # fragt interaktiv nach (Timeout = Sub-Paket wird nicht entfernt).
        # --force: bricht nicht ab wenn der Uninstaller fehlt oder
        # Dependencies im Weg sind — räumt auch ghost-packages auf (z.B.
        # peazip wo der App-Ordner weg ist, aber C:\ProgramData\chocolatey\
        # lib\peazip\ noch existiert).
        # --skip-autouninstaller: vermeidet dass choco nachträglich noch
        # den MSI/EXE-Uninstaller startet wenn er in der DB gefunden wird,
        # aber das App-Verzeichnis schon weg ist. Verhindert „uninstaller
        # not found" Hard-Error bei ghost-installs.
        choco_args = (
            f"uninstall '{safe}' -y --force --remove-dependencies "
            f"--skip-autouninstaller --no-progress --limit-output"
        )

    # Wichtig: Wir exitieren IMMER mit 0 und kodieren den echten ExitCode
    # in einer Marker-Zeile am Ende des stdout. Hintergrund: PowerShell's
    # `Write-Error` + `exit non-zero` erzeugt einen Error-Record mit dem
    # gesamten Script-Body als InvocationInfo, und Tactical's run_command-
    # Response enthält dann NUR diesen Error-Record — die `Write-Output`-
    # Zeilen mit dem echten choco-stdout (inkl. wertvoller Fehlermeldungen
    # wie „vlc is not installed") gehen verloren. Mit „immer exit 0" landen
    # alle stdout-Zeilen sauber bei uns, und Python parsed den Marker.
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
    Write-Output "choco ist nicht installiert (Chocolatey fehlt auf dem Agent)"
    Write-Output "===SOFTSHELF_EXIT=== 9009"
    exit 0
}}
$out = (& $choco {choco_args} 2>&1) -join "`n"
$code = $LASTEXITCODE
Write-Output $out
Write-Output "===SOFTSHELF_EXIT=== $code"
exit 0
"""


async def _run_choco_one(agent_id: str, cmd: str) -> tuple[int | None, str]:
    """Einzelner Tactical run_command-Aufruf für eine fertige choco-Powershell.
    Returns (real_exit_code_or_None, cleaned_output).

    Der Wrapper exitiert immer mit 0 und kodiert den echten ExitCode in einer
    `===SOFTSHELF_EXIT=== <code>` Marker-Zeile am Ende. Wir extrahieren die
    und geben sie zusammen mit dem geputzten stdout zurück. Wenn der Marker
    fehlt (z.B. Tactical-Verbindungsfehler), returns (None, error_text)."""
    try:
        raw_output = await TacticalClient().run_command(agent_id, cmd, timeout=600)
        if raw_output and raw_output.startswith('"'):
            try:
                import json as _json
                raw_output = _json.loads(raw_output)
            except Exception:
                pass
    except Exception as e:
        return None, str(e)
    code, cleaned = _extract_exit_marker(raw_output or "")
    return code, cleaned


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
    last_action_error in scan_meta, chain targeted re-scan.

    Spezialfall für uninstall: wenn das Metapackage nicht installiert ist,
    aber die `<name>.install`-Variante existiert (z.B. 'vlc' weg, 'vlc.install'
    noch da), retry mit dem .install-Namen. Behebt Orphans aus früheren
    halb-fehlgeschlagenen Uninstalls."""
    exit_code, raw_output = await _run_choco_one(agent_id, cmd)
    soft_err = _detect_choco_soft_error(raw_output, exit_code)
    success = exit_code in _CHOCO_SUCCESS_CODES and not soft_err

    # Auto-Retry: wenn uninstall fehlschlägt UND der stdout sagt
    # „is not installed" UND der Paket-Name endet nicht schon auf .install,
    # versuche `<name>.install` als Fallback. Behebt Orphans aus früheren
    # halb-fehlgeschlagenen Uninstalls (z.B. vlc weg, vlc.install noch da).
    retried_name: str | None = None
    if (
        action == "uninstall"
        and not success
        and "is not installed" in (raw_output or "").lower()
        and not package_name.endswith(".install")
        and _CHOCO_NAME_RE.fullmatch(f"{package_name}.install")
    ):
        retry_target = f"{package_name}.install"
        logger.info(
            "choco uninstall: %s nicht installiert, retry mit %s",
            package_name, retry_target,
        )
        retry_cmd = _build_choco_command("uninstall", retry_target)
        retry_exit, retry_output = await _run_choco_one(agent_id, retry_cmd)
        retry_soft_err = _detect_choco_soft_error(retry_output, retry_exit)
        if retry_exit in _CHOCO_SUCCESS_CODES and not retry_soft_err:
            success = True
            raw_output = retry_output
            soft_err = None
            retried_name = retry_target
        else:
            success = False
            soft_err = (
                f"Weder '{package_name}' noch '{retry_target}' konnten "
                f"deinstalliert werden. "
                f"{retry_soft_err or (retry_output or '')[:200]}"
            )

    error_msg = soft_err if soft_err else None
    if error_msg:
        logger.warning(
            "choco %s soft-error für %s auf %s: %s",
            action, display_name, hostname, error_msg,
        )
    elif not success:
        error_msg = f"choco beendete unerwartet (ExitCode {exit_code})"
        logger.warning(
            "choco %s fehlgeschlagen: %s auf %s — exit=%s",
            action, display_name, hostname, exit_code,
        )
    else:
        logger.info(
            "choco %s ok: %s auf %s%s",
            action, display_name, hostname,
            f" (via {retried_name})" if retried_name else "",
        )

    # Tracking nur updaten wenn alles sauber durch ist
    if success and not error_msg:
        try:
            if action == "install":
                await database.set_agent_installation(agent_id, package_name, None)
            else:
                await database.delete_agent_installation(agent_id, package_name)
        except Exception as e:
            logger.warning("agent_installations update failed: %s", e)

    try:
        # Voller Output fuer das Fehler-Detail-Modal mitspeichern. Mit dem
        # ExitCode-Tag im Header damit der Admin sofort sieht was los war.
        full_out = (
            f"=== choco {action} {package_name} ===\n"
            f"ExitCode: {exit_code}\n\n"
            f"{raw_output or '(kein Output)'}"
        )
        await database.upsert_action_result(
            agent_id, package_name, error_msg,
            full_output=full_out, action=action,
        )
    except Exception as e:
        logger.warning("upsert_action_result choco failed: %s", e)

    # Targeted Re-Scan via choco_scanner — refresht agent_choco_state
    try:
        await choco_scanner.scan_agent(agent_id)
    except Exception as e:
        logger.warning("post-action choco rescan failed for %s: %s", agent_id, e)


# winget ExitCode der "kein Installer fuer dieses System / scope" meint.
# Tritt auf wenn wir --scope machine erzwingen, das Paket aber nur per-user
# installierbar ist (LastPass, Bitwarden, Firefox-per-user, 1Password-Store).
_WINGET_NO_APPLICABLE_INSTALLER = -1978335216


async def _run_one_winget(
    agent_id: str, cmd: str, run_as_user: bool
) -> tuple[int | None, str, str | None]:
    """Einzelner Tactical run_command-Aufruf fuer eine fertige winget-
    PowerShell. Returns (exit_code, cleaned_output, exception_msg_or_none).
    """
    try:
        raw_output = await TacticalClient().run_command(
            agent_id, cmd, timeout=600, run_as_user=run_as_user,
        )
        if raw_output and raw_output.startswith('"'):
            try:
                import json as _json
                raw_output = _json.loads(raw_output)
            except Exception:
                pass
    except Exception as e:
        return None, "", str(e)[:300]
    code, cleaned = _extract_exit_marker(raw_output or "")
    return code, cleaned, None


async def _run_winget_command_bg(
    agent_id: str,
    hostname: str,
    package_name: str,
    display_name: str,
    cmd: str,
    action: str,
    winget_id: str,
    winget_scope: str = "auto",
    version: str | None = None,
):
    """
    Background-Task für winget install/upgrade/uninstall via Tactical run-cmd.
    Nach Completion (egal ob ok oder Fehler) wird ein targeted Re-Scan
    getriggert damit der Kiosk-State frisch ist — bei Fehler dokumentiert
    der Re-Scan dass das Paket NICHT installiert ist. Bei „Soft-Errors"
    (winget exited mit Success-Code aber druckt einen Fehler in stdout)
    wird die Meldung in agent_scan_meta.last_action_error persistiert
    damit das Admin-UI sie als Banner anzeigen kann.

    Layer-2-Fallback:
      winget_scope == 'auto'    → erst --scope machine (als SYSTEM), bei
                                   ExitCode -1978335216 retry OHNE --scope
                                   machine im User-Kontext (run_as_user).
      winget_scope == 'machine' → nur --scope machine, kein Fallback.
      winget_scope == 'user'    → direkt ohne --scope machine im User-Kontext.

    Der uebergebene `cmd` ist der initial gebaute Wrapper. Fuer den Fallback-
    Pfad bauen wir den user-scope-Wrapper selbst hier um Parameter zu behalten.
    """
    scope = (winget_scope or "auto").lower()
    if scope not in ("auto", "machine", "user"):
        scope = "auto"

    # Uninstall ignoriert scope komplett (der Uninstall-Wrapper haengt kein
    # --scope an; per-user ARP-Eintraege muss der User selber uninstallieren
    # — wenn das bei uns als SYSTEM nicht geht, liefert winget
    # NO_UNINSTALL_INFO_FOUND und der Fallback-Retry als User ist hier
    # ebenfalls sinnvoll.)
    if action == "uninstall":
        # SYSTEM-Versuch zuerst, bei per-user-Fehler im User-Kontext retry.
        first_as_user = False
    elif scope == "user":
        first_as_user = True
        # Command neu bauen ohne --scope machine
        cmd = _build_winget_command(action, winget_id, version, include_scope_machine=False)
    else:
        first_as_user = False

    error_msg: str | None = None
    raw_output = ""
    exit_code, raw_output, exc = await _run_one_winget(agent_id, cmd, first_as_user)
    if exc:
        error_msg = exc

    fallback_used = False

    # Layer-2 Fallback: auto-scope + NO_APPLICABLE_INSTALLER → retry als User
    should_fallback = (
        scope == "auto"
        and action in ("install", "upgrade")
        and exit_code == _WINGET_NO_APPLICABLE_INSTALLER
    )
    # Uninstall-Retry: bei NO_UNINSTALL_INFO_FOUND als User versuchen
    uninstall_fallback = (
        action == "uninstall"
        and exit_code is not None
        and exit_code not in _WINGET_SUCCESS_CODES
        and ("no uninstall information found" in (raw_output or "").lower()
             or exit_code in (-1978335162, _WINGET_NO_APPLICABLE_INSTALLER))
    )

    if should_fallback or uninstall_fallback:
        logger.info(
            "winget %s per-user fallback: %s auf %s (exit=%s)",
            action, display_name, hostname, exit_code,
        )
        user_cmd = (
            _build_winget_command(action, winget_id, version, include_scope_machine=False)
            if action != "uninstall"
            else cmd  # uninstall-cmd ist schon scope-frei
        )
        retry_exit, retry_output, retry_exc = await _run_one_winget(
            agent_id, user_cmd, run_as_user=True,
        )
        if retry_exc:
            # Erster Versuch hatte vermutlich den useful output — den
            # Retry-Exc-Text nur anhaengen als Zusatzinfo.
            raw_output = (
                f"{raw_output}\n"
                f"--- per-user Retry fehlgeschlagen ---\n"
                f"{retry_exc}"
            )
        else:
            # Retry hat klare Antwort — das nehmen wir als Wahrheit.
            fallback_used = True
            raw_output = (
                f"=== machine scope Versuch ===\n{raw_output}\n\n"
                f"=== per-user fallback (run_as_user) ===\n{retry_output}"
            )
            exit_code = retry_exit

    # Analyse Phase
    if error_msg is None:
        soft_err = _detect_winget_soft_error(raw_output)
        if soft_err:
            error_msg = soft_err
            logger.warning(
                "winget %s soft-error für %s auf %s (exit=%s): %s",
                action, display_name, hostname, exit_code, soft_err,
            )
        elif exit_code is not None and exit_code not in _WINGET_SUCCESS_CODES:
            # Special-Case fuer per-user-uninstall die als SYSTEM gar nicht
            # sichtbar sind — ueberlappt mit dem uninstall_fallback oben,
            # aber falls der Fallback auch keinen Erfolg hatte, geben wir
            # eine hilfreiche Meldung.
            if (
                action == "uninstall"
                and exit_code == -1978335162
            ):
                error_msg = (
                    "winget hat keine Uninstall-Information gefunden. "
                    "Vermutlich ein per-user Install der fuer SYSTEM nicht "
                    "sichtbar ist — ein interaktiver User muss eingeloggt "
                    "sein, oder das Paket ueber die Windows Apps-Liste "
                    "entfernen."
                )
            else:
                error_msg = f"winget {action} beendete mit ExitCode {exit_code}"
            logger.warning(
                "winget %s unhandled exit für %s auf %s: %s",
                action, display_name, hostname, exit_code,
            )
        else:
            logger.info(
                "winget %s ok: %s auf %s%s",
                action, display_name, hostname,
                " (per-user fallback)" if fallback_used else "",
            )

    # Erfolg ODER „bereits vorhanden" → in agent_installations tracken.
    # Hintergrund: winget kennt manche ARP-Pakete nur heuristisch (z.B.
    # 1Password installiert via .exe vom Hersteller — winget findet's
    # via DisplayName-Match, aber `winget list --id` und `winget export`
    # zeigen es nicht). agent_winget_state bleibt dann leer und der
    # Kiosk-Client sieht das Paket als „nicht installiert" obwohl es da
    # ist. agent_installations dient als zweite Tracking-Quelle.
    if not error_msg and action in ("install", "upgrade"):
        try:
            await database.set_agent_installation(agent_id, package_name, None)
        except Exception as e:
            logger.warning("agent_installations winget update failed: %s", e)
    elif not error_msg and action == "uninstall":
        try:
            await database.delete_agent_installation(agent_id, package_name)
        except Exception as e:
            logger.warning("agent_installations winget delete failed: %s", e)

    # Action-Result in scan_meta persistieren (auch bei Erfolg, dann mit error=None,
    # damit der vorherige Fehler-Banner weggeht)
    try:
        scope_tag = f" scope={scope}" + (" +fallback" if fallback_used else "")
        full_out = (
            f"=== winget {action} {winget_id}{scope_tag} ===\n"
            f"ExitCode: {exit_code}\n\n"
            f"{raw_output or '(kein Output)'}"
        )
        await database.upsert_action_result(
            agent_id, package_name, error_msg,
            full_output=full_out, action=action,
        )
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
        scope = pkg.get("winget_scope") or "auto"
        ver = pkg.get("winget_version")
        include_scope_machine = scope != "user"
        cmd = _build_winget_command(
            action, body.package_name, ver,
            include_scope_machine=include_scope_machine,
        )
        _spawn_bg(_run_winget_command_bg(
            agent_id, hostname, body.package_name, pkg["display_name"],
            cmd, action, body.package_name,
            winget_scope=scope, version=ver,
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
        scope = pkg.get("winget_scope") or "auto"
        _spawn_bg(_run_winget_command_bg(
            agent_id, hostname, body.package_name, pkg["display_name"],
            cmd, "uninstall", body.package_name,
            winget_scope=scope,
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


# ── Shared dispatch helpers (für admin-driven bulk + profile apply) ───────────

async def dispatch_install_for_agent(
    agent_id: str,
    hostname: str,
    pkg: dict,
    version_pin: str | None = None,
) -> dict:
    """Spawned einen install (oder upgrade fuer winget) für genau ein
    (Agent, Paket)-Pair und logged in install_log.

    Wird sowohl vom admin per-package-install endpoint als auch vom Profile-
    Apply und Bulk-Install benutzt — der ganze type-dispatch sitzt hier.

    Returns ein dict mit Metadaten fuer den Caller (action, package_name).
    """
    package_name = pkg["name"]
    ptype = pkg.get("type") or "choco"

    if ptype == "winget":
        _check_winget_id(package_name)
        # winget braucht install vs. upgrade entscheidung
        state = await database.get_agent_winget_state(agent_id)
        st = state.get(package_name)
        if st and st.get("installed_version") and st.get("available_version"):
            action = "upgrade"
        else:
            action = "install"
        ver = version_pin or pkg.get("winget_version")
        scope = pkg.get("winget_scope") or "auto"
        include_scope_machine = scope != "user"
        cmd = _build_winget_command(
            action, package_name, ver,
            include_scope_machine=include_scope_machine,
        )
        _spawn_bg(_run_winget_command_bg(
            agent_id, hostname, package_name, pkg["display_name"],
            cmd, action, package_name,
            winget_scope=scope, version=ver,
        ))

    elif ptype == "custom":
        if not _is_safe_package_name(package_name):
            raise HTTPException(status_code=400, detail="Ungültiger Paketname")
        if not pkg.get("sha256"):
            raise HTTPException(status_code=400, detail="Custom-Paket ohne aktive Version")
        cmd = await _build_install_command(pkg, agent_id)
        _spawn_bg(_run_custom_command_bg(
            agent_id, hostname, package_name, pkg["display_name"],
            cmd, "install", pkg.get("current_version_id"),
        ))
        action = "install"

    else:
        if not _is_safe_package_name(package_name):
            raise HTTPException(status_code=400, detail="Ungültiger Paketname")
        cmd = _build_choco_command("install", package_name, version=version_pin)
        _spawn_bg(_run_choco_command_bg(
            agent_id, hostname, package_name, pkg["display_name"],
            cmd, "install",
        ))
        action = "install"

    await database.log_install(
        agent_id, hostname, package_name, pkg["display_name"], "install"
    )
    return {"action": action, "package_name": package_name, "type": ptype}


async def dispatch_upgrade_for_agent(
    agent_id: str,
    hostname: str,
    pkg: dict,
) -> dict:
    """Spawned eine reine Upgrade-Operation. Fuer winget = upgrade-action,
    fuer choco = install (idempotent, nimmt latest), fuer custom = install
    mit der aktuellen current_version_id (zaehlt als push-update).
    """
    return await dispatch_install_for_agent(agent_id, hostname, pkg, version_pin=None)


async def dispatch_uninstall_for_agent(
    agent_id: str,
    hostname: str,
    pkg: dict,
) -> dict:
    """Spawned uninstall-Aktion fuer ein (Agent, Paket)-Pair.

    Wird vom Profile-Unassign-mit-Uninstall-Pfad und vom existing per-package
    Admin-Uninstall-Endpoint genutzt. Type-dispatch identisch zum Install-Pfad.
    """
    package_name = pkg["name"]
    ptype = pkg.get("type") or "choco"

    if ptype == "winget":
        _check_winget_id(package_name)
        cmd = _build_winget_command("uninstall", package_name)
        scope = pkg.get("winget_scope") or "auto"
        _spawn_bg(_run_winget_command_bg(
            agent_id, hostname, package_name, pkg["display_name"],
            cmd, "uninstall", package_name,
            winget_scope=scope,
        ))

    elif ptype == "custom":
        if not _is_safe_package_name(package_name):
            raise HTTPException(status_code=400, detail="Ungültiger Paketname")
        uninstall_cmd = (pkg.get("uninstall_cmd") or "").strip()
        if not uninstall_cmd:
            raise HTTPException(
                status_code=400,
                detail=f"Paket {package_name!r} hat keinen Uninstall-Command hinterlegt",
            )
        ps_cmd = _build_uninstall_command(uninstall_cmd)
        _spawn_bg(_run_custom_command_bg(
            agent_id, hostname, package_name, pkg["display_name"],
            ps_cmd, "uninstall", pkg.get("current_version_id"),
        ))

    else:
        if not _is_safe_package_name(package_name):
            raise HTTPException(status_code=400, detail="Ungültiger Paketname")
        cmd = _build_choco_command("uninstall", package_name)
        _spawn_bg(_run_choco_command_bg(
            agent_id, hostname, package_name, pkg["display_name"],
            cmd, "uninstall",
        ))

    await database.log_install(
        agent_id, hostname, package_name, pkg["display_name"], "uninstall"
    )
    return {"action": "uninstall", "package_name": package_name, "type": ptype}
