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
"""
import asyncio
import logging
import re
import secrets as _secrets
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import database
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
    Bei Erfolg wird agent_installations aktualisiert (für Versions-Tracking
    und 'Update pushen' im Admin-UI).
    """
    try:
        await TacticalClient().run_command(agent_id, cmd, timeout=600)
        logger.info("custom %s ok: %s auf %s", action, display_name, hostname)
        if action == "install":
            await database.set_agent_installation(agent_id, package_name, version_id)
        elif action == "uninstall":
            await database.delete_agent_installation(agent_id, package_name)
    except Exception as e:
        logger.warning("custom %s fehlgeschlagen: %s auf %s — %s",
                       action, display_name, hostname, e)


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


@router.post("/install", response_model=SoftwareResponse)
async def install_package(
    body: SoftwareRequest,
    token: dict = Depends(verify_machine_token),
):
    agent_id = token["agent_id"]
    hostname = token["hostname"]

    if not _is_safe_package_name(body.package_name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")

    pkg = await database.get_package(body.package_name)
    if not pkg:
        raise HTTPException(status_code=403, detail="Paket nicht freigegeben")

    if pkg.get("type") == "custom":
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
        try:
            msg = await TacticalClient().install_software(agent_id, body.package_name)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Fehler: {e}")

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

    if not _is_safe_package_name(body.package_name):
        raise HTTPException(status_code=400, detail="Ungültiger Paketname")

    pkg = await database.get_package(body.package_name)
    if not pkg:
        raise HTTPException(status_code=403, detail="Paket nicht freigegeben")

    if pkg.get("type") == "custom":
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
        # Choco-Uninstall (alte Logik)
        try:
            installed = await TacticalClient().get_installed_software(agent_id)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Tactical RMM nicht erreichbar: {e}")

        pkg_lower = body.package_name.lower()
        is_installed = any(
            pkg_lower in item.get("name", "").lower() or item.get("name", "").lower() in pkg_lower
            for item in installed
        )
        if not is_installed:
            raise HTTPException(status_code=409, detail="Paket ist nicht installiert")

        try:
            msg = await TacticalClient().uninstall_software(agent_id, body.package_name)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Fehler: {e}")

    await database.log_install(
        agent_id, hostname, body.package_name, pkg["display_name"], "uninstall"
    )

    return SoftwareResponse(
        status="started",
        message=msg or f"Deinstallation von '{pkg['display_name']}' auf {hostname} gestartet.",
    )
