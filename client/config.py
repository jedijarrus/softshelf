"""
Client-Konfiguration.

ProxyUrl und MachineToken werden von setup.exe in die Registry geschrieben:
  HKLM\\SOFTWARE\\<PRODUCT_SLUG>\\ProxyUrl
  HKLM\\SOFTWARE\\<PRODUCT_SLUG>\\MachineToken

Vorteil gegenueber Credential Manager: Funktioniert auch wenn setup.exe
als SYSTEM (Tactical RMM) ausgefuehrt wird - der Client liest die Werte
dann als normaler Benutzer.

PRODUCT_SLUG wird vom Builder in _build_config.py eingebacken und steuert
Registry-Pfad und Namen der System-Umgebungsvariable (fuer CI-Branding).
"""
import ctypes
import os
import re
import sys
import winreg
from dataclasses import dataclass

try:
    from _build_config import PRODUCT_SLUG as _SLUG
except Exception:
    _SLUG = "Softshelf"

# Defense in depth: ein unerwarteter Wert (alte _build_config.py, manuell
# editiertes File) darf keine Pfad-Traversal- oder Registry-Escapes ermoeglichen.
if not re.match(r"^[A-Za-z][A-Za-z0-9_-]{0,30}$", _SLUG):
    _SLUG = "Softshelf"

PRODUCT_SLUG = _SLUG
_REG_PATH    = rf"SOFTWARE\{PRODUCT_SLUG}"
# Env-Var-Name muss valid sein: nur [A-Z0-9_], hyphens werden zu _
_ENV_VAR     = PRODUCT_SLUG.upper().replace("-", "_") + "_PROXY_URL"


@dataclass
class ClientConfig:
    proxy_url: str
    machine_token: str
    app_name: str = "Softshelf"


def load_config() -> ClientConfig:
    proxy_url = os.environ.get(_ENV_VAR, "").rstrip("/")
    token: str | None = None

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _REG_PATH) as k:
            if not proxy_url:
                proxy_url = winreg.QueryValueEx(k, "ProxyUrl")[0].rstrip("/")
            token = winreg.QueryValueEx(k, "MachineToken")[0]
    except FileNotFoundError:
        pass

    if not proxy_url:
        _fatal(
            f"Proxy-URL nicht konfiguriert.\n"
            f"Bitte {PRODUCT_SLUG} neu installieren ({PRODUCT_SLUG}-setup.exe)."
        )

    if not token:
        _fatal(
            f"Kein Machine Token gefunden.\n"
            f"Bitte {PRODUCT_SLUG} neu installieren ({PRODUCT_SLUG}-setup.exe)."
        )

    return ClientConfig(proxy_url=proxy_url, machine_token=token)


def _fatal(msg: str) -> None:
    """Zeigt eine native Windows MessageBox (kein PyQt5 noetig)."""
    try:
        ctypes.windll.user32.MessageBoxW(
            0,
            msg,
            f"{PRODUCT_SLUG} \u2014 Konfigurationsfehler",
            0x10,  # MB_ICONERROR
        )
    except Exception:
        print(f"Konfigurationsfehler: {msg}", file=sys.stderr)
    sys.exit(1)
