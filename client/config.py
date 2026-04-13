"""
Client-Konfiguration.

ProxyUrl und MachineToken werden von setup.exe in die Registry geschrieben:
  HKLM\SOFTWARE\Softshelf\ProxyUrl
  HKLM\SOFTWARE\Softshelf\MachineToken

Vorteil gegenueber Credential Manager: Funktioniert auch wenn setup.exe
als SYSTEM (Tactical RMM) ausgefuehrt wird - softshelf.exe liest die Werte
dann als normaler Benutzer.
"""
import os
import sys
import winreg
from dataclasses import dataclass

_REG_PATH = r"SOFTWARE\Softshelf"


@dataclass
class ClientConfig:
    proxy_url: str
    machine_token: str
    app_name: str = "Softshelf"


def load_config() -> ClientConfig:
    proxy_url = os.environ.get("SOFTSHELF_PROXY_URL", "").rstrip("/")
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
            "Proxy-URL nicht konfiguriert.\n"
            "Bitte das Softshelf neu installieren (softshelf-setup.exe)."
        )

    if not token:
        _fatal(
            "Kein Machine Token gefunden.\n"
            "Bitte das Softshelf neu installieren (softshelf-setup.exe)."
        )

    return ClientConfig(proxy_url=proxy_url, machine_token=token)


def _fatal(msg: str) -> None:
    try:
        from PyQt5.QtWidgets import QApplication, QMessageBox
        if not QApplication.instance():
            QApplication(sys.argv)
        QMessageBox.critical(None, "Softshelf – Konfigurationsfehler", msg)
    except Exception:
        print(f"Konfigurationsfehler: {msg}", file=sys.stderr)
    sys.exit(1)
