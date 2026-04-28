"""
Softshelf Client - Entry Point (pywebview Edition)

Architecture:
  Main thread:  webview.start() - blocks, manages all windows
  Background 1: pystray - tray icon + menu
  Background 2: health monitor - polls /api/v1/health
"""
import ctypes
import os
import sys
import threading
from ctypes import wintypes

import webview

from config import load_config
from api_client import KioskApiClient
from ui.tray import KioskTray


def _running_in_session_0() -> bool:
    """True wenn dieser Prozess in Session 0 (SYSTEM) gestartet wurde.

    In Session 0 gibt es keinen interaktiven Desktop, kein Explorer und keine
    Notification-Area. Ein Tray-Icon wuerde dort unsichtbar im Vakuum landen
    und der Prozess als Zombie weiterlaufen. Wir weigern uns deshalb dort zu
    starten.
    """
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcessId.restype = wintypes.DWORD
        kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
        kernel32.ProcessIdToSessionId.argtypes = [
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ]
        sid = wintypes.DWORD()
        if not kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(),
                                              ctypes.byref(sid)):
            return False
        return sid.value == 0
    except Exception:
        return False


def main():
    if _running_in_session_0():
        try:
            try:
                from _build_config import PRODUCT_SLUG
                log_name = f"{PRODUCT_SLUG.lower()}_tray_session0.log"
            except Exception:
                log_name = "softshelf_tray_session0.log"
            log = os.path.join(
                os.environ.get("TEMP", r"C:\Windows\Temp"),
                log_name,
            )
            with open(log, "a", encoding="utf-8") as f:
                f.write("Tray refused to start in session 0\n")
        except Exception:
            pass
        sys.exit(0)

    try:
        config = load_config()
    except SystemExit:
        raise
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(
            0, str(e), "Softshelf - Fehler", 0x10,
        )
        sys.exit(1)

    api = KioskApiClient(config)

    # Client-Titel vom Proxy holen (Runtime-Setting).
    meta = api.get_client_config()
    app_name = meta.get("app_name") or config.app_name

    # Tray starten (eigener Thread via run_detached)
    tray = KioskTray(api, app_name=app_name)
    tray.start()

    # webview.start() blockiert den Main-Thread.
    # Alle Fenster werden vom Tray via webview.create_window() erzeugt.
    # Wir starten ohne initiales Fenster - der Tray oeffnet es bei Klick.
    webview.start(debug=False, gui="edgechromium")


if __name__ == "__main__":
    main()
