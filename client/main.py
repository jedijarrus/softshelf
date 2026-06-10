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


# Handle modulglobal halten — sonst raeumt der GC den Mutex weg
_instance_mutex = None


def _another_instance_running() -> bool:
    """Single-Instance-Guard via benannten Mutex (pro Session).

    Ohne den liefen bei Doppelstart (Autostart + manueller Klick) zwei
    Tray-Icons mit zwei Health-Threads parallel. 'Local\\' = Session-
    Namespace: bei RDP/Multi-User darf jede Session ihren eigenen Tray haben.
    """
    global _instance_mutex
    try:
        try:
            from _build_config import PRODUCT_SLUG as _slug
        except Exception:
            _slug = "Softshelf"
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        _instance_mutex = kernel32.CreateMutexW(
            None, False, f"Local\\{_slug}TrayInstance",
        )
        ERROR_ALREADY_EXISTS = 183
        return ctypes.get_last_error() == ERROR_ALREADY_EXISTS
    except Exception:
        return False


def main():
    if _another_instance_running():
        sys.exit(0)
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

    # Tray SOFORT mit dem lokalen Default starten — der Client-Titel vom
    # Proxy (Runtime-Setting) kommt async nach. Vorher blockierte der
    # HTTP-Call (timeout 3s + Retry ≈ 8s bei Server-down) den Tray-Start
    # bei jedem Login.
    tray = KioskTray(api, app_name=config.app_name)
    tray.start()

    def _late_client_meta():
        try:
            meta = api.get_client_config()
            name = meta.get("app_name")
            if name:
                tray.update_app_name(name)
        except Exception:
            pass
    threading.Thread(
        target=_late_client_meta, daemon=True, name="KioskClientMeta",
    ).start()

    # pywebview braucht mindestens ein Fenster vor start().
    # Erstelle ein verstecktes Dummy-Fenster das offen bleibt solange die App laeuft.
    _keeper = webview.create_window(
        "", hidden=True, width=1, height=1,
    )
    webview.start(debug=False, gui="edgechromium")


if __name__ == "__main__":
    main()
