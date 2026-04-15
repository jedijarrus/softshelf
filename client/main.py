"""
Softshelf Client – Entry Point
"""
import ctypes
import os
import sys
from ctypes import wintypes

from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt

from config import load_config
from api_client import KioskApiClient
from ui.tray import KioskTray


def _running_in_session_0() -> bool:
    """True wenn dieser Prozess in Session 0 (SYSTEM) gestartet wurde.

    In Session 0 gibt es keinen interaktiven Desktop, kein Explorer und keine
    Notification-Area. Ein Tray-Icon wuerde dort unsichtbar im Vakuum landen
    und der Prozess als Zombie weiterlaufen. Wir weigern uns deshalb dort zu
    starten — der Autostart in HKLM\\Run feuert sowieso erst wenn ein User sich
    interaktiv anmeldet, und der Setup-Installer benutzt CreateProcessAsUser
    fuer den initialen Launch.
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
        # Versuch ins Setup-Error-Log zu schreiben, damit das Phaenomen
        # nachvollziehbar wird falls jemand wundert wo der Tray ist.
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

    # Qt muss vor allem anderen initialisiert werden
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)   # Tray-App läuft weiter wenn Fenster zu
    app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    try:
        config = load_config()
    except RuntimeError as e:
        QMessageBox.critical(None, "Softshelf – Konfigurationsfehler", str(e))
        sys.exit(1)

    api = KioskApiClient(config)

    # Client-Titel vom Proxy holen (Runtime-Setting).
    # Fällt bei Fehler/Timeout auf den eingebauten Default zurück.
    meta = api.get_client_config()
    app_name = meta.get("app_name") or config.app_name

    tray = KioskTray(api, app_name=app_name)
    tray.start()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
