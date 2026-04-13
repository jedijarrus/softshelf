"""
Softshelf Client – Entry Point
"""
import sys

from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt

from config import load_config
from api_client import KioskApiClient
from ui.tray import KioskTray


def main():
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
