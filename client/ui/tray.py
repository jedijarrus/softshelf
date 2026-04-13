"""
System Tray Icon – pystray läuft im Hintergrund-Thread,
Fenster werden sicher über Qt-Signals auf dem Main-Thread geöffnet.

Health-Monitor: pollt den Proxy alle HEALTH_INTERVAL Sekunden. Bei einem
State-Übergang (online ↔ offline) wird eine Tray-Notification angezeigt
und das Icon visuell aktualisiert (rot bei offline).
"""
import threading
from PIL import Image, ImageDraw
import pystray

from PyQt5.QtCore import QObject, pyqtSignal, Qt
from PyQt5.QtWidgets import QApplication, QMessageBox

from api_client import KioskApiClient
from _version import __version__

HEALTH_INTERVAL = 60  # Sekunden zwischen Health-Checks


def _create_icon_image(offline: bool = False) -> Image.Image:
    """Schlichtes Quadrat mit weißem Innenrahmen — passt zum Web-Admin.
    Offline-Variante in Rot."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    fill = (220, 38, 38) if offline else (9, 9, 11)  # red-600 / zinc-950
    draw.rounded_rectangle([6, 6, 58, 58], radius=10, fill=fill)
    draw.rectangle([20, 20, 44, 44], outline=(255, 255, 255), width=3)
    return img


class KioskTray(QObject):
    _show_signal = pyqtSignal()
    _quit_signal = pyqtSignal()
    _health_signal = pyqtSignal(bool)  # True = online, False = offline

    def __init__(self, api: KioskApiClient, app_name: str = "Softshelf"):
        # Default oben muss konsistent zu config.py sein
        super().__init__()
        self._api = api
        self._app_name = app_name
        self._window = None
        self._icon: pystray.Icon | None = None
        # Health-Monitor State
        self._is_online: bool | None = None  # None bis erste Messung
        self._stop_health = threading.Event()
        self._health_thread: threading.Thread | None = None

        self._show_signal.connect(self._on_show)
        self._quit_signal.connect(self._on_quit)
        self._health_signal.connect(self._on_health_changed)

    def start(self):
        """Startet pystray im Hintergrund-Thread (blockiert NICHT)."""
        menu = pystray.Menu(
            pystray.MenuItem(self._app_name, self._request_open, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Beenden", self._request_quit),
        )
        self._icon = pystray.Icon(
            name="softshelf",
            icon=_create_icon_image(),
            title=f"{self._app_name}  v{__version__}",
            menu=menu,
        )
        self._icon.run_detached()
        self._start_health_monitor()

    def _start_health_monitor(self):
        """Hintergrund-Thread der periodisch /api/v1/health pollt."""
        def loop():
            while not self._stop_health.is_set():
                try:
                    ok = self._api.health_check()
                except Exception:
                    ok = False
                self._health_signal.emit(ok)
                if self._stop_health.wait(HEALTH_INTERVAL):
                    return
        self._health_thread = threading.Thread(
            target=loop, daemon=True, name="KioskHealth"
        )
        self._health_thread.start()

    def _on_health_changed(self, online: bool):
        """Qt-Slot: wird vom Health-Thread aufgerufen. Meldet State-Übergänge."""
        # Erste Messung — kein Toast bei online, nur bei initialem offline
        if self._is_online is None:
            self._is_online = online
            self._update_tray_visuals()
            if not online:
                self._notify_offline()
            return

        # offline → online
        if not self._is_online and online:
            self._is_online = True
            self._update_tray_visuals()
            self._notify_online()
            return

        # online → offline
        if self._is_online and not online:
            self._is_online = False
            self._update_tray_visuals()
            self._notify_offline()
            return

    def _update_tray_visuals(self):
        if not self._icon:
            return
        status = "Verbunden" if self._is_online else "OFFLINE"
        try:
            self._icon.title = f"{self._app_name}  v{__version__}  ·  {status}"
            self._icon.icon = _create_icon_image(offline=not self._is_online)
        except Exception:
            pass

    def _notify_offline(self):
        if not self._icon:
            return
        try:
            self._icon.notify(
                f"{self._app_name} kann den Server nicht erreichen. "
                "Software-Installation ist aktuell nicht möglich.",
                "Server nicht erreichbar",
            )
        except Exception:
            pass

    def _notify_online(self):
        if not self._icon:
            return
        try:
            self._icon.notify(
                "Verbindung zum Server wiederhergestellt.",
                self._app_name,
            )
        except Exception:
            pass

    # pystray-Callbacks (laufen im pystray-Thread → nur Signals emittieren)
    def _request_open(self, icon, item):
        self._show_signal.emit()

    def _request_quit(self, icon, item):
        self._quit_signal.emit()

    # Qt-Slots (laufen auf dem Main-Thread)
    def _on_show(self):
        if self._window is None:
            from ui.package_window import PackageWindow
            self._window = PackageWindow(self._api, app_name=self._app_name)
            self._window.setAttribute(Qt.WA_DeleteOnClose)
            self._window.destroyed.connect(self._on_window_closed)
        self._window.show()
        self._window.raise_()
        self._window.activateWindow()

    def _on_window_closed(self):
        self._window = None

    def _on_quit(self):
        # Confirm-Dialog – versehentliches Beenden vermeiden
        parent = self._window  # falls offen, sonst None → MessageBox auf Desktop
        reply = QMessageBox.question(
            parent,
            "Beenden",
            f"{self._app_name} wirklich beenden?\n\n"
            "Es startet beim nächsten Windows-Login automatisch wieder.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._stop_health.set()
        if self._health_thread:
            self._health_thread.join(timeout=6)
        if self._icon:
            self._icon.stop()
        QApplication.quit()
