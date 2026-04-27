"""
System Tray Icon – pystray läuft im Hintergrund-Thread,
Fenster werden sicher über Qt-Signals auf dem Main-Thread geöffnet.

Health-Monitor: pollt den Proxy alle HEALTH_INTERVAL Sekunden. Bei einem
State-Übergang (online ↔ offline) wird das Icon visuell aktualisiert
(rot bei offline) und das PackageWindow informiert (In-Window-Banner
statt aufdringlicher OS-Toast-Notifications).

Custom Icon: beim Start wird versucht das Branding-Icon vom Server zu
laden (/api/v1/icon). Wenn vorhanden wird es als Tray-Icon verwendet,
sonst fällt es auf das generierte Fallback-Icon zurück.
"""
import io
import threading
from PIL import Image, ImageDraw
import pystray

from PyQt5.QtCore import QObject, pyqtSignal, Qt
from PyQt5.QtWidgets import QApplication, QMessageBox

from api_client import KioskApiClient
from _version import __version__

HEALTH_INTERVAL = 60  # Sekunden zwischen Health-Checks


def _create_fallback_icon(offline: bool = False) -> Image.Image:
    """Generiertes Fallback-Icon wenn kein Custom-Icon vom Server geladen."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    fill = (220, 38, 38) if offline else (9, 9, 11)  # red-600 / zinc-950
    draw.rounded_rectangle([6, 6, 58, 58], radius=10, fill=fill)
    draw.rectangle([20, 20, 44, 44], outline=(255, 255, 255), width=3)
    return img


def _tint_icon_red(img: Image.Image) -> Image.Image:
    """Overlay: Custom-Icon mit rotem Warndot unten rechts."""
    out = img.copy().convert("RGBA").resize((64, 64), Image.LANCZOS)
    draw = ImageDraw.Draw(out)
    # Roter Dot mit weißem Ring (unten rechts)
    draw.ellipse([42, 42, 62, 62], fill=(255, 255, 255))
    draw.ellipse([44, 44, 60, 60], fill=(220, 38, 38))
    return out


class KioskTray(QObject):
    _show_signal = pyqtSignal()
    _quit_signal = pyqtSignal()
    _health_signal = pyqtSignal(bool)   # True = online, False = offline
    _reboot_signal = pyqtSignal(dict)   # pending reboot action vom Proxy

    def __init__(self, api: KioskApiClient, app_name: str = "Softshelf"):
        super().__init__()
        self._api = api
        self._app_name = app_name
        self._window = None
        self._icon: pystray.Icon | None = None
        self._custom_icon: Image.Image | None = None  # vom Server geladen
        # Health-Monitor State
        self._is_online: bool | None = None  # None bis erste Messung
        self._stop_health = threading.Event()
        self._health_thread: threading.Thread | None = None

        self._show_signal.connect(self._on_show)
        self._quit_signal.connect(self._on_quit)
        self._health_signal.connect(self._on_health_changed)
        self._reboot_signal.connect(self._on_reboot_request)
        self._shown_reboot_runs: set = set()

    def start(self):
        """Startet pystray im Hintergrund-Thread (blockiert NICHT)."""
        self._load_custom_icon()
        menu = pystray.Menu(
            pystray.MenuItem(self._app_name, self._request_open, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Beenden", self._request_quit),
        )
        self._icon = pystray.Icon(
            name="softshelf",
            icon=self._get_icon_image(offline=False),
            title=f"{self._app_name}  v{__version__}",
            menu=menu,
        )
        self._icon.run_detached()
        self._start_health_monitor()

    def _load_custom_icon(self):
        """Versucht das Branding-Icon vom Server zu laden (best-effort)."""
        try:
            data = self._api.get_icon()
            if data:
                self._custom_icon = Image.open(io.BytesIO(data)).convert("RGBA")
        except Exception:
            pass

    def _get_icon_image(self, offline: bool = False) -> Image.Image:
        """Gibt das passende Icon zurück — custom oder fallback."""
        if self._custom_icon:
            return _tint_icon_red(self._custom_icon) if offline else self._custom_icon.resize((64, 64), Image.LANCZOS)
        return _create_fallback_icon(offline)

    def _start_health_monitor(self):
        """Hintergrund-Thread der periodisch /api/v1/health pollt."""
        def loop():
            while not self._stop_health.is_set():
                try:
                    data = self._api.health_check_full()
                    ok = data.get("status") == "ok"
                    for action in data.get("pending_actions", []):
                        if action.get("type") == "reboot":
                            rid = action.get("run_id")
                            if rid and rid not in self._shown_reboot_runs:
                                self._shown_reboot_runs.add(rid)
                                self._reboot_signal.emit(action)
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
        """Qt-Slot: meldet State-Übergänge an Tray-Icon + PackageWindow."""
        if self._is_online is None:
            self._is_online = online
            self._update_tray_visuals()
            if self._window:
                self._window.set_online_state(online)
            return

        if self._is_online == online:
            return

        self._is_online = online
        self._update_tray_visuals()
        # In-Window-Banner statt OS-Toast
        if self._window:
            self._window.set_online_state(online)

    def _update_tray_visuals(self):
        if not self._icon:
            return
        status = "Verbunden" if self._is_online else "OFFLINE"
        try:
            self._icon.title = f"{self._app_name}  v{__version__}  ·  {status}"
            self._icon.icon = self._get_icon_image(offline=not self._is_online)
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
        if self._is_online is not None:
            self._window.set_online_state(self._is_online)
        self._window.show()
        self._window.raise_()
        self._window.activateWindow()

    def _on_window_closed(self):
        self._window = None

    def _on_reboot_request(self, action: dict):
        """Qt-Slot: zeigt den Reboot-Dialog und handhabt das Ergebnis."""
        from ui.reboot_dialog import RebootDialog
        # Icon-Daten fuer den Dialog (falls Custom-Icon vom Server geladen)
        icon_bytes = None
        if self._custom_icon:
            try:
                import io
                buf = io.BytesIO()
                self._custom_icon.save(buf, format="PNG")
                icon_bytes = buf.getvalue()
            except Exception:
                pass
        dlg = RebootDialog(
            message=action.get("message", "Neustart erforderlich."),
            countdown=action.get("countdown", 300),
            can_defer=action.get("can_defer", True),
            app_name=self._app_name,
            icon_data=icon_bytes,
            parent=None,
        )
        dlg.exec_()
        run_id = action.get("run_id")
        if not run_id:
            return
        if dlg.result in ("now", "auto"):
            self._api.workflow_reboot_now(run_id)
            # Server triggert shutdown via Tactical — kein lokaler shutdown noetig
        elif dlg.result == "defer":
            self._api.workflow_defer(run_id)
            # run_id aus der gesehenen Menge entfernen, damit er beim
            # naechsten Health-Poll wieder angezeigt werden kann
            self._shown_reboot_runs.discard(run_id)

    def _on_quit(self):
        parent = self._window
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
