"""
System Tray Icon - pystray runs in background thread.

No PyQt5 dependencies. Communication with pywebview windows via
module-level functions in package_window.py and reboot_dialog.py.

Health-Monitor: polls the proxy every HEALTH_INTERVAL seconds. On state
transitions (online <-> offline) the tray icon updates and the package
window is notified via JS evaluation.

Custom Icon: on start, tries to load branding icon from server
(/api/v1/icon). Falls back to generated icon if not available.
"""
import io
import os
import sys
import threading
from PIL import Image, ImageDraw
import pystray
import webview

from api_client import KioskApiClient
from _version import __version__

HEALTH_INTERVAL = 60  # seconds between health checks


def _create_fallback_icon(offline: bool = False) -> Image.Image:
    """Generated fallback icon when no custom icon from server."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    fill = (220, 38, 38) if offline else (9, 9, 11)  # red-600 / zinc-950
    draw.rounded_rectangle([6, 6, 58, 58], radius=10, fill=fill)
    draw.rectangle([20, 20, 44, 44], outline=(255, 255, 255), width=3)
    return img


def _tint_icon_red(img: Image.Image) -> Image.Image:
    """Overlay: custom icon with red warning dot bottom-right."""
    out = img.copy().convert("RGBA").resize((64, 64), Image.LANCZOS)
    draw = ImageDraw.Draw(out)
    draw.ellipse([42, 42, 62, 62], fill=(255, 255, 255))
    draw.ellipse([44, 44, 60, 60], fill=(220, 38, 38))
    return out


class KioskTray:
    """System tray icon with health monitor. No Qt dependencies."""

    def __init__(self, api: KioskApiClient, app_name: str = "Softshelf"):
        self._api = api
        self._app_name = app_name
        self._icon: pystray.Icon | None = None
        self._custom_icon: Image.Image | None = None
        self._is_online: bool | None = None
        self._stop_health = threading.Event()
        self._health_thread: threading.Thread | None = None
        self._shown_reboot_runs: set = set()

    def start(self):
        """Start pystray in background thread (does NOT block)."""
        self._load_custom_icon()
        menu = pystray.Menu(
            pystray.MenuItem(self._app_name, self._on_open, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Beenden", self._on_quit),
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
        """Try to load branding icon from server (best-effort)."""
        try:
            data = self._api.get_icon()
            if data:
                self._custom_icon = Image.open(io.BytesIO(data)).convert("RGBA")
        except Exception:
            pass

    def _get_icon_image(self, offline: bool = False) -> Image.Image:
        """Return the appropriate icon image."""
        if self._custom_icon:
            if offline:
                return _tint_icon_red(self._custom_icon)
            return self._custom_icon.resize((64, 64), Image.LANCZOS)
        return _create_fallback_icon(offline)

    def _start_health_monitor(self):
        """Background thread polling /api/v1/health."""
        def loop():
            while not self._stop_health.is_set():
                try:
                    data = self._api.health_check_full()
                    ok = data.get("status") == "ok"
                    # Check for pending reboot actions
                    for action in data.get("pending_actions", []):
                        if action.get("type") == "reboot":
                            rid = action.get("run_id")
                            if rid and rid not in self._shown_reboot_runs:
                                self._shown_reboot_runs.add(rid)
                                self._handle_reboot_request(action)
                except Exception:
                    ok = False
                self._on_health_changed(ok)
                if self._stop_health.wait(HEALTH_INTERVAL):
                    return
        self._health_thread = threading.Thread(
            target=loop, daemon=True, name="KioskHealth",
        )
        self._health_thread.start()

    def _on_health_changed(self, online: bool):
        """Called from health thread on every poll."""
        if self._is_online is None:
            self._is_online = online
            self._update_tray_visuals()
            self._notify_window(online)
            return

        if self._is_online == online:
            return

        self._is_online = online
        self._update_tray_visuals()
        self._notify_window(online)

    def _update_tray_visuals(self):
        if not self._icon:
            return
        status = "Verbunden" if self._is_online else "OFFLINE"
        try:
            self._icon.title = f"{self._app_name}  v{__version__}  \u00B7  {status}"
            self._icon.icon = self._get_icon_image(offline=not self._is_online)
        except Exception:
            pass

    def _notify_window(self, online: bool):
        """Notify the package window about online state change."""
        from ui.package_window import set_online_state
        set_online_state(online)

    def _handle_reboot_request(self, action: dict):
        """Show the reboot dialog for a pending reboot action."""
        from ui.reboot_dialog import show_reboot_dialog

        run_id = action.get("run_id")

        def on_done(result):
            if result == "defer":
                # Remove from seen set so it reappears on next poll
                self._shown_reboot_runs.discard(run_id)

        show_reboot_dialog(
            api_client=self._api,
            run_id=run_id,
            message=action.get("message", "Neustart erforderlich."),
            countdown=action.get("countdown", 300),
            can_defer=action.get("can_defer", True),
            app_name=self._app_name,
            on_done=on_done,
        )

    # ─── pystray Callbacks (run in pystray thread) ───

    def _on_open(self, icon, item):
        """Tray click: open/show the main package window."""
        from ui.package_window import show_main_window
        show_main_window(self._api, app_name=self._app_name)

    def _on_quit(self, icon, item):
        """Tray quit: clean up everything and exit."""
        self._stop_health.set()
        if self._health_thread:
            self._health_thread.join(timeout=6)

        # Destroy all webview windows
        from ui.package_window import destroy_main_window
        from ui.reboot_dialog import destroy_reboot_window
        destroy_main_window()
        destroy_reboot_window()

        if self._icon:
            self._icon.stop()

        # Shut down the webview event loop which unblocks main thread
        for w in webview.windows[:]:
            try:
                w.destroy()
            except Exception:
                pass

        os._exit(0)
