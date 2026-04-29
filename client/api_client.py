"""
HTTP Client für die Kommunikation mit dem Proxy-Server.
Kein direkter Tactical RMM Zugriff.
"""
import httpx
from dataclasses import dataclass

from config import ClientConfig


@dataclass
class Package:
    name: str
    display_name: str
    version: str | None
    installed: bool
    category: str = "Allgemein"
    type: str = "choco"          # "choco" oder "custom"
    publisher: str | None = None
    installed_version_label: str | None = None
    current_version_label: str | None = None
    update_available: bool = False


def _get_windows_user() -> str:
    """Aktuell eingeloggter Windows-User (DOMAIN\\User oder User)."""
    import os
    try:
        return os.environ.get("USERNAME") or os.environ.get("USER") or os.getlogin()
    except Exception:
        return ""


class KioskApiClient:
    def __init__(self, config: ClientConfig):
        self._base = config.proxy_url
        self._headers = {
            "Authorization": f"Bearer {config.machine_token}",
            "Content-Type": "application/json",
            "X-Softshelf-User": _get_windows_user(),
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(headers=self._headers, timeout=15, verify=True)

    def get_packages(self) -> list[Package]:
        with self._client() as c:
            r = c.get(f"{self._base}/api/v1/packages")
            r.raise_for_status()
            return [
                Package(
                    name=p["name"],
                    display_name=p["display_name"],
                    version=p.get("version"),
                    installed=p.get("installed", False),
                    category=p.get("category", "Allgemein"),
                    type=p.get("type", "choco"),
                    publisher=p.get("publisher"),
                    installed_version_label=p.get("installed_version_label"),
                    current_version_label=p.get("current_version_label"),
                    update_available=p.get("update_available", False),
                )
                for p in r.json()
            ]

    def install_package(self, package_name: str) -> str:
        with self._client() as c:
            r = c.post(
                f"{self._base}/api/v1/install",
                json={"package_name": package_name},
            )
            r.raise_for_status()
            return r.json().get("message", "Installation gestartet.")

    def uninstall_package(self, package_name: str) -> str:
        with self._client() as c:
            r = c.post(
                f"{self._base}/api/v1/uninstall",
                json={"package_name": package_name},
            )
            r.raise_for_status()
            return r.json().get("message", "Deinstallation gestartet.")

    def get_client_config(self) -> dict:
        """
        Holt Client-Metadaten vom Proxy (app_name, version).
        Bei Fehler: leeres Dict → Client nimmt den eingebauten Default.
        Kurzer Timeout damit Startup nicht hängt wenn Proxy weg ist.
        """
        try:
            with self._client() as c:
                r = c.get(f"{self._base}/api/v1/client-config", timeout=3)
                r.raise_for_status()
                return r.json()
        except Exception:
            return {}

    def health_check(self) -> bool:
        try:
            with self._client() as c:
                r = c.get(f"{self._base}/api/v1/health", timeout=5)
                return r.status_code == 200
        except Exception:
            return False

    def health_check_full(self) -> dict:
        """Health-Check mit vollem Response-Body (pending_actions etc.)."""
        try:
            with self._client() as c:
                r = c.get(f"{self._base}/api/v1/health", timeout=5)
                if r.status_code == 200:
                    return r.json()
        except Exception:
            pass
        return {"status": "error"}

    def workflow_reboot_now(self, run_id: int) -> bool:
        """Returns True only if server accepted the reboot (ok=true)."""
        try:
            with self._client() as c:
                r = c.post(
                    f"{self._base}/api/v1/workflow/reboot-now/{run_id}",
                    timeout=5,
                )
                if r.status_code != 200:
                    return False
                data = r.json()
                return data.get("ok", False) is True
        except Exception:
            return False

    def workflow_defer(self, run_id: int) -> bool:
        """Returns True only if server accepted the defer (ok=true)."""
        try:
            with self._client() as c:
                r = c.post(
                    f"{self._base}/api/v1/workflow/defer/{run_id}",
                    timeout=5,
                )
                if r.status_code != 200:
                    return False
                data = r.json()
                return data.get("ok", False) is True
        except Exception:
            return False

    def get_icon(self) -> bytes | None:
        """Branding-Icon vom Server laden (ICO). None wenn nicht vorhanden."""
        try:
            with self._client() as c:
                r = c.get(f"{self._base}/api/v1/icon", timeout=5)
                if r.status_code == 200:
                    return r.content
        except Exception:
            pass
        return None
