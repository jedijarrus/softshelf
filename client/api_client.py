"""
HTTP Client für die Kommunikation mit dem Proxy-Server.
Kein direkter Tactical RMM Zugriff.
"""
import time
import httpx
from dataclasses import dataclass

from config import ClientConfig

# Tray-Start-Time fuer Uptime-Telemetrie. Wird beim ersten Modul-Import
# gesetzt — also beim Tray-App-Boot.
_TRAY_START_TS = time.time()


def _build_version() -> str:
    """Liefert die einkompilierte BUILD_VERSION oder fallback."""
    try:
        from _build_config import BUILD_VERSION  # type: ignore
        return str(BUILD_VERSION)
    except Exception:
        return "0.0.0-dev"


def _os_version() -> str:
    """Windows-Version als kurzer String fuer Telemetrie. Best-effort."""
    try:
        import platform
        # Beispiel: "Windows-10-10.0.22631-SP0" → "Win11 22631"
        rel = platform.release() or ""
        ver = platform.version() or ""
        # Verkurzte Form
        if rel and ver:
            return f"Win{rel} {ver.split('.')[-1]}"[:80]
        return platform.platform()[:80]
    except Exception:
        return ""

# Retry-Verhalten fuer transiente Netzwerkfehler bei idempotenten GETs.
# Wir retryen GENAU EIN MAL nach 2s. Nur bei Connection-Fehlern oder
# 502/503/504. Niemals fuer POST (nicht idempotent) und nicht fuer 4xx.
_RETRY_DELAY_S = 2.0
_RETRY_HTTP_STATUS = {502, 503, 504}
_RETRY_EXCEPTIONS = (
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.ConnectTimeout,
)


def _get_with_retry(client: httpx.Client, url: str, **kwargs) -> httpx.Response:
    """GET mit einem Retry bei transientem Fehler. Nur fuer idempotente Calls."""
    try:
        r = client.get(url, **kwargs)
        if r.status_code in _RETRY_HTTP_STATUS:
            time.sleep(_RETRY_DELAY_S)
            r = client.get(url, **kwargs)
        return r
    except _RETRY_EXCEPTIONS:
        time.sleep(_RETRY_DELAY_S)
        return client.get(url, **kwargs)


@dataclass
class Package:
    name: str
    display_name: str
    version: str | None
    installed: bool
    category: str = "Allgemein"
    type: str = "choco"          # "choco" / "custom" / "winget" / "plugin"
    publisher: str | None = None
    installed_version_label: str | None = None
    current_version_label: str | None = None
    update_available: bool = False
    hide_uninstall: bool = False
    process_check: str = ""
    plugin_host: str | None = None
    plugin_host_label: str | None = None


class _PooledHttp:
    """Context-Manager-Wrapper um den shared httpx.Client: schliesst beim
    Exit NICHT (Pooling bleibt), injiziert die per-Call-Header. Drop-in
    fuer das bisherige `with self._client() as c:`."""

    def __init__(self, client: httpx.Client, headers: dict):
        self._c = client
        self._h = headers

    def __enter__(self) -> "_PooledHttp":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def get(self, url, **kw):
        kw.setdefault("headers", self._h)
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        kw.setdefault("headers", self._h)
        return self._c.post(url, **kw)


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
        # Telemetrie-Header: Tray-Version + OS einmal beim Init bestimmen
        # (aendern sich nicht zur Laufzeit). Tray-Uptime wird per-call gesetzt.
        self._build_version = _build_version()
        self._os_version = _os_version()
        self._headers = {
            "Authorization": f"Bearer {config.machine_token}",
            "Content-Type": "application/json",
            "X-Softshelf-User": _get_windows_user(),
            "X-Softshelf-Client-Version": self._build_version,
            "X-Softshelf-Os-Version": self._os_version,
        }
        # Shared HTTP-Client (httpx.Client ist thread-safe; Health-Thread und
        # webview-Worker teilen sich den Connection-Pool).
        self._http: httpx.Client | None = None

    def _client(self) -> "_PooledHttp":
        # Per-call Uptime-Header damit der Server lange Tray-Sessions sieht.
        # Shared httpx.Client mit Connection-Pooling: vorher baute jeder
        # API-Call TCP+TLS neu auf — spuerbare Latenz bei jedem Klick.
        headers = dict(self._headers)
        headers["X-Softshelf-Tray-Uptime"] = str(int(time.time() - _TRAY_START_TS))
        if self._http is None or self._http.is_closed:
            self._http = httpx.Client(timeout=15, verify=True)
        return _PooledHttp(self._http, headers)

    def get_packages(self) -> list[Package]:
        with self._client() as c:
            r = _get_with_retry(c, f"{self._base}/api/v1/packages")
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
                    hide_uninstall=p.get("hide_uninstall", False),
                    process_check=p.get("process_check", "") or "",
                    plugin_host=p.get("plugin_host"),
                    plugin_host_label=p.get("plugin_host_label"),
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
                r = _get_with_retry(c, f"{self._base}/api/v1/client-config", timeout=3)
                r.raise_for_status()
                return r.json()
        except Exception:
            return {}

    def health_check(self) -> bool:
        try:
            with self._client() as c:
                r = _get_with_retry(c, f"{self._base}/api/v1/health", timeout=5)
                return r.status_code == 200
        except Exception:
            return False

    def health_check_full(self) -> dict:
        """Health-Check mit vollem Response-Body (pending_actions etc.)."""
        try:
            with self._client() as c:
                r = _get_with_retry(c, f"{self._base}/api/v1/health", timeout=5)
                if r.status_code == 200:
                    return r.json()
        except Exception:
            pass
        return {"status": "error"}

    def client_version_check(self) -> dict | None:
        """Holt Tray-Self-Update-Info vom Server.

        Returns dict mit `latest`, `setup_url`, `setup_sha`, `min_required`
        oder None bei Fehler. Tray-App vergleicht selbst current vs latest.
        """
        try:
            with self._client() as c:
                r = _get_with_retry(
                    c, f"{self._base}/api/v1/client-version-check", timeout=5,
                )
                if r.status_code == 200:
                    return r.json()
        except Exception:
            pass
        return None

    def current_build_version(self) -> str:
        return self._build_version

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

    def list_workflows(self) -> list[dict]:
        """Kiosk-freigegebene Workflows fuer diesen Agent. Bei Fehler: leere Liste."""
        try:
            with self._client() as c:
                r = _get_with_retry(c, f"{self._base}/api/v1/workflows", timeout=8)
                if r.status_code == 200:
                    data = r.json()
                    return data if isinstance(data, list) else []
        except Exception:
            pass
        return []

    def start_workflow(self, workflow_id: int) -> tuple[bool, str, int | None]:
        """Startet einen Workflow. Returns (ok, message, run_id)."""
        try:
            with self._client() as c:
                r = c.post(
                    f"{self._base}/api/v1/workflows/{workflow_id}/start",
                    timeout=10,
                )
                if r.status_code == 200:
                    data = r.json()
                    return True, "Workflow gestartet.", data.get("run_id")
                # Server-Fehlertext durchreichen
                try:
                    msg = r.json().get("detail") or f"Fehler {r.status_code}"
                except Exception:
                    msg = f"Fehler {r.status_code}"
                return False, str(msg), None
        except Exception as e:
            return False, str(e), None

    def get_active_workflow_run(self) -> dict | None:
        """Aktiver Workflow-Run fuer diesen Agent (null wenn keiner)."""
        try:
            with self._client() as c:
                r = _get_with_retry(
                    c, f"{self._base}/api/v1/workflows/active-run", timeout=5,
                )
                if r.status_code == 200:
                    data = r.json()
                    return data if isinstance(data, dict) else None
        except Exception:
            pass
        return None

    def get_icon(self) -> bytes | None:
        """Branding-Icon vom Server laden (ICO). None wenn nicht vorhanden."""
        try:
            with self._client() as c:
                r = _get_with_retry(c, f"{self._base}/api/v1/icon", timeout=5)
                if r.status_code == 200:
                    return r.content
        except Exception:
            pass
        return None
