"""
Wrapper für die Tactical RMM API.
Kapselt alle Calls – kein anderer Code spricht direkt mit Tactical.

URL + API-Key werden bei jedem Request aus der DB (settings-Tabelle) gelesen,
damit Änderungen im Admin-UI sofort wirksam werden ohne Restart.

Verwendete Endpoints:
  GET  /software/<agent_id>/           → Installierte Software
  GET  /software/chocos/               → Chocolatey-Liste
  POST /software/<agent_id>/           → Choco-Install
  POST /software/<agent_id>/uninstall/ → Choco-Uninstall
  POST /agents/<agent_id>/cmd/         → Raw Command (für custom MSI/EXE)
"""
import asyncio
import re
import httpx

from config import runtime_value

_RETRYABLE_STATUS = {502, 503, 504}

# Defense-in-depth: Namens-Validierung vor jeder URL-/Shell-Interpolation
_PKG_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,99}$")
_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9\-]{8,64}$")


def _check_pkg(name: str) -> None:
    if not _PKG_NAME_RE.fullmatch(name):
        raise ValueError(f"Unsicherer Paketname: {name!r}")


def _check_agent(agent_id: str) -> None:
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise ValueError(f"Ungültige Agent-ID: {agent_id!r}")


class TacticalClient:
    async def _connection(self) -> tuple[str, dict]:
        """Liest URL + API-Key aus der DB bei jedem Call."""
        base = (await runtime_value("tactical_url")).rstrip("/")
        api_key = await runtime_value("tactical_api_key")
        if not base or not api_key:
            raise RuntimeError(
                "Tactical RMM ist nicht konfiguriert. "
                "Bitte im Admin-UI unter Einstellungen ausfüllen."
            )
        headers = {"X-API-KEY": api_key, "Content-Type": "application/json"}
        return base, headers

    def _client(self, headers: dict) -> httpx.AsyncClient:
        return httpx.AsyncClient(headers=headers, timeout=30)

    async def get_installed_software(self, agent_id: str) -> list[dict]:
        _check_agent(agent_id)
        base, headers = await self._connection()
        url = f"{base}/software/{agent_id}/"
        delays = [0, 1.0, 2.5]
        last_exc: Exception | None = None
        async with self._client(headers) as c:
            for delay in delays:
                if delay:
                    await asyncio.sleep(delay)
                try:
                    r = await c.get(url)
                    if r.status_code in _RETRYABLE_STATUS:
                        last_exc = httpx.HTTPStatusError(
                            f"Tactical RMM returned HTTP {r.status_code}",
                            request=r.request, response=r,
                        )
                        continue
                    r.raise_for_status()
                    data = r.json()
                    if isinstance(data, dict):
                        return data.get("software", [])
                    return data
                except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as e:
                    last_exc = e
                    continue
        assert last_exc is not None
        raise last_exc

    async def install_software(self, agent_id: str, package_name: str) -> str:
        _check_agent(agent_id)
        _check_pkg(package_name)
        base, headers = await self._connection()
        async with self._client(headers) as c:
            r = await c.post(
                f"{base}/software/{agent_id}/",
                json={"name": package_name},
            )
            r.raise_for_status()
            return r.text

    async def get_chocos(self) -> list[dict]:
        base, headers = await self._connection()
        async with self._client(headers) as c:
            r = await c.get(f"{base}/software/chocos/")
            r.raise_for_status()
            return r.json()

    async def uninstall_software(self, agent_id: str, package_name: str) -> str:
        _check_agent(agent_id)
        _check_pkg(package_name)  # vor f-string-Interpolation in cmd
        cmd = f"choco uninstall {package_name} -y --no-progress"
        base, headers = await self._connection()
        async with self._client(headers) as c:
            r = await c.post(
                f"{base}/software/{agent_id}/uninstall/",
                json={
                    "name": package_name,
                    "command": cmd,
                    "timeout": 120,
                    "run_as_user": False,
                },
            )
            r.raise_for_status()
            return r.text

    async def run_command(
        self,
        agent_id: str,
        cmd: str,
        shell: str = "powershell",
        timeout: int = 600,
    ) -> str:
        _check_agent(agent_id)
        base, headers = await self._connection()
        async with httpx.AsyncClient(headers=headers, timeout=timeout + 15) as c:
            r = await c.post(
                f"{base}/agents/{agent_id}/cmd/",
                json={
                    "shell": shell,
                    "cmd": cmd,
                    "timeout": timeout,
                    "custom_shell": "",
                    "run_as_user": False,
                },
            )
            r.raise_for_status()
            return r.text
