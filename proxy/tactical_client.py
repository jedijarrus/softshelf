"""
Wrapper für die Tactical RMM API.
Kapselt alle Calls – kein anderer Code spricht direkt mit Tactical.

URL + API-Key werden bei jedem Request aus der DB (settings-Tabelle) gelesen,
damit Änderungen im Admin-UI sofort wirksam werden ohne Restart.

Globaler Concurrency-Limiter: maximal MAX_CONCURRENT_COMMANDS gleichzeitige
run_command-Calls. Verhindert dass Bulk-Aktionen (Profile-Apply, Compliance-Fix)
den Tactical-Server mit parallelen Requests fluten und dessen uwsgi-Worker-Pool
erschoepfen.

Verwendete Endpoints:
  GET  /software/<agent_id>/           → Installierte Software
  GET  /software/chocos/               → Chocolatey-Liste
  POST /software/<agent_id>/           → Choco-Install
  POST /software/<agent_id>/uninstall/ → Choco-Uninstall
  POST /agents/<agent_id>/cmd/         → Raw Command (für custom MSI/EXE)
"""
import asyncio
import contextlib
import logging
import re
import threading
import time as _time
import httpx

from config import runtime_value

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS = {500, 502, 503, 504}

# Globaler Semaphore: max N gleichzeitige run_command Calls an Tactical.
# Schuetzt den Tactical-Server vor Worker-Pool-Erschoepfung.
MAX_CONCURRENT_COMMANDS = 8
_cmd_semaphore: asyncio.Semaphore | None = None

# In-Process Cache fuer die Agent-Liste (TTL 60s). Lookups by hostname/IP
# treffen denselben Cache statt jeweils /agents/ separat zu hitten.
_AGENTS_LIST_TTL_S = 60
_agents_list_cache: dict[str, tuple[float, list]] = {}  # key="all" → (ts, agents)


def _agents_cache_get() -> list | None:
    entry = _agents_list_cache.get("all")
    if not entry:
        return None
    ts, value = entry
    if _time.time() - ts > _AGENTS_LIST_TTL_S:
        return None
    return value


def _agents_cache_put(agents: list) -> None:
    _agents_list_cache["all"] = (_time.time(), agents)

# Queue-Tracking: was laeuft, was wartet
_active_commands: list[dict] = []   # [{agent_id, hostname, action, started_at}]
_waiting_count: int = 0
_queue_lock = threading.Lock()


def _get_semaphore() -> asyncio.Semaphore:
    """Lazy init — Semaphore muss im Event-Loop erzeugt werden."""
    global _cmd_semaphore
    if _cmd_semaphore is None:
        _cmd_semaphore = asyncio.Semaphore(MAX_CONCURRENT_COMMANDS)
    return _cmd_semaphore


@contextlib.asynccontextmanager
async def _tracked_semaphore(agent_id: str = "", hostname: str = "", action: str = ""):
    """Semaphore mit Tracking — zaehlt wartende + aktive Commands."""
    global _waiting_count
    with _queue_lock:
        _waiting_count += 1
    try:
        async with _get_semaphore():
            entry = {
                "agent_id": agent_id, "hostname": hostname,
                "action": action, "started_at": _time.time(),
            }
            with _queue_lock:
                _waiting_count -= 1
                _active_commands.append(entry)
            try:
                yield
            finally:
                with _queue_lock:
                    if entry in _active_commands:
                        _active_commands.remove(entry)
    except BaseException:
        with _queue_lock:
            _waiting_count = max(0, _waiting_count - 1)
        raise


def get_queue_status() -> dict:
    """Gibt den aktuellen Queue-Status zurueck (fuer Admin-API)."""
    with _queue_lock:
        active = [
            {**cmd, "running_seconds": int(_time.time() - cmd["started_at"])}
            for cmd in _active_commands
        ]
        return {
            "max_concurrent": MAX_CONCURRENT_COMMANDS,
            "active_count": len(active),
            "waiting_count": _waiting_count,
            "active": active,
        }

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

    async def _list_agents_cached(self) -> list | None:
        """Liefert /agents/ — gecachet 60s. None bei API-Fehler."""
        cached = _agents_cache_get()
        if cached is not None:
            return cached
        try:
            base, headers = await self._connection()
            async with self._client(headers) as c:
                r = await c.get(f"{base}/agents/")
                if r.status_code != 200:
                    return None
                agents = r.json()
                _agents_cache_put(agents)
                return agents
        except Exception as e:
            logger.warning("_list_agents_cached failed: %s", e)
            return None

    @staticmethod
    def _agent_to_brief(a: dict) -> dict:
        return {
            "agent_id": a.get("agent_id"),
            "hostname": a.get("hostname"),
            "status":   a.get("status", "unknown"),
        }

    async def find_agent_by_hostname(self, hostname: str) -> dict | None:
        """Sucht Tactical-Agent ueber Hostname (case-insensitive)."""
        if not hostname or not isinstance(hostname, str):
            return None
        hn_lower = hostname.strip().lower()
        if not hn_lower:
            return None
        agents = await self._list_agents_cached()
        if agents is None:
            return None
        for a in agents:
            if (a.get("hostname") or "").lower() == hn_lower:
                return self._agent_to_brief(a)
        return None

    async def find_agent_by_ip(self, ip: str) -> dict | None:
        """Sucht Tactical-Agent ueber lokale IP. Tactical liefert local_ips als
        Whitespace-/Komma-separierte Liste je Agent. Erfolgreich = exakte
        IP-String-Uebereinstimmung. Mehrfach-Treffer (z.B. zwei Agents mit
        derselben IP nach Re-Image): erstes online > erstes offline.
        """
        if not ip or not isinstance(ip, str):
            return None
        ip_clean = ip.strip()
        if not ip_clean:
            return None
        agents = await self._list_agents_cached()
        if agents is None:
            return None
        candidates = []
        for a in agents:
            raw = a.get("local_ips") or ""
            if not raw:
                continue
            ips = [p.strip() for p in raw.replace(",", " ").split()]
            if ip_clean in ips:
                candidates.append(a)
        if not candidates:
            return None
        # Online bevorzugt
        candidates.sort(key=lambda a: (0 if a.get("status") == "online" else 1))
        return self._agent_to_brief(candidates[0])

    async def check_agent_status(self, agent_id: str) -> dict:
        """Pre-Flight-Check: Agent existiert + online?
        Returns dict mit 'exists', 'status', 'hostname'.
        Wirft keine Exception — gibt immer ein Ergebnis."""
        _check_agent(agent_id)
        try:
            base, headers = await self._connection()
            async with self._client(headers) as c:
                r = await c.get(f"{base}/agents/{agent_id}/")
                if r.status_code == 404:
                    return {"exists": False, "status": "not_found", "hostname": ""}
                if r.status_code != 200:
                    return {"exists": False, "status": f"http_{r.status_code}", "hostname": ""}
                data = r.json()
                return {
                    "exists": True,
                    "status": data.get("status", "unknown"),
                    "hostname": data.get("hostname", ""),
                }
        except Exception as e:
            logger.warning("check_agent_status failed for %s: %s", agent_id[:12], e)
            return {"exists": True, "status": "check_failed", "hostname": ""}

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

    async def list_scripts(self) -> list[dict]:
        """Liefert alle Scripts aus Tactical: [{id, name, ...}, ...]."""
        base, headers = await self._connection()
        async with self._client(headers) as c:
            r = await c.get(f"{base}/scripts/")
            r.raise_for_status()
            return r.json()

    async def find_script_id_by_name(self, name: str) -> int | None:
        """Sucht Script-ID per case-insensitive Namen-Match. None wenn nicht gefunden.

        Wird vom oeffentlichen Landing-Endpoint aufgerufen — bei transienten
        Tactical-API-Fehlern wuerde warning() das Log fluten. Stattdessen debug()
        und der Caller behandelt None weiter oben als 'script_not_found'.
        """
        if not name:
            return None
        target = name.strip().lower()
        try:
            scripts = await self.list_scripts()
        except Exception as e:
            logger.debug("list_scripts failed: %s", e)
            return None
        for s in scripts:
            if (s.get("name") or "").strip().lower() == target:
                return s.get("id")
        return None

    async def run_script_by_name(self, agent_id: str, script_name: str, timeout: int = 600) -> dict:
        """Triggert einen Tactical-Script nach Name auf einem Agent.
        Fire-and-forget (output=forget) — kein Warten auf Ausgabe.
        Liefert {ok, status, body}. Wirft keine Exception.

        Verwendet self._client(headers) wie die anderen Methoden — also
        verify=True (TLS-Validation) und konsistentes Default-Timeout-Setup.
        Timeout 60s damit Tactical bei Last noch acken kann.

        Asymmetrie: Tactical dispatched intern via NATS — bei einem
        ReadTimeout/ConnectTimeout ist der Befehl moeglicherweise SCHON
        rausgegangen. Statt einen Timeout als Fehler zu melden (was den
        User sehen lassen wuerde 'gescheitert' obwohl Install gerade
        laeuft) behandeln wir es als best-effort dispatched — der Frontend
        kann eine sanftere Meldung zeigen und der Status-Polling-Loop
        erkennt anschliessend ob der Client wirklich hochkam.
        """
        _check_agent(agent_id)
        sid = await self.find_script_id_by_name(script_name)
        if sid is None:
            return {"ok": False, "status": "script_not_found", "body": script_name}
        base, headers = await self._connection()
        url = f"{base}/agents/{agent_id}/runscript/"
        payload = {
            "script": sid,
            "output": "forget",  # fire-and-forget, blockiert nicht (Tactical wartet sonst auf Agent-Output)
            "args": [],
            "env_vars": [],
            "timeout": timeout,
            "custom_shell": "",
            "run_as_user": False,
        }
        try:
            # Eigener Client mit 60s-Timeout statt self._client (Default 30s):
            # Tactical kann unter Last laenger zum acken brauchen.
            async with httpx.AsyncClient(headers=headers, timeout=60) as c:
                r = await c.post(url, json=payload)
                if r.status_code >= 400:
                    return {"ok": False, "status": f"http_{r.status_code}", "body": r.text[:300]}
                return {"ok": True, "status": "dispatched", "body": r.text[:300], "script_id": sid}
        except (httpx.ReadTimeout, httpx.ConnectTimeout) as e:
            # Asymmetrie wie oben dokumentiert: Befehl koennte trotzdem
            # rausgegangen sein. Best-effort dispatched zurueckmelden.
            logger.info("run_script timeout (dispatched best-effort): %s", e)
            return {
                "ok": True,
                "status": "dispatched_timeout",
                "body": "Tactical did not reply within 60s; install may still proceed",
                "script_id": sid,
            }
        except Exception as e:
            logger.warning("run_script failed: %s", e)
            return {"ok": False, "status": "error", "body": str(e)[:300]}

    async def run_command(
        self,
        agent_id: str,
        cmd: str,
        shell: str = "powershell",
        timeout: int = 300,
        run_as_user: bool = False,
    ) -> str:
        """Fuehrt cmd via Tactical run_command aus.

        Concurrency-limitiert durch globalen Semaphore (MAX_CONCURRENT_COMMANDS)
        damit Bulk-Aktionen den Tactical-Server nicht fluten.

        KEIN Retry: Tactical liefert den Befehl sofort via NATS an den Agent.
        Bei HTTP 502/504 ist der Befehl bereits raus — Retry wuerde ihn
        duplizieren. Stattdessen einmal versuchen und bei Fehler sauber
        abbrechen.

        run_as_user=True laesst Tactical den Befehl im Kontext des interaktiv
        eingeloggten Users ausfuehren statt als SYSTEM.
        """
        _check_agent(agent_id)
        base, headers = await self._connection()
        url = f"{base}/agents/{agent_id}/cmd/"
        payload = {
            "shell": shell,
            "cmd": cmd,
            "timeout": timeout,
            "custom_shell": "",
            "run_as_user": bool(run_as_user),
        }

        async with _tracked_semaphore(agent_id=agent_id, action=cmd[:80]):
            async with httpx.AsyncClient(headers=headers, timeout=timeout + 15) as c:
                try:
                    r = await c.post(url, json=payload)
                    if r.status_code in _RETRYABLE_STATUS:
                        raise httpx.HTTPStatusError(
                            f"Tactical returned HTTP {r.status_code}",
                            request=r.request, response=r,
                        )
                    r.raise_for_status()
                    return r.text
                except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as e:
                    raise
