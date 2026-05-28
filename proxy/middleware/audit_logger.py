"""
Audit Logging Middleware – schreibt fire-and-forget in SQLite (+ stdout).

Der DB-Write läuft als Background-Task, damit langsame DB-Writes
die Request-Latenz nicht beeinflussen und kein DoS-Vektor entsteht.

Filter: Hochfrequente Read-Polls (Health-Heartbeat, Workflow-Active-Run,
Script-Download, etc.) werden NICHT geschrieben — das Volumen wäre
sinnlos und vernebelt die echten Audit-Events. State-Changes
(POST/PATCH/DELETE) werden IMMER geloggt.
"""
import asyncio
import logging
import time
from fastapi import Request

logger = logging.getLogger("softshelf")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Strong-References für fire-and-forget Background-Tasks (siehe asyncio docs)
_bg_tasks: set[asyncio.Task] = set()

# GET-Pfade die NICHT im Audit-Log landen sollen (high-frequency, kein
# Sicherheits-Mehrwert). Exakt-Match oder Prefix.
_AUDIT_SKIP_EXACT: frozenset[str] = frozenset({
    "/api/v1/health",
    "/api/v1/workflows/active-run",
    "/api/v1/icon",
    "/api/v1/client-version-check",
    "/favicon.ico",
})
_AUDIT_SKIP_PREFIX: tuple[str, ...] = (
    "/api/v1/script/",     # Agent laed Bootstrap-Script (job_id-gebunden)
    "/static/",            # statische Assets
)


def _should_audit(method: str, path: str, status: int) -> bool:
    # State-Changes immer auditen.
    if method in ("POST", "PATCH", "PUT", "DELETE"):
        return True
    if path in _AUDIT_SKIP_EXACT:
        return False
    for p in _AUDIT_SKIP_PREFIX:
        if path.startswith(p):
            return False
    return True


async def _log_safe(method: str, path: str, ip: str, status: int, duration_ms: int):
    try:
        import database
        await database.log_request(method, path, ip, status, duration_ms)
    except Exception as e:
        logger.warning("Audit-Log-Schreiben fehlgeschlagen: %s", e)


async def audit_log_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000)

    method = request.method
    path = request.url.path
    client_ip = request.client.host if request.client else "unknown"
    status = response.status_code

    if _should_audit(method, path, status):
        t = asyncio.create_task(_log_safe(method, path, client_ip, status, duration))
        _bg_tasks.add(t)
        t.add_done_callback(_bg_tasks.discard)
    # stdout-Log bleibt fuer Debugging immer
    logger.info("%s %s %s %dms", method, path, status, duration)
    return response
