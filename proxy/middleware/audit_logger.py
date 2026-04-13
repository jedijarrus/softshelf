"""
Audit Logging Middleware – schreibt fire-and-forget in SQLite (+ stdout).

Der DB-Write läuft als Background-Task, damit langsame DB-Writes
die Request-Latenz nicht beeinflussen und kein DoS-Vektor entsteht.
"""
import asyncio
import logging
import time
from fastapi import Request

logger = logging.getLogger("softshelf")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Strong-References für fire-and-forget Background-Tasks (siehe asyncio docs)
_bg_tasks: set[asyncio.Task] = set()


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

    t = asyncio.create_task(_log_safe(method, path, client_ip, status, duration))
    _bg_tasks.add(t)
    t.add_done_callback(_bg_tasks.discard)
    logger.info("%s %s %s %dms", method, path, status, duration)
    return response
