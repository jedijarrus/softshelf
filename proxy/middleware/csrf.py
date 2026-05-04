"""
CSRF-Schutz für /admin/api/* und das Landing-Install-Endpoint.

Da die Admin-UI über HTTP Basic Auth läuft, sendet der Browser die
Credentials bei jedem Request automatisch. Eine bösartige Drittwebsite
könnte dadurch (theoretisch) POST/PATCH/DELETE-Calls auslösen.

Das Landing-Install-Endpoint (/api/v1/landing-trigger-install) ist
unauthenticated, aber per reverse-DNS auf die Client-IP gebunden — eine
bösartige Drittwebsite könnte aus dem Browser des Opfers heraus einen
Trigger auslösen. Deshalb gleiche CSRF-Regel wie für /admin/api/*.

Schutzmechanismus: bei state-changing Methoden auf den geschützten Pfaden
muss entweder
  • der Origin-/Referer-Header zum eigenen Host passen, ODER
  • der Header X-Requested-With: XMLHttpRequest gesetzt sein
    (Browser senden den nicht automatisch cross-origin).
"""
from urllib.parse import urlparse
from fastapi import Request
from fastapi.responses import JSONResponse

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

# Pfade die CSRF-Schutz brauchen (ueber /admin/api/* hinaus)
_CSRF_PROTECTED_EXTRA = {"/api/v1/landing-trigger-install"}


def _needs_csrf(path: str) -> bool:
    if path.startswith("/admin/api/"):
        return True
    if path in _CSRF_PROTECTED_EXTRA:
        return True
    return False


async def csrf_middleware(request: Request, call_next):
    if request.method in _STATE_CHANGING and _needs_csrf(request.url.path):
        host = request.headers.get("host", "")
        origin = request.headers.get("origin") or request.headers.get("referer", "")
        xrw = request.headers.get("x-requested-with", "")

        origin_ok = False
        if origin:
            try:
                origin_host = urlparse(origin).netloc
                if origin_host and host and origin_host == host:
                    origin_ok = True
            except Exception:
                pass

        xrw_ok = xrw == "XMLHttpRequest"

        if not (origin_ok or xrw_ok):
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF: Origin oder X-Requested-With fehlt"},
            )

    return await call_next(request)
