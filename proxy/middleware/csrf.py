"""
CSRF-Schutz für /admin/api/* state-changing Requests.

Da die Admin-UI über HTTP Basic Auth läuft, sendet der Browser die
Credentials bei jedem Request automatisch. Eine bösartige Drittwebsite
könnte dadurch (theoretisch) POST/PATCH/DELETE-Calls auslösen.

Schutzmechanismus: bei state-changing Methoden auf /admin/api/* muss
entweder
  • der Origin-/Referer-Header zum eigenen Host passen, ODER
  • der Header X-Requested-With: XMLHttpRequest gesetzt sein
    (Browser senden den nicht automatisch cross-origin).
"""
from urllib.parse import urlparse
from fastapi import Request
from fastapi.responses import JSONResponse

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


async def csrf_middleware(request: Request, call_next):
    if request.method in _STATE_CHANGING and request.url.path.startswith("/admin/api/"):
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
