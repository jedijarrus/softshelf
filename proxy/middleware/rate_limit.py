"""
In-Memory Rate-Limiter für /api/v1/register und /admin – pro Client-IP.

Bewusst ohne externe Dependency (Redis/slowapi). Reicht für eine kleine
interne Deployment, wo der Proxy nur einen Worker-Prozess hat.

Limits:
  /api/v1/register     5 Requests / 60 s   (Brute-Force des Registration-Secrets)
  /admin und /admin/*  60 Requests / 60 s  (Login-Brute-Force + normale UI-Nutzung)

Hinter einem Reverse-Proxy auf demselben Host wird X-Forwarded-For respektiert,
damit nicht alle Clients den Bucket des Proxies teilen. Es werden NUR Forwarded-
Header von loopback-Adressen (127.0.0.1, ::1) akzeptiert; Header von externen
IPs werden ignoriert (sonst trivial spoofbar).
"""
import time
from collections import defaultdict, deque
from fastapi import Request
from fastapi.responses import JSONResponse

# {ip: {bucket: deque[timestamps]}}
_buckets: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))

LIMITS: dict[str, tuple[int, int]] = {
    "register": (5, 60),
    "admin":    (60, 60),
}

# Loopback-IPs deren X-Forwarded-For wir akzeptieren (Reverse-Proxy lokal)
_TRUSTED_PROXIES = {"127.0.0.1", "::1", "localhost"}

# Anzahl Requests bevor wir einen Cleanup-Sweep machen (cheap GC)
_SWEEP_INTERVAL = 500
_request_counter = 0


def _client_ip(request: Request) -> str:
    """Echte Client-IP ermitteln. Trust X-Forwarded-For nur von loopback."""
    peer = request.client.host if request.client else "unknown"
    if peer in _TRUSTED_PROXIES:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            # Erstes Element ist der ursprüngliche Client
            return xff.split(",")[0].strip() or peer
    return peer


def _check(ip: str, bucket: str) -> bool:
    max_req, window = LIMITS[bucket]
    now = time.time()
    dq = _buckets[ip][bucket]
    while dq and dq[0] < now - window:
        dq.popleft()
    if len(dq) >= max_req:
        return False
    dq.append(now)
    return True


def _sweep():
    """Räumt IPs raus deren alle Buckets leer sind. O(n) über alle IPs aber
    läuft nur jeden N-ten Request → amortized O(1)."""
    now = time.time()
    max_window = max(w for _, w in LIMITS.values())
    cutoff = now - max_window
    to_drop = []
    for ip, buckets in _buckets.items():
        # Erst alte Timestamps aus jedem Bucket entfernen
        any_alive = False
        for dq in buckets.values():
            while dq and dq[0] < cutoff:
                dq.popleft()
            if dq:
                any_alive = True
        if not any_alive:
            to_drop.append(ip)
    for ip in to_drop:
        del _buckets[ip]


def _bucket_for(path: str) -> str | None:
    if path == "/api/v1/register":
        return "register"
    if path == "/admin" or path.startswith("/admin/"):
        return "admin"
    return None


async def rate_limit_middleware(request: Request, call_next):
    global _request_counter
    bucket = _bucket_for(request.url.path)
    if bucket:
        ip = _client_ip(request)
        if not _check(ip, bucket):
            return JSONResponse(
                status_code=429,
                content={"detail": "Zu viele Anfragen – bitte einen Moment warten."},
            )
        _request_counter += 1
        if _request_counter >= _SWEEP_INTERVAL:
            _request_counter = 0
            _sweep()
    return await call_next(request)
