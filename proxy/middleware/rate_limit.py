"""
In-Memory Rate-Limiter für /api/v1/register und /admin – pro Client-IP.

Bewusst ohne externe Dependency (Redis/slowapi). Reicht für eine kleine
interne Deployment, wo der Proxy nur einen Worker-Prozess hat.

Limits:
  /api/v1/register      5 Requests / 60 s   (Brute-Force des Registration-Secrets)
  /admin/login         10 Requests / 60 s   (Login-Brute-Force)
  /admin/api/*        600 Requests / 60 s   (SPA macht viele parallele API-Calls)
  /admin/* (Rest)     120 Requests / 60 s   (Admin-Portal HTML + Assets)

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
    "register":   (5,   60),
    "admin_login": (10,  60),
    "admin_api":  (600, 60),
    "admin":      (120, 60),
    # Landing-Endpoints: oeffentlich, kein Auth — strikte Per-IP Limits.
    # Status: 20/min damit polling waehrend Install nicht sofort knockt.
    # Trigger: 3/min — verhindert Trigger-Sturm (zusaetzlich zum 5-Min-Cooldown
    # pro Hostname im main.py).
    "landing_status":  (20, 60),
    "landing_trigger": (3,  60),
}

# Loopback-IPs deren X-Forwarded-For wir akzeptieren (Reverse-Proxy lokal).
# Public-API (TRUSTED_PROXIES, is_trusted_peer) statt _-Prefix damit andere
# Module nicht in private Symbole greifen.
TRUSTED_PROXIES = {"127.0.0.1", "::1", "localhost"}
# Backward-compat Alias — entfernen sobald keine Konsumenten mehr da sind.
_TRUSTED_PROXIES = TRUSTED_PROXIES


def is_trusted_peer(host: str) -> bool:
    """Prueft ob die TCP-Peer-IP ein vertrauenswuerdiger Reverse-Proxy ist
    (also: ihr X-Forwarded-For-Header darf gelesen werden)."""
    return host in TRUSTED_PROXIES

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
    # Login ist der eigentliche Brute-Force-Pfad → eigener, harter Bucket
    if path == "/admin/login" or path == "/admin/logout":
        return "admin_login"
    # API-Calls vom SPA: viele parallele Requests pro Tab-Wechsel → viel hoeher
    if path.startswith("/admin/api/"):
        return "admin_api"
    # Rest (/admin, static assets) → moderater Bucket
    if path == "/admin" or path.startswith("/admin/"):
        return "admin"
    # Oeffentliche Landing-Endpoints (kein Auth) → strikte Per-IP Limits.
    if path == "/api/v1/landing-status":
        return "landing_status"
    if path == "/api/v1/landing-trigger-install":
        return "landing_trigger"
    return None


def _real_peer_ip(request: Request) -> str:
    """Echter TCP-Peer (NICHT XFF). Verwendet fuer landing-Buckets damit ein
    Angreifer nicht via gespoofter XFF Header die Limits umgehen kann."""
    return request.client.host if request.client else "unknown"


async def rate_limit_middleware(request: Request, call_next):
    global _request_counter
    bucket = _bucket_for(request.url.path)
    if bucket:
        # Fuer Landing-Buckets: echte Peer-IP (kein XFF-Trust), damit ein
        # Angreifer nicht durch gespoofte Headers die Limits umgehen kann.
        # Fuer Admin/Register: weiter XFF-Trust von loopback erlauben.
        if bucket in ("landing_status", "landing_trigger"):
            ip = _real_peer_ip(request)
        else:
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
