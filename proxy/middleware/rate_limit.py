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

# Loopback-IPs immer vertrauenswuerdig.
_DEFAULT_TRUSTED_PROXIES = {"127.0.0.1", "::1", "localhost"}
# Cache fuer trusted-proxies Setting (DB-Wert union mit defaults). 30s TTL.
_TRUSTED_PROXIES_CACHE: tuple[float, set[str]] = (0.0, set(_DEFAULT_TRUSTED_PROXIES))


async def _load_trusted_proxies() -> set[str]:
    """Liest runtime-setting `trusted_proxies` (Komma-separierte IPs/Hostnames)
    und vereint mit den hardcoded Loopback-Defaults. Cached 30s damit jeder
    Request nicht die DB hittet."""
    global _TRUSTED_PROXIES_CACHE
    now = time.time()
    cached_at, cached_set = _TRUSTED_PROXIES_CACHE
    if now - cached_at < 30:
        return cached_set
    try:
        from config import runtime_value
        raw = (await runtime_value("trusted_proxies")) or ""
        extra = {p.strip() for p in raw.replace(";", ",").split(",") if p.strip()}
    except Exception:
        extra = set()
    result = set(_DEFAULT_TRUSTED_PROXIES) | extra
    _TRUSTED_PROXIES_CACHE = (now, result)
    return result


# Snapshot fuer sync-Callsites (z.B. is_trusted_peer ohne await).
# Wird vom rate-limit-Middleware bei jedem ersten Request des 30s-Fensters
# refreshed. Garantiert eventuell-konsistent.
TRUSTED_PROXIES: set[str] = set(_DEFAULT_TRUSTED_PROXIES)
# Backward-compat Alias.
_TRUSTED_PROXIES = TRUSTED_PROXIES


def is_trusted_peer(host: str) -> bool:
    """Sync-Check gegen den TRUSTED_PROXIES-Snapshot. Snapshot wird vom
    Rate-Limit-Middleware via `_load_trusted_proxies()` regelmaessig refreshed."""
    return host in TRUSTED_PROXIES


async def refresh_trusted_proxies_snapshot() -> None:
    """Lifespan/Middleware-Hook: aktualisiert den globalen Snapshot."""
    global TRUSTED_PROXIES
    new = await _load_trusted_proxies()
    TRUSTED_PROXIES.clear()
    TRUSTED_PROXIES.update(new)

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
    # Trusted-Proxies-Snapshot opportunistisch refreshen (cached 30s in
    # _load_trusted_proxies). So sieht is_trusted_peer immer einen aktuellen
    # Wert ohne dass jeder Request die DB hittet.
    try:
        await refresh_trusted_proxies_snapshot()
    except Exception:
        pass
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
