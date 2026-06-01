"""
System-Status / Healthcheck-Modul.

Stellt einzelne Checks bereit die der Admin-UI als Status-Cards anzeigt.
Jeder Check ist eine async-Funktion die ein Dict zurueckgibt:

    {
        "key": "<short-id>",
        "label": "<Label fuer UI>",
        "status": "ok" | "warn" | "error" | "info",
        "message": "<eine Zeile fuer die Card>",
        "details": "<optionaler Mehrzeiler fuer Expand>",
        "latency_ms": <int, wie lange der Check brauchte>,
        "value": <optional, fuer numerische Anzeige>,
    }

Cheap = Tier 1 (laeuft beim Tab-Open, <1s gesamt).
Expensive = Tier 2 (on-demand button).
Anomalies = Tier 3 (Faktenbasis fuer UI-Karten).
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
from typing import Any

import httpx

import database
from config import get_settings, runtime_value

logger = logging.getLogger(__name__)

# Schwellwerte
DISK_WARN_FREE_PCT = 15
DISK_CRIT_FREE_PCT = 5
CATALOG_WARN_AGE_H = 36
CATALOG_CRIT_AGE_H = 72
APSCHED_JOB_OVERDUE_FACTOR = 3  # last_run > interval * factor → warn
STUCK_ACTION_MIN = 30
STUCK_WORKFLOW_MIN = 60 * 24
STALE_AGENT_DAYS = 30

DATA_DIR = os.path.dirname(database.DB_PATH)
DOWNLOADS_DIR = "/app/downloads"
BUILDER_URL_DEFAULT = "http://softshelf-builder:8766"


def _ms_since(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


def _result(key: str, label: str, status: str, message: str,
            *, t0: float | None = None, details: str = "",
            value: Any = None) -> dict:
    return {
        "key": key,
        "label": label,
        "status": status,
        "message": message,
        "details": details,
        "latency_ms": _ms_since(t0) if t0 is not None else 0,
        "value": value,
    }


# ─── Tier 1 ────────────────────────────────────────────────────────────

async def check_db_latency() -> dict:
    """Test-Insert + Rollback misst echte Write-Latency."""
    t0 = time.perf_counter()
    try:
        async with database._db() as db:
            await db.execute("BEGIN")
            await db.execute(
                "CREATE TEMP TABLE IF NOT EXISTS _hc_probe (x INTEGER)"
            )
            await db.execute("INSERT INTO _hc_probe (x) VALUES (1)")
            await db.execute("ROLLBACK")
        ms = _ms_since(t0)
        status = "ok" if ms < 200 else ("warn" if ms < 1000 else "error")
        return _result(
            "db_latency", "DB Latenz", status,
            f"{ms} ms Write-Roundtrip",
            t0=t0,
        )
    except Exception as e:
        return _result(
            "db_latency", "DB Latenz", "error",
            f"DB nicht erreichbar: {e}",
            t0=t0,
        )


async def check_db_size() -> dict:
    t0 = time.perf_counter()
    try:
        size_b = os.path.getsize(database.DB_PATH)
        size_mb = size_b / 1024 / 1024
        wal_b = 0
        for ext in ("-wal", "-shm"):
            p = database.DB_PATH + ext
            if os.path.exists(p):
                wal_b += os.path.getsize(p)
        wal_mb = wal_b / 1024 / 1024
        details = f"Hauptdatei: {size_mb:.1f} MB"
        if wal_mb > 0:
            details += f"\nWAL+SHM: {wal_mb:.1f} MB"
            if wal_mb > 200:
                return _result(
                    "db_size", "DB Groesse", "warn",
                    f"{size_mb:.1f} MB DB, {wal_mb:.0f} MB WAL (Checkpoint stuck?)",
                    t0=t0, details=details, value=size_b,
                )
        return _result(
            "db_size", "DB Groesse", "ok",
            f"{size_mb:.1f} MB",
            t0=t0, details=details, value=size_b,
        )
    except FileNotFoundError:
        return _result(
            "db_size", "DB Groesse", "error",
            "DB-Datei nicht gefunden",
            t0=t0,
        )


def _disk_check(path: str, key: str, label: str) -> dict:
    t0 = time.perf_counter()
    try:
        usage = shutil.disk_usage(path)
        free_pct = (usage.free / usage.total) * 100 if usage.total else 0
        free_gb = usage.free / 1024 / 1024 / 1024
        total_gb = usage.total / 1024 / 1024 / 1024
        if free_pct < DISK_CRIT_FREE_PCT:
            status = "error"
        elif free_pct < DISK_WARN_FREE_PCT:
            status = "warn"
        else:
            status = "ok"
        return _result(
            key, label, status,
            f"{free_gb:.1f} / {total_gb:.1f} GB frei ({free_pct:.0f}%)",
            t0=t0,
            details=f"Pfad: {path}\nFrei: {usage.free:,} Bytes\nGesamt: {usage.total:,} Bytes",
            value=usage.free,
        )
    except Exception as e:
        return _result(key, label, "error", f"Fehler: {e}", t0=t0)


async def check_disk_data() -> dict:
    return _disk_check(DATA_DIR, "disk_data", "Disk /app/data")


async def check_disk_downloads() -> dict:
    return _disk_check(DOWNLOADS_DIR, "disk_downloads", "Disk /app/downloads")


async def check_builder_ping() -> dict:
    t0 = time.perf_counter()
    cfg = get_settings()
    base = (cfg.builder_url or BUILDER_URL_DEFAULT).rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{base}/health")
        if r.status_code == 200:
            return _result(
                "builder_ping", "Builder", "ok",
                f"Erreichbar ({_ms_since(t0)} ms)",
                t0=t0, details=f"URL: {base}/health",
            )
        return _result(
            "builder_ping", "Builder", "error",
            f"HTTP {r.status_code}",
            t0=t0,
        )
    except Exception as e:
        return _result(
            "builder_ping", "Builder", "error",
            f"Nicht erreichbar: {e}",
            t0=t0, details=f"URL: {base}/health",
        )


async def check_winget_catalog() -> dict:
    """Alter der lokalen winget-Catalog-DB."""
    t0 = time.perf_counter()
    catalog_path = "/app/data/winget_index.db"
    try:
        if not os.path.exists(catalog_path):
            return _result(
                "winget_catalog", "Winget-Catalog", "warn",
                "Noch nicht heruntergeladen",
                t0=t0, details=f"Pfad: {catalog_path}",
            )
        mtime = os.path.getmtime(catalog_path)
        age_h = (time.time() - mtime) / 3600
        if age_h > CATALOG_CRIT_AGE_H:
            status = "error"
        elif age_h > CATALOG_WARN_AGE_H:
            status = "warn"
        else:
            status = "ok"
        return _result(
            "winget_catalog", "Winget-Catalog", status,
            f"Letzter Refresh vor {age_h:.0f} h",
            t0=t0,
            details=f"Pfad: {catalog_path}\nGroesse: {os.path.getsize(catalog_path)/1024/1024:.1f} MB",
            value=int(age_h),
        )
    except Exception as e:
        return _result(
            "winget_catalog", "Winget-Catalog", "error",
            f"Fehler: {e}", t0=t0,
        )


async def check_tactical_api() -> dict:
    t0 = time.perf_counter()
    base = (await runtime_value("tactical_url")).rstrip("/")
    api_key = await runtime_value("tactical_api_key")
    if not base:
        return _result(
            "tactical_api", "Tactical API", "warn",
            "Nicht konfiguriert",
            t0=t0, details="Einstellungen → Tactical RMM URL",
        )
    if not api_key:
        return _result(
            "tactical_api", "Tactical API", "warn",
            "API-Key fehlt",
            t0=t0,
        )
    try:
        async with httpx.AsyncClient(
            headers={"X-API-KEY": api_key}, timeout=8,
        ) as c:
            r = await c.get(f"{base}/core/version/")
        if r.status_code == 200:
            try:
                ver = r.json().get("version") or r.text.strip()[:80]
            except Exception:
                ver = r.text.strip()[:80]
            return _result(
                "tactical_api", "Tactical API", "ok",
                f"Erreichbar ({_ms_since(t0)} ms)",
                t0=t0,
                details=f"URL: {base}\nVersion: {ver}",
            )
        if r.status_code in (401, 403):
            return _result(
                "tactical_api", "Tactical API", "error",
                f"Auth fehlgeschlagen (HTTP {r.status_code})",
                t0=t0, details="API-Key in den Einstellungen pruefen.",
            )
        return _result(
            "tactical_api", "Tactical API", "error",
            f"HTTP {r.status_code}", t0=t0,
        )
    except httpx.TimeoutException:
        return _result(
            "tactical_api", "Tactical API", "error",
            "Timeout (>8s)", t0=t0,
        )
    except Exception as e:
        return _result(
            "tactical_api", "Tactical API", "error",
            f"Fehler: {e}", t0=t0,
        )


async def check_apscheduler() -> dict:
    """APScheduler-Job-Status: anzahl jobs + ggf. ueberfaellige."""
    t0 = time.perf_counter()
    try:
        import main as _main
        sched = getattr(_main, "scheduler", None)
        if sched is None:
            return _result(
                "scheduler", "Hintergrund-Jobs", "warn",
                "Scheduler nicht initialisiert", t0=t0,
            )
        jobs = sched.get_jobs()
        now = time.time()
        late: list[str] = []
        details_lines: list[str] = []
        for j in jobs:
            nrt = j.next_run_time
            details_lines.append(
                f"{j.id}: next={nrt.isoformat() if nrt else 'paused'}"
            )
            if nrt is not None:
                delta = nrt.timestamp() - now
                # Nur als "spät" markieren wenn next_run > 24h in der
                # Vergangenheit liegt (z.B. paused). next_run_time in der
                # Zukunft ist normal.
                if delta < -86400:
                    late.append(j.id)
        if not jobs:
            return _result(
                "scheduler", "Hintergrund-Jobs", "warn",
                "Keine Jobs registriert",
                t0=t0, details="\n".join(details_lines),
            )
        if late:
            return _result(
                "scheduler", "Hintergrund-Jobs", "warn",
                f"{len(late)} Jobs ueberfaellig: {', '.join(late[:3])}",
                t0=t0, details="\n".join(details_lines),
            )
        return _result(
            "scheduler", "Hintergrund-Jobs", "ok",
            f"{len(jobs)} Jobs registriert",
            t0=t0, details="\n".join(details_lines),
            value=len(jobs),
        )
    except Exception as e:
        return _result(
            "scheduler", "Hintergrund-Jobs", "error",
            f"Fehler: {e}", t0=t0,
        )


async def check_admin_users() -> dict:
    t0 = time.perf_counter()
    try:
        async with database._db() as db:
            async with db.execute(
                "SELECT COUNT(*) FROM admin_users WHERE is_active = 1"
            ) as cur:
                row = await cur.fetchone()
        n = (row or [0])[0]
        if n == 0:
            return _result(
                "admin_users", "Admin-Accounts", "error",
                "Keine aktiven Admins (nur Bootstrap moeglich)",
                t0=t0,
            )
        return _result(
            "admin_users", "Admin-Accounts", "ok",
            f"{n} aktive(r)",
            t0=t0, value=n,
        )
    except Exception as e:
        return _result(
            "admin_users", "Admin-Accounts", "error",
            f"Fehler: {e}", t0=t0,
        )


async def check_secret_key() -> dict:
    t0 = time.perf_counter()
    try:
        cfg = get_settings()
        sk = cfg.secret_key or ""
        weak_substrings = ("change", "secret", "default", "example", "test1234")
        if len(sk) < 32:
            return _result(
                "secret_key", "SECRET_KEY", "error",
                f"Zu kurz ({len(sk)} Zeichen, min. 32)",
                t0=t0,
            )
        for w in weak_substrings:
            if w in sk.lower():
                return _result(
                    "secret_key", "SECRET_KEY", "warn",
                    f"Enthaelt schwaches Muster '{w}'",
                    t0=t0,
                )
        return _result(
            "secret_key", "SECRET_KEY", "ok",
            f"{len(sk)} Zeichen, ok",
            t0=t0,
        )
    except Exception as e:
        return _result(
            "secret_key", "SECRET_KEY", "error",
            f"Fehler: {e}", t0=t0,
        )


# ─── Tier 3 — Anomalien ─────────────────────────────────────────────────

async def check_stuck_actions() -> dict:
    """action_logs status=running älter als N min."""
    t0 = time.perf_counter()
    try:
        async with database._db() as db:
            async with db.execute(
                "SELECT id, agent_id, package_name, action, created_at "
                "FROM action_log WHERE status='running' "
                "AND created_at < datetime('now', ?) "
                "ORDER BY id DESC LIMIT 50",
                (f"-{STUCK_ACTION_MIN} minutes",),
            ) as cur:
                rows = await cur.fetchall()
        n = len(rows)
        items = [
            {"id": r[0], "agent_id": r[1], "package": r[2], "action": r[3], "created_at": r[4]}
            for r in rows
        ]
        if n == 0:
            return _result(
                "stuck_actions", "Stuck Pending", "ok",
                "Keine stuck Aktionen",
                t0=t0, value=0,
            )
        status = "warn" if n < 10 else "error"
        return _result(
            "stuck_actions", "Stuck Pending", status,
            f"{n} Aktion(en) > {STUCK_ACTION_MIN} min im running-Zustand",
            t0=t0, value=n,
            details=str(items[:5]),
        )
    except Exception as e:
        return _result(
            "stuck_actions", "Stuck Pending", "error",
            f"Fehler: {e}", t0=t0,
        )


async def check_stale_agents() -> dict:
    """Agents ohne Heartbeat seit > N Tagen."""
    t0 = time.perf_counter()
    try:
        async with database._db() as db:
            async with db.execute(
                "SELECT COUNT(*) FROM agents "
                "WHERE last_seen IS NOT NULL "
                "AND last_seen < datetime('now', ?) ",
                (f"-{STALE_AGENT_DAYS} days",),
            ) as cur:
                row = await cur.fetchone()
        n = (row or [0])[0]
        if n == 0:
            return _result(
                "stale_agents", "Stale Agents", "ok",
                "Alle Agents aktiv", t0=t0, value=0,
            )
        return _result(
            "stale_agents", "Stale Agents", "info",
            f"{n} Agents kein Kontakt seit >{STALE_AGENT_DAYS}T",
            t0=t0, value=n,
            details="Eventuell vergessen zu loeschen.",
        )
    except Exception as e:
        return _result(
            "stale_agents", "Stale Agents", "error",
            f"Fehler: {e}", t0=t0,
        )


async def check_stuck_workflows() -> dict:
    t0 = time.perf_counter()
    try:
        async with database._db() as db:
            async with db.execute(
                "SELECT COUNT(*) FROM workflow_runs "
                "WHERE status IN ('running', 'pending') "
                "AND started_at < datetime('now', ?)",
                (f"-{STUCK_WORKFLOW_MIN} minutes",),
            ) as cur:
                row = await cur.fetchone()
        n = (row or [0])[0]
        if n == 0:
            return _result(
                "stuck_workflows", "Stuck Workflows", "ok",
                "Keine haengenden Runs", t0=t0, value=0,
            )
        return _result(
            "stuck_workflows", "Stuck Workflows", "warn",
            f"{n} Workflow-Run(s) >{STUCK_WORKFLOW_MIN//60}h aktiv",
            t0=t0, value=n,
        )
    except Exception as e:
        return _result(
            "stuck_workflows", "Stuck Workflows", "error",
            f"Fehler: {e}", t0=t0,
        )


async def check_failed_login_burst() -> dict:
    """Failed-Logins (HTTP 401 auf /admin/login) der letzten 1h."""
    t0 = time.perf_counter()
    try:
        async with database._db() as db:
            async with db.execute(
                "SELECT client_ip, COUNT(*) as n FROM audit_log "
                "WHERE method='POST' AND path='/admin/login' "
                "AND status IN (401, 403) "
                "AND ts > datetime('now', '-1 hour') "
                "GROUP BY client_ip ORDER BY n DESC LIMIT 5"
            ) as cur:
                rows = await cur.fetchall()
        total = sum(r[1] for r in rows)
        top = [(r[0], r[1]) for r in rows]
        if total == 0:
            return _result(
                "failed_logins", "Failed Logins (1h)", "ok",
                "Keine Fehlversuche", t0=t0, value=0,
            )
        if total < 20:
            status = "info"
        elif total < 100:
            status = "warn"
        else:
            status = "error"
        details_lines = [f"{ip}: {n}x" for ip, n in top]
        return _result(
            "failed_logins", "Failed Logins (1h)", status,
            f"{total} Fehlversuche von {len(rows)} IP(s)",
            t0=t0, value=total,
            details="\n".join(details_lines),
        )
    except Exception as e:
        return _result(
            "failed_logins", "Failed Logins (1h)", "error",
            f"Fehler: {e}", t0=t0,
        )


async def check_install_failure_rate() -> dict:
    """Per-Type Fehlerquote der letzten 24h."""
    t0 = time.perf_counter()
    try:
        async with database._db() as db:
            async with db.execute(
                "SELECT pkg_type, "
                "SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errs, "
                "COUNT(*) AS total "
                "FROM action_log "
                "WHERE created_at > datetime('now', '-24 hours') "
                "AND action IN ('install','uninstall') "
                "GROUP BY pkg_type"
            ) as cur:
                rows = await cur.fetchall()
        parts = []
        worst_pct = 0
        for ptype, errs, total in rows:
            if total < 5:
                continue
            pct = (errs / total) * 100
            worst_pct = max(worst_pct, pct)
            parts.append(f"{ptype or '?'}: {errs}/{total} ({pct:.0f}%)")
        if not parts:
            return _result(
                "install_fail_rate", "Install-Fehler (24h)", "ok",
                "Kaum Aktivitaet oder fehlerfrei", t0=t0,
            )
        if worst_pct >= 50:
            status = "error"
        elif worst_pct >= 25:
            status = "warn"
        else:
            status = "ok"
        return _result(
            "install_fail_rate", "Install-Fehler (24h)", status,
            f"Hoechste Quote: {worst_pct:.0f}%",
            t0=t0, value=int(worst_pct),
            details="\n".join(parts),
        )
    except Exception as e:
        return _result(
            "install_fail_rate", "Install-Fehler (24h)", "error",
            f"Fehler: {e}", t0=t0,
        )


# ─── Tier 2 — Expensive on-demand ──────────────────────────────────────

async def probe_build() -> dict:
    """Triggert ein Selftest-Build im Builder. Erwartet builder-/selftest
    Endpoint der ~30s laeuft. Faellt zurueck auf builder /health wenn
    selftest nicht existiert (alte Builder-Image)."""
    cfg = get_settings()
    base = (cfg.builder_url or BUILDER_URL_DEFAULT).rstrip("/")
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=120) as c:
            r = await c.post(f"{base}/selftest")
        ms = _ms_since(t0)
        if r.status_code == 404:
            # Fallback: keine selftest-Endpoint, nur /health.
            return _result(
                "probe_build", "Probe-Build", "warn",
                "Builder ohne /selftest — bitte Builder neu bauen",
                t0=t0,
            )
        try:
            j = r.json()
        except Exception:
            j = {}
        ok = bool(j.get("ok"))
        log = (j.get("log") or "")[-2000:]
        if ok:
            return _result(
                "probe_build", "Probe-Build", "ok",
                f"Build erfolgreich ({ms} ms)",
                t0=t0, details=log,
            )
        return _result(
            "probe_build", "Probe-Build", "error",
            f"Build fehlgeschlagen (HTTP {r.status_code})",
            t0=t0, details=log,
        )
    except httpx.TimeoutException:
        return _result(
            "probe_build", "Probe-Build", "error",
            "Timeout (>120s)", t0=t0,
        )
    except Exception as e:
        return _result(
            "probe_build", "Probe-Build", "error",
            f"Fehler: {e}", t0=t0,
        )


async def db_integrity_check() -> dict:
    """SQLite PRAGMA integrity_check. Sehr schnell bei kleinen DBs."""
    t0 = time.perf_counter()
    try:
        async with database._db() as db:
            async with db.execute("PRAGMA integrity_check") as cur:
                rows = await cur.fetchall()
        results = [r[0] for r in rows]
        if results == ["ok"]:
            return _result(
                "db_integrity", "DB Integrity", "ok",
                "PRAGMA integrity_check: ok",
                t0=t0,
            )
        return _result(
            "db_integrity", "DB Integrity", "error",
            f"{len(results)} Problem(e)",
            t0=t0, details="\n".join(results[:20]),
        )
    except Exception as e:
        return _result(
            "db_integrity", "DB Integrity", "error",
            f"Fehler: {e}", t0=t0,
        )


# ─── Sammlung ──────────────────────────────────────────────────────────

TIER1_CHECKS = [
    check_db_latency,
    check_db_size,
    check_disk_data,
    check_disk_downloads,
    check_builder_ping,
    check_winget_catalog,
    check_tactical_api,
    check_apscheduler,
    check_admin_users,
    check_secret_key,
]

ANOMALY_CHECKS = [
    check_stuck_actions,
    check_stale_agents,
    check_stuck_workflows,
    check_failed_login_burst,
    check_install_failure_rate,
]


async def run_all_tier1() -> list[dict]:
    """Parallel — Tier-1-Checks sind alle billig + unabhaengig."""
    return list(await asyncio.gather(*(c() for c in TIER1_CHECKS), return_exceptions=False))


async def run_all_anomalies() -> list[dict]:
    return list(await asyncio.gather(*(c() for c in ANOMALY_CHECKS), return_exceptions=False))
