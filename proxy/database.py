"""
SQLite-Datenbank für den Kiosk-Proxy.

Tabellen:
  packages     – vom Admin freigeschaltete Self-Service Pakete
  chocos_cache – Chocolatey-Paketliste aus Tactical (persistent gecacht)
  agents       – registrierte Kiosk-Clients (inkl. token_version für Revocation)
  install_log  – Aktionsprotokoll (install/uninstall pro Agent)
  audit_log    – HTTP-Request-Log

Wichtig: Alle Connection-Aufrufe gehen über `_db()` — der Helper aktiviert
PRAGMA foreign_keys = ON pro Connection (SQLite enforced FKs nicht
automatisch). Damit greifen die ON DELETE CASCADE Klauseln im Schema.
"""
import json
import os
from contextlib import asynccontextmanager
import aiosqlite

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "softshelf.db")
_JSON_LEGACY = os.path.join(os.path.dirname(__file__), "packages.json")


@asynccontextmanager
async def _db():
    """aiosqlite-Connection mit aktivierten Foreign Keys."""
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute("PRAGMA journal_mode = WAL")
        await conn.execute("PRAGMA busy_timeout = 5000")
        yield conn


async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with _db() as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS packages (
                name         TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                category     TEXT NOT NULL DEFAULT 'Allgemein',
                created_at   TEXT DEFAULT (datetime('now')),
                updated_at   TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS chocos_cache (
                name       TEXT PRIMARY KEY,
                cached_at  TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS agents (
                agent_id      TEXT PRIMARY KEY,
                hostname      TEXT NOT NULL,
                registered_at TEXT DEFAULT (datetime('now')),
                last_seen     TEXT DEFAULT (datetime('now')),
                token_version INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS install_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           TEXT DEFAULT (datetime('now')),
                agent_id     TEXT NOT NULL,
                hostname     TEXT NOT NULL,
                package_name TEXT NOT NULL,
                display_name TEXT NOT NULL,
                action       TEXT NOT NULL CHECK(action IN ('install','uninstall'))
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT DEFAULT (datetime('now')),
                method      TEXT,
                path        TEXT,
                client_ip   TEXT,
                status      INTEGER,
                duration_ms INTEGER
            );

            CREATE TABLE IF NOT EXISTS event_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT DEFAULT (datetime('now')),
                event_type TEXT NOT NULL,
                actor      TEXT,
                details    TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL DEFAULT '',
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS build_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at  TEXT DEFAULT (datetime('now')),
                finished_at TEXT,
                status      TEXT NOT NULL,
                log         TEXT NOT NULL DEFAULT '',
                proxy_url   TEXT,
                version     TEXT
            );

            CREATE TABLE IF NOT EXISTS admin_users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name  TEXT,
                email         TEXT,
                password_hash TEXT,
                sso_provider  TEXT,
                sso_subject   TEXT,
                is_active     INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT DEFAULT (datetime('now')),
                last_login    TEXT
            );

            CREATE TABLE IF NOT EXISTS admin_sessions (
                token       TEXT PRIMARY KEY,
                user_id     INTEGER NOT NULL,
                created_at  TEXT DEFAULT (datetime('now')),
                expires_at  TEXT NOT NULL,
                last_active TEXT DEFAULT (datetime('now')),
                user_agent  TEXT,
                ip          TEXT,
                FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS package_versions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name    TEXT NOT NULL,
                version_label   TEXT NOT NULL,
                filename        TEXT,
                sha256          TEXT,
                size_bytes      INTEGER,
                install_args    TEXT,
                uninstall_cmd   TEXT,
                notes           TEXT,
                archive_type    TEXT NOT NULL DEFAULT 'single',
                entry_point     TEXT,
                archive_entries TEXT,
                uploaded_at     TEXT DEFAULT (datetime('now')),
                UNIQUE(package_name, version_label),
                FOREIGN KEY (package_name) REFERENCES packages(name) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS agent_installations (
                agent_id      TEXT NOT NULL,
                package_name  TEXT NOT NULL,
                version_id    INTEGER,
                installed_at  TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (agent_id, package_name)
            );

            CREATE TABLE IF NOT EXISTS agent_blocklist (
                agent_id   TEXT PRIMARY KEY,
                hostname   TEXT,
                banned_at  TEXT DEFAULT (datetime('now')),
                banned_by  TEXT,
                reason     TEXT
            );

            CREATE TABLE IF NOT EXISTS agent_winget_state (
                agent_id          TEXT NOT NULL,
                winget_id         TEXT NOT NULL,
                installed_version TEXT,
                available_version TEXT,
                source            TEXT,
                scanned_at        TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (agent_id, winget_id)
            );

            CREATE TABLE IF NOT EXISTS agent_choco_state (
                agent_id          TEXT NOT NULL,
                choco_name        TEXT NOT NULL,
                installed_version TEXT,
                available_version TEXT,
                scanned_at        TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (agent_id, choco_name)
            );

            CREATE TABLE IF NOT EXISTS agent_scan_meta (
                agent_id             TEXT PRIMARY KEY,
                last_scan_at         TEXT,
                last_status          TEXT,
                last_error           TEXT,
                consecutive_failures INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS discovery_enrichment (
                display_name  TEXT PRIMARY KEY,
                winget_id     TEXT,
                confidence    TEXT,
                install_count INTEGER NOT NULL DEFAULT 0,
                checked_at    TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS profiles (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL UNIQUE COLLATE NOCASE,
                description     TEXT NOT NULL DEFAULT '',
                color           TEXT,
                auto_update     INTEGER NOT NULL DEFAULT 0,
                auto_update_at  TEXT,
                created_at      TEXT DEFAULT (datetime('now')),
                updated_at      TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS profile_packages (
                profile_id    INTEGER NOT NULL,
                package_name  TEXT NOT NULL,
                version_pin   TEXT,
                sort_order    INTEGER NOT NULL DEFAULT 0,
                added_at      TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (profile_id, package_name),
                FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
                FOREIGN KEY (package_name) REFERENCES packages(name) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS agent_profiles (
                agent_id     TEXT NOT NULL,
                profile_id   INTEGER NOT NULL,
                assigned_at  TEXT DEFAULT (datetime('now')),
                assigned_by  TEXT,
                PRIMARY KEY (agent_id, profile_id),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE,
                FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_install_log_agent  ON install_log(agent_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_profile_packages_pkg ON profile_packages(package_name);
            CREATE INDEX IF NOT EXISTS idx_agent_profiles_profile ON agent_profiles(profile_id);
            CREATE INDEX IF NOT EXISTS idx_event_log_ts ON event_log(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_event_log_type ON event_log(event_type, ts DESC);
            CREATE INDEX IF NOT EXISTS idx_agent_winget_id    ON agent_winget_state(winget_id);
            CREATE INDEX IF NOT EXISTS idx_agent_winget_avail ON agent_winget_state(available_version) WHERE available_version IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_agent_choco_name   ON agent_choco_state(choco_name);
            CREATE INDEX IF NOT EXISTS idx_agent_choco_avail  ON agent_choco_state(available_version) WHERE available_version IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_audit_log_ts       ON audit_log(ts);
            CREATE INDEX IF NOT EXISTS idx_build_log_ts      ON build_log(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_admin_sessions_user ON admin_sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_admin_sessions_exp  ON admin_sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_package_versions_pkg ON package_versions(package_name);
            CREATE INDEX IF NOT EXISTS idx_package_versions_sha ON package_versions(sha256);
            CREATE INDEX IF NOT EXISTS idx_agent_installations_pkg ON agent_installations(package_name);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_sso ON admin_users(sso_provider, sso_subject)
                WHERE sso_subject IS NOT NULL;
        """)
        # Geplante Jobs (Maintenance-Window-Dispatches)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scheduled_jobs (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                run_at         TEXT NOT NULL,
                action_type    TEXT NOT NULL,
                action_params  TEXT NOT NULL,
                description    TEXT,
                status         TEXT NOT NULL DEFAULT 'pending',
                created_at     TEXT DEFAULT (datetime('now')),
                created_by     INTEGER,
                executed_at    TEXT,
                result         TEXT,
                FOREIGN KEY (created_by) REFERENCES admin_users(id)
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_scheduled_status_time "
            "ON scheduled_jobs(status, run_at)"
        )

        # Rollout-Tracking (phased rollout state machine)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS rollouts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name    TEXT NOT NULL,
                display_name    TEXT,
                action          TEXT NOT NULL,
                current_phase   INTEGER NOT NULL DEFAULT 1,
                status          TEXT NOT NULL DEFAULT 'active',
                created_at      TEXT DEFAULT (datetime('now')),
                created_by      INTEGER,
                last_advanced_at TEXT,
                phase_history   TEXT,
                FOREIGN KEY (created_by) REFERENCES admin_users(id)
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_rollouts_status ON rollouts(status)"
        )

        # Action-Log (Install-Observability: pending → running → success/error)
        # Migration: alte Tabelle mit defekter FK droppen (packages hat name PK, nicht id)
        async with db.execute("PRAGMA table_info(action_log)") as cur:
            al_cols = {row[1] for row in await cur.fetchall()}
        if "package_id" in al_cols:
            await db.execute("DROP TABLE IF EXISTS action_log")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS action_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id     TEXT NOT NULL,
                hostname     TEXT NOT NULL,
                package_name TEXT NOT NULL,
                display_name TEXT NOT NULL,
                pkg_type     TEXT NOT NULL,
                action       TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'pending',
                exit_code    INTEGER,
                error_summary TEXT,
                stdout       TEXT,
                created_at   TEXT NOT NULL DEFAULT (datetime('now')),
                completed_at TEXT,
                job_id       TEXT,
                metadata     TEXT
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_action_log_agent "
            "ON action_log(agent_id, created_at DESC)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_action_log_status "
            "ON action_log(status)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_action_log_created "
            "ON action_log(created_at)"
        )

        # Workflow-Tabellen (Schritt-basierte Agent-Automatisierung)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS workflows (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
                description TEXT NOT NULL DEFAULT '',
                steps       TEXT NOT NULL DEFAULT '[]',
                created_at  TEXT DEFAULT (datetime('now')),
                updated_at  TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS workflow_runs (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                workflow_id      INTEGER NOT NULL REFERENCES workflows(id),
                agent_id         TEXT NOT NULL,
                hostname         TEXT NOT NULL DEFAULT '',
                step_snapshot    TEXT NOT NULL,
                current_step     INTEGER NOT NULL DEFAULT 0,
                status           TEXT NOT NULL DEFAULT 'pending'
                                 CHECK(status IN ('pending','running','completed','failed','timed_out','cancelled')),
                step_state       TEXT DEFAULT '{}',
                step_deadline_at TEXT,
                started_at       TEXT,
                updated_at       TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_workflow_active_run "
            "ON workflow_runs(agent_id) WHERE status IN ('pending', 'running')"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_workflow_runs_status "
            "ON workflow_runs(status)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_workflow_runs_agent "
            "ON workflow_runs(agent_id, id DESC)"
        )
        await db.execute("""
            CREATE TABLE IF NOT EXISTS agent_workflows (
                agent_id    TEXT NOT NULL,
                workflow_id INTEGER NOT NULL,
                assigned_at TEXT DEFAULT (datetime('now')),
                assigned_by TEXT,
                PRIMARY KEY (agent_id, workflow_id),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE,
                FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_workflows_wf "
            "ON agent_workflows(workflow_id)"
        )

        # Migration: job_id Spalte fuer Callback-Pattern
        async with db.execute("PRAGMA table_info(action_log)") as cur:
            al_cols_now = {row[1] for row in await cur.fetchall()}
        if "job_id" not in al_cols_now:
            await db.execute(
                "ALTER TABLE action_log ADD COLUMN job_id TEXT"
            )
        await db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_action_log_job "
            "ON action_log(job_id) WHERE job_id IS NOT NULL"
        )
        if "metadata" not in al_cols_now:
            await db.execute(
                "ALTER TABLE action_log ADD COLUMN metadata TEXT"
            )
        if "workflow_run_id" not in al_cols_now:
            await db.execute(
                "ALTER TABLE action_log ADD COLUMN workflow_run_id INTEGER "
                "REFERENCES workflow_runs(id)"
            )

        # Migration: role-Spalte auf admin_users fuer RBAC
        async with db.execute("PRAGMA table_info(admin_users)") as cur:
            au_cols = {row[1] for row in await cur.fetchall()}
        if "role" not in au_cols:
            await db.execute(
                "ALTER TABLE admin_users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'"
            )

        # Migration: ring-Spalte fuer phased rollout
        # Semantik v1.7.2: Ring 1 = Canary, Ring 2 = Pilot, Ring 3 = Produktion
        # (Default). Frueher (experimentell) war ring=0 Default — wir
        # migrieren alte Werte einmal auf 3.
        async with db.execute("PRAGMA table_info(agents)") as cur:
            agent_cols = {row[1] for row in await cur.fetchall()}
        if "ring" not in agent_cols:
            await db.execute("ALTER TABLE agents ADD COLUMN ring INTEGER NOT NULL DEFAULT 3")
        # Einmaliger Legacy-Migrate: ring=0 → 3 (Produktion).
        await db.execute("UPDATE agents SET ring = 3 WHERE ring = 0")

        # Migration: token_version-Spalte für ältere Installationen nachziehen
        async with db.execute("PRAGMA table_info(agents)") as cur:
            cols = {row[1] for row in await cur.fetchall()}
        if "token_version" not in cols:
            await db.execute("ALTER TABLE agents ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1")

        # Migration: custom-package-Felder + winget-Felder
        async with db.execute("PRAGMA table_info(packages)") as cur:
            pkg_cols = {row[1] for row in await cur.fetchall()}
        for col, ddl in [
            ("type",               "TEXT NOT NULL DEFAULT 'choco'"),
            ("filename",           "TEXT"),
            ("sha256",             "TEXT"),
            ("size_bytes",         "INTEGER"),
            ("install_args",       "TEXT"),
            ("uninstall_cmd",      "TEXT"),
            ("detection_name",     "TEXT"),
            ("current_version_id", "INTEGER"),
            ("archive_type",       "TEXT NOT NULL DEFAULT 'single'"),
            ("entry_point",        "TEXT"),
            ("winget_version",     "TEXT"),
            ("version_pin",        "TEXT"),
            ("winget_publisher",   "TEXT"),
            ("winget_scope",       "TEXT NOT NULL DEFAULT 'auto'"),
            ("required",           "INTEGER NOT NULL DEFAULT 0"),
            ("notes",              "TEXT"),
            ("staged_rollout",     "INTEGER NOT NULL DEFAULT 0"),
            ("hidden_in_kiosk",    "INTEGER NOT NULL DEFAULT 0"),
            ("auto_advance",       "INTEGER NOT NULL DEFAULT 0"),
            ("install_timeout",    "INTEGER NOT NULL DEFAULT 120"),
            ("check_reboot",       "INTEGER NOT NULL DEFAULT 0"),
        ]:
            if col not in pkg_cols:
                await db.execute(f"ALTER TABLE packages ADD COLUMN {col} {ddl}")

        # Migration: winget_version → version_pin (idempotent)
        await db.execute(
            "UPDATE packages SET version_pin = winget_version "
            "WHERE winget_version IS NOT NULL AND version_pin IS NULL"
        )
        await db.commit()

        # Migration: archive-Felder in package_versions
        async with db.execute("PRAGMA table_info(package_versions)") as cur:
            pv_cols = {row[1] for row in await cur.fetchall()}
        for col, ddl in [
            ("archive_type",    "TEXT NOT NULL DEFAULT 'single'"),
            ("entry_point",     "TEXT"),
            ("archive_entries", "TEXT"),
        ]:
            if col not in pv_cols:
                await db.execute(f"ALTER TABLE package_versions ADD COLUMN {col} {ddl}")

        # Migration: install_count in discovery_enrichment für ältere Installationen
        async with db.execute("PRAGMA table_info(discovery_enrichment)") as cur:
            de_cols = {row[1] for row in await cur.fetchall()}
        if "install_count" not in de_cols:
            await db.execute(
                "ALTER TABLE discovery_enrichment ADD COLUMN install_count INTEGER NOT NULL DEFAULT 0"
            )

        # Migration: last_action_error/at in agent_scan_meta für post-action
        # Fehler-Reporting (z.B. winget Installer-Technology-Mismatch)
        async with db.execute("PRAGMA table_info(agent_scan_meta)") as cur:
            sm_cols = {row[1] for row in await cur.fetchall()}
        if "last_action_error" not in sm_cols:
            await db.execute(
                "ALTER TABLE agent_scan_meta ADD COLUMN last_action_error TEXT"
            )
        if "last_action_at" not in sm_cols:
            await db.execute(
                "ALTER TABLE agent_scan_meta ADD COLUMN last_action_at TEXT"
            )
        if "last_action_package" not in sm_cols:
            await db.execute(
                "ALTER TABLE agent_scan_meta ADD COLUMN last_action_package TEXT"
            )
        if "last_action_full_output" not in sm_cols:
            await db.execute(
                "ALTER TABLE agent_scan_meta ADD COLUMN last_action_full_output TEXT"
            )
        if "last_action_action" not in sm_cols:
            await db.execute(
                "ALTER TABLE agent_scan_meta ADD COLUMN last_action_action TEXT"
            )
        if "last_action_error_acked_at" not in sm_cols:
            await db.execute(
                "ALTER TABLE agent_scan_meta ADD COLUMN last_action_error_acked_at TEXT"
            )

        # Migration: profile.auto_update + auto_update_at
        async with db.execute("PRAGMA table_info(profiles)") as cur:
            prof_cols = {row[1] for row in await cur.fetchall()}
        if "auto_update" not in prof_cols:
            await db.execute(
                "ALTER TABLE profiles ADD COLUMN auto_update INTEGER NOT NULL DEFAULT 0"
            )
        if "auto_update_at" not in prof_cols:
            await db.execute(
                "ALTER TABLE profiles ADD COLUMN auto_update_at TEXT"
            )

        await db.commit()

    await _migrate_custom_packages_to_versions()

    await _migrate_json_if_needed()

    await _backfill_choco_agent_installations()


async def _migrate_custom_packages_to_versions():
    """
    Migration: bestehende custom-Pakete mit dem flachen filename/sha256-Schema
    bekommen automatisch einen package_versions-Eintrag (Label 'v1') und
    werden über current_version_id verlinkt. Idempotent.
    """
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT name, filename, sha256, size_bytes, install_args, uninstall_cmd "
            "FROM packages "
            "WHERE type='custom' "
            "AND sha256 IS NOT NULL AND sha256 != '' "
            "AND (current_version_id IS NULL OR current_version_id = 0)"
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]

        for r in rows:
            # Hat dieses Paket schon eine Version? Dann nur den Pointer setzen.
            async with db.execute(
                "SELECT id FROM package_versions "
                "WHERE package_name = ? ORDER BY id ASC LIMIT 1",
                (r["name"],),
            ) as cur:
                existing = await cur.fetchone()

            if existing:
                version_id = existing[0]
            else:
                cur = await db.execute(
                    "INSERT INTO package_versions "
                    "(package_name, version_label, filename, sha256, size_bytes, "
                    " install_args, uninstall_cmd, notes) "
                    "VALUES (?, 'v1', ?, ?, ?, ?, ?, ?)",
                    (r["name"], r["filename"], r["sha256"], r["size_bytes"],
                     r["install_args"], r["uninstall_cmd"],
                     "Auto-Migration aus flachem Schema"),
                )
                version_id = cur.lastrowid

            await db.execute(
                "UPDATE packages SET current_version_id = ? WHERE name = ?",
                (version_id, r["name"]),
            )
        if rows:
            await db.commit()


async def _backfill_choco_agent_installations():
    """
    Migration: für jeden choco-Install im install_log dessen letzte Aktion
    'install' war (nicht 'uninstall' danach) und der noch keinen
    agent_installations-Eintrag hat, einen anlegen. Idempotent — läuft beim
    Start und tut nichts wenn alle Tracking-Einträge schon vorhanden sind.

    Wird gebraucht für Agents die VOR der Einführung des choco-Trackings
    (v1.4.0) Pakete via Softshelf installiert haben — sonst würde Pass 3 in
    get_agent_software diese Pakete nicht als deterministisch verwaltet
    erkennen können.
    """
    async with _db() as db:
        async with db.execute(
            """
            SELECT DISTINCT l.agent_id, l.package_name
            FROM install_log l
            JOIN packages p ON p.name = l.package_name
            LEFT JOIN agent_installations i
              ON i.agent_id = l.agent_id AND i.package_name = l.package_name
            WHERE p.type = 'choco'
              AND i.agent_id IS NULL
              AND l.id = (
                SELECT MAX(l2.id) FROM install_log l2
                WHERE l2.agent_id = l.agent_id
                  AND l2.package_name = l.package_name
              )
              AND l.action = 'install'
            """
        ) as cur:
            rows = await cur.fetchall()
        for agent_id, package_name in rows:
            await db.execute(
                "INSERT INTO agent_installations (agent_id, package_name, version_id) "
                "VALUES (?, ?, NULL)",
                (agent_id, package_name),
            )
        if rows:
            await db.commit()


async def _migrate_json_if_needed():
    """Importiert packages.json einmalig falls vorhanden."""
    if not os.path.exists(_JSON_LEGACY):
        return
    async with _db() as db:
        async with db.execute("SELECT COUNT(*) FROM packages") as cur:
            if (await cur.fetchone())[0] > 0:
                return
    with open(_JSON_LEGACY, encoding="utf-8") as f:
        data = json.load(f)
    for name, val in data.items():
        if isinstance(val, str):
            await upsert_package(name, val, "Allgemein")
        elif isinstance(val, dict):
            await upsert_package(name, val.get("display_name", name), val.get("category", "Allgemein"))
    os.rename(_JSON_LEGACY, _JSON_LEGACY + ".migrated")


async def health_ping():
    """Wirft Exception wenn DB nicht erreichbar – für /health."""
    async with _db() as db:
        async with db.execute("SELECT 1") as cur:
            await cur.fetchone()


async def cleanup_old_logs(days: int):
    """Löscht audit_log, install_log und event_log Einträge älter als N Tage."""
    if days <= 0:
        return
    async with _db() as db:
        await db.execute(
            "DELETE FROM audit_log WHERE ts < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.execute(
            "DELETE FROM install_log WHERE ts < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.execute(
            "DELETE FROM event_log WHERE ts < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()


# ── Packages ──────────────────────────────────────────────────────────────────

_PKG_COLS = (
    "name, display_name, category, type, filename, sha256, size_bytes, "
    "install_args, uninstall_cmd, detection_name, current_version_id, "
    "archive_type, entry_point, version_pin, winget_publisher, winget_scope, "
    "required, notes, staged_rollout, hidden_in_kiosk, auto_advance, "
    "install_timeout, check_reboot"
)


async def get_packages() -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT {_PKG_COLS} FROM packages ORDER BY category, display_name"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_package(name: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT {_PKG_COLS} FROM packages WHERE name = ?", (name,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_package_by_sha(sha256: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT {_PKG_COLS} FROM packages WHERE sha256 = ?", (sha256,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_package_names() -> set[str]:
    async with _db() as db:
        async with db.execute("SELECT name FROM packages") as cur:
            return {r[0] for r in await cur.fetchall()}


async def get_name_map() -> dict[str, str]:
    """Gibt {choco_name: display_name} zurück – für install/uninstall Checks."""
    async with _db() as db:
        async with db.execute("SELECT name, display_name FROM packages") as cur:
            return {r[0]: r[1] for r in await cur.fetchall()}


async def upsert_package(name: str, display_name: str, category: str = "Allgemein"):
    """Choco-Paket einfügen oder aktualisieren (legacy/Standardfall)."""
    async with _db() as db:
        await db.execute("""
            INSERT INTO packages (name, display_name, category, type)
            VALUES (?, ?, ?, 'choco')
            ON CONFLICT(name) DO UPDATE SET
                display_name = excluded.display_name,
                category     = excluded.category,
                updated_at   = datetime('now')
        """, (name, display_name, category))
        await db.commit()


async def upsert_custom_package(
    name: str,
    display_name: str,
    category: str,
    filename: str,
    sha256: str,
    size_bytes: int,
    install_args: str,
    uninstall_cmd: str | None,
    detection_name: str | None,
    archive_type: str = "single",
    entry_point: str | None = None,
):
    """Custom-Paket (MSI/EXE oder Programm-Ordner) einfügen oder aktualisieren."""
    async with _db() as db:
        await db.execute("""
            INSERT INTO packages (
                name, display_name, category, type,
                filename, sha256, size_bytes,
                install_args, uninstall_cmd, detection_name,
                archive_type, entry_point
            )
            VALUES (?, ?, ?, 'custom', ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                display_name   = excluded.display_name,
                category       = excluded.category,
                type           = 'custom',
                filename       = excluded.filename,
                sha256         = excluded.sha256,
                size_bytes     = excluded.size_bytes,
                install_args   = excluded.install_args,
                uninstall_cmd  = excluded.uninstall_cmd,
                detection_name = excluded.detection_name,
                archive_type   = excluded.archive_type,
                entry_point    = excluded.entry_point,
                updated_at     = datetime('now')
        """, (
            name, display_name, category,
            filename, sha256, size_bytes,
            install_args, uninstall_cmd, detection_name,
            archive_type, entry_point,
        ))
        await db.commit()


async def delete_package(name: str):
    async with _db() as db:
        await db.execute("DELETE FROM packages WHERE name = ?", (name,))
        await db.commit()


async def sha256_usage_count(sha256: str) -> int:
    """Anzahl Pakete die diesen SHA-256-Hash referenzieren (für safe-file-delete)."""
    async with _db() as db:
        async with db.execute(
            "SELECT COUNT(*) FROM packages WHERE sha256 = ?", (sha256,)
        ) as cur:
            return (await cur.fetchone())[0]


# ── Package Versions ──────────────────────────────────────────────────────────


async def add_package_version(
    package_name: str,
    version_label: str,
    filename: str | None,
    sha256: str | None,
    size_bytes: int | None,
    install_args: str | None,
    uninstall_cmd: str | None,
    notes: str | None,
    archive_type: str = "single",
    entry_point: str | None = None,
    archive_entries: str | None = None,
) -> int:
    """Neue Version anlegen. Wirft IntegrityError bei doppeltem Label."""
    async with _db() as db:
        cur = await db.execute(
            "INSERT INTO package_versions "
            "(package_name, version_label, filename, sha256, size_bytes, "
            " install_args, uninstall_cmd, notes, "
            " archive_type, entry_point, archive_entries) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (package_name, version_label, filename, sha256, size_bytes,
             install_args, uninstall_cmd, notes,
             archive_type, entry_point, archive_entries),
        )
        await db.commit()
        return cur.lastrowid


_PV_COLS = (
    "id, package_name, version_label, filename, sha256, size_bytes, "
    "install_args, uninstall_cmd, notes, archive_type, entry_point, "
    "archive_entries, uploaded_at"
)


async def get_package_versions(package_name: str) -> list[dict]:
    """Alle Versionen eines Pakets, neueste zuerst, mit is_current Flag."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT v.id, v.package_name, v.version_label, v.filename, v.sha256, "
            f"v.size_bytes, v.install_args, v.uninstall_cmd, v.notes, "
            f"v.archive_type, v.entry_point, v.archive_entries, v.uploaded_at, "
            f"(p.current_version_id = v.id) AS is_current "
            f"FROM package_versions v "
            f"JOIN packages p ON p.name = v.package_name "
            f"WHERE v.package_name = ? "
            f"ORDER BY v.id DESC",
            (package_name,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_package_version(version_id: int) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT {_PV_COLS} FROM package_versions WHERE id = ?",
            (version_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_current_package_version(package_name: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT v.id, v.package_name, v.version_label, v.filename, v.sha256, "
            f"v.size_bytes, v.install_args, v.uninstall_cmd, v.notes, "
            f"v.archive_type, v.entry_point, v.archive_entries, v.uploaded_at "
            f"FROM package_versions v "
            f"JOIN packages p ON p.current_version_id = v.id "
            f"WHERE p.name = ?",
            (package_name,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def set_current_package_version(package_name: str, version_id: int):
    """Setzt die aktuelle Version eines Pakets und synchronisiert die flachen
    Felder in `packages` (filename/sha256/archive_type/entry_point/...)
    damit Code der direkt auf packages.* zugreift die richtige Version sieht."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT package_name, filename, sha256, size_bytes, install_args, "
            "uninstall_cmd, archive_type, entry_point "
            "FROM package_versions WHERE id = ?",
            (version_id,),
        ) as cur:
            v = await cur.fetchone()
        if not v:
            raise ValueError("Version nicht gefunden")
        if v["package_name"] != package_name:
            raise ValueError("Version gehört nicht zu diesem Paket")
        await db.execute(
            "UPDATE packages SET "
            "current_version_id = ?, "
            "filename       = ?, "
            "sha256         = ?, "
            "size_bytes     = ?, "
            "install_args   = ?, "
            "uninstall_cmd  = ?, "
            "archive_type   = ?, "
            "entry_point    = ?, "
            "updated_at     = datetime('now') "
            "WHERE name = ?",
            (version_id, v["filename"], v["sha256"], v["size_bytes"],
             v["install_args"], v["uninstall_cmd"],
             v["archive_type"] or "single", v["entry_point"], package_name),
        )
        await db.commit()


async def delete_package_version(
    version_id: int, expected_package_name: str | None = None
) -> dict | None:
    """Löscht eine Version. Wirft ValueError wenn es die aktuelle Version ist
    (Caller muss zuerst eine andere als current setzen) oder wenn
    expected_package_name nicht zur Version passt (Schutz gegen "delete-by-id
    mit falschem Pfad"). Gibt {filename, sha256, package_name} der gelöschten
    Version zurück damit der Caller die Datei aufräumen kann."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT v.id, v.package_name, v.filename, v.sha256, "
            "(p.current_version_id = v.id) AS is_current "
            "FROM package_versions v "
            "JOIN packages p ON p.name = v.package_name "
            "WHERE v.id = ?",
            (version_id,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        if expected_package_name is not None and row["package_name"] != expected_package_name:
            raise ValueError(
                f"Version {version_id} gehört zu '{row['package_name']}', nicht zu '{expected_package_name}'"
            )
        if row["is_current"]:
            raise ValueError(
                "Aktuelle Version kann nicht gelöscht werden — vorher andere Version aktiv setzen"
            )
        await db.execute("DELETE FROM package_versions WHERE id = ?", (version_id,))
        await db.commit()
        return {
            "filename":     row["filename"],
            "sha256":       row["sha256"],
            "package_name": row["package_name"],
        }


async def count_versions_with_sha(sha256: str) -> int:
    """Anzahl Versionen die diesen SHA-256 referenzieren (für safe-file-delete)."""
    if not sha256:
        return 0
    async with _db() as db:
        async with db.execute(
            "SELECT COUNT(*) FROM package_versions WHERE sha256 = ?",
            (sha256,),
        ) as cur:
            return (await cur.fetchone())[0]


async def get_existing_version_labels(package_name: str) -> set[str]:
    async with _db() as db:
        async with db.execute(
            "SELECT version_label FROM package_versions WHERE package_name = ?",
            (package_name,),
        ) as cur:
            return {r[0] for r in await cur.fetchall()}


async def count_package_versions(package_name: str) -> int:
    async with _db() as db:
        async with db.execute(
            "SELECT COUNT(*) FROM package_versions WHERE package_name = ?",
            (package_name,),
        ) as cur:
            return (await cur.fetchone())[0]


async def delete_versions_for_package(package_name: str):
    """Bulk-delete aller Versionen — ohne current-Check. Nur beim
    kompletten Löschen eines Pakets verwenden."""
    async with _db() as db:
        await db.execute(
            "DELETE FROM package_versions WHERE package_name = ?",
            (package_name,),
        )
        await db.commit()


async def update_version_entry_point(version_id: int, entry_point: str):
    async with _db() as db:
        await db.execute(
            "UPDATE package_versions SET entry_point = ? WHERE id = ?",
            (entry_point, version_id),
        )
        await db.commit()


# ── Agent Installations ───────────────────────────────────────────────────────


async def set_agent_installation(
    agent_id: str, package_name: str, version_id: int | None
):
    """Trackt dass ein Agent ein bestimmtes Paket auf einer bestimmten Version
    installiert hat. Upsert-safe."""
    async with _db() as db:
        await db.execute(
            "INSERT INTO agent_installations (agent_id, package_name, version_id) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(agent_id, package_name) DO UPDATE SET "
            "version_id = excluded.version_id, "
            "installed_at = datetime('now')",
            (agent_id, package_name, version_id),
        )
        await db.commit()


async def delete_agent_installation(agent_id: str, package_name: str):
    async with _db() as db:
        await db.execute(
            "DELETE FROM agent_installations WHERE agent_id = ? AND package_name = ?",
            (agent_id, package_name),
        )
        await db.commit()


async def delete_installations_for_package(package_name: str):
    """Wird beim Löschen eines Pakets aufgerufen."""
    async with _db() as db:
        await db.execute(
            "DELETE FROM agent_installations WHERE package_name = ?",
            (package_name,),
        )
        await db.commit()


async def get_agent_installations(agent_id: str) -> list[dict]:
    """Welche Pakete hat dieser Agent über das Self-Service-Center installiert?"""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT i.package_name, i.version_id, i.installed_at, "
            "p.display_name, p.type, p.current_version_id, "
            "v.version_label, "
            "(i.version_id IS NOT NULL "
            " AND p.current_version_id IS NOT NULL "
            " AND i.version_id != p.current_version_id) AS outdated "
            "FROM agent_installations i "
            "JOIN packages p ON p.name = i.package_name "
            "LEFT JOIN package_versions v ON v.id = i.version_id "
            "WHERE i.agent_id = ? "
            "ORDER BY p.display_name",
            (agent_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_installations_for_package(package_name: str) -> list[dict]:
    """Welche Agents haben dieses Paket installiert (mit Version-Info)?"""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT i.agent_id, i.version_id, i.installed_at, "
            "a.hostname, a.last_seen, "
            "v.version_label, "
            "p.current_version_id, "
            "(i.version_id IS NOT NULL "
            " AND p.current_version_id IS NOT NULL "
            " AND i.version_id != p.current_version_id) AS outdated "
            "FROM agent_installations i "
            "JOIN agents a ON a.agent_id = i.agent_id "
            "JOIN packages p ON p.name = i.package_name "
            "LEFT JOIN package_versions v ON v.id = i.version_id "
            "WHERE i.package_name = ? "
            "ORDER BY a.hostname",
            (package_name,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_outdated_agents_for_package(package_name: str) -> list[dict]:
    """Agents die dieses Paket installiert haben, aber NICHT auf der current Version.
    Wird für 'Update pushen' gebraucht."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT i.agent_id, i.version_id, i.installed_at, "
            "a.hostname, a.last_seen, "
            "v.version_label "
            "FROM agent_installations i "
            "JOIN agents a ON a.agent_id = i.agent_id "
            "JOIN packages p ON p.name = i.package_name "
            "LEFT JOIN package_versions v ON v.id = i.version_id "
            "WHERE i.package_name = ? "
            "AND p.current_version_id IS NOT NULL "
            "AND (i.version_id IS NULL OR i.version_id != p.current_version_id) "
            "ORDER BY a.hostname",
            (package_name,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_agent_installation_summary(package_name: str) -> dict:
    """Übersicht: total, current, outdated, unknown-Version."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT "
            "COUNT(*) AS total, "
            "SUM(CASE WHEN i.version_id IS NULL THEN 1 ELSE 0 END) AS unknown, "
            "SUM(CASE WHEN i.version_id IS NOT NULL "
            "         AND i.version_id = p.current_version_id "
            "         THEN 1 ELSE 0 END) AS current, "
            "SUM(CASE WHEN i.version_id IS NOT NULL "
            "         AND p.current_version_id IS NOT NULL "
            "         AND i.version_id != p.current_version_id "
            "         THEN 1 ELSE 0 END) AS outdated "
            "FROM agent_installations i "
            "JOIN packages p ON p.name = i.package_name "
            "WHERE i.package_name = ?",
            (package_name,),
        ) as cur:
            row = await cur.fetchone()
            if not row:
                return {"total": 0, "current": 0, "outdated": 0, "unknown": 0}
            return {
                "total":    row["total"]    or 0,
                "current":  row["current"]  or 0,
                "outdated": row["outdated"] or 0,
                "unknown":  row["unknown"]  or 0,
            }


# ── Chocos Cache ──────────────────────────────────────────────────────────────

async def get_cached_chocos() -> list[str] | None:
    async with _db() as db:
        async with db.execute("SELECT COUNT(*) FROM chocos_cache") as cur:
            if (await cur.fetchone())[0] == 0:
                return None
        async with db.execute("SELECT name FROM chocos_cache ORDER BY name") as cur:
            return [r[0] for r in await cur.fetchall()]


async def save_chocos_cache(names: list[str]):
    async with _db() as db:
        await db.execute("DELETE FROM chocos_cache")
        await db.executemany("INSERT INTO chocos_cache (name) VALUES (?)", [(n,) for n in names])
        await db.commit()


# ── Agents ────────────────────────────────────────────────────────────────────

async def upsert_agent(agent_id: str, hostname: str):
    async with _db() as db:
        await db.execute("""
            INSERT INTO agents (agent_id, hostname)
            VALUES (?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname  = excluded.hostname,
                last_seen = datetime('now')
        """, (agent_id, hostname))
        await db.commit()


async def get_agents() -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT a.agent_id, a.hostname, a.registered_at, a.last_seen, "
            "a.ring, (b.agent_id IS NOT NULL) AS banned "
            "FROM agents a "
            "LEFT JOIN agent_blocklist b ON b.agent_id = a.agent_id "
            "ORDER BY a.hostname"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def set_agent_ring(agent_id: str, ring: int):
    """Setzt Ring-Nummer. Gueltige Werte: 1 (Canary), 2 (Pilot),
    3 (Produktion, Default). 0 ist Legacy, nicht mehr ueber UI setzbar."""
    if not isinstance(ring, int) or ring < 0 or ring > 9:
        raise ValueError(f"Invalid ring: {ring!r} (0..9)")
    async with _db() as db:
        await db.execute(
            "UPDATE agents SET ring = ? WHERE agent_id = ?",
            (ring, agent_id),
        )
        await db.commit()


async def get_agents_by_ring(ring: int | str) -> list[dict]:
    """Agents gefiltert nach Ring.

    Neue Semantik (v1.7.2):
      'all'   → alle Agents
      'prod'  → ring = 3 (Produktion, Final)
      'rings' → ring IN (1, 2) (Test-Ringe, vor Produktion)
      int N   → exakt ring = N
    """
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        if ring == "all":
            where, params = "1=1", ()
        elif ring == "rings":
            where, params = "a.ring IN (1, 2)", ()
        elif ring == "prod":
            where, params = "a.ring = 3", ()
        else:
            where, params = "a.ring = ?", (int(ring),)
        async with db.execute(
            f"SELECT a.agent_id, a.hostname, a.last_seen, a.ring "
            f"FROM agents a WHERE {where} AND a.agent_id NOT IN "
            f"(SELECT agent_id FROM agent_blocklist) "
            f"ORDER BY a.hostname",
            params,
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_ring_counts() -> dict:
    """Wieviele Agents pro Ring. Returns {ring_1: N, ring_2: N, ring_3: N}."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT ring, COUNT(*) AS n FROM agents "
            "WHERE agent_id NOT IN (SELECT agent_id FROM agent_blocklist) "
            "GROUP BY ring ORDER BY ring"
        ) as cur:
            return {f"ring_{r['ring']}": r["n"] for r in await cur.fetchall()}


async def get_ring_overview() -> list[dict]:
    """Pro Ring: liste aller Agents drin, sortiert nach Hostname.

    Fuer Rollouts-Tab Ring-Ueberblick:
      [{ring: 1, agents: [{agent_id, hostname, last_seen}, ...]}, ...]
    """
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT a.agent_id, a.hostname, a.last_seen, a.ring "
            "FROM agents a "
            "WHERE a.agent_id NOT IN (SELECT agent_id FROM agent_blocklist) "
            "ORDER BY a.ring, a.hostname"
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    by_ring: dict[int, list[dict]] = {}
    for r in rows:
        ring = r["ring"] if r["ring"] in (1, 2, 3) else 3
        by_ring.setdefault(ring, []).append(r)
    return [
        {"ring": n, "agents": by_ring.get(n, [])}
        for n in (1, 2, 3)
    ]


async def update_agent_seen(agent_id: str, hostname: str):
    """Aktualisiert last_seen für einen bekannten Agent (upsert-safe)."""
    async with _db() as db:
        await db.execute("""
            INSERT INTO agents (agent_id, hostname)
            VALUES (?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname  = excluded.hostname,
                last_seen = datetime('now')
        """, (agent_id, hostname))
        await db.commit()


async def get_token_version(agent_id: str) -> int:
    """Aktuelle Token-Version für einen Agent. 1 wenn unbekannt."""
    async with _db() as db:
        async with db.execute(
            "SELECT token_version FROM agents WHERE agent_id = ?", (agent_id,)
        ) as cur:
            row = await cur.fetchone()
            return row[0] if row else 1


async def bump_token_version(agent_id: str):
    """Erhöht die Token-Version → alle bisherigen JWTs für diesen Agent werden ungültig."""
    async with _db() as db:
        await db.execute(
            "UPDATE agents SET token_version = COALESCE(token_version, 1) + 1 WHERE agent_id = ?",
            (agent_id,),
        )
        await db.commit()


async def get_agent(agent_id: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT agent_id, hostname, registered_at, last_seen, token_version, ring "
            "FROM agents WHERE agent_id = ?",
            (agent_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_active_rollout_phases() -> dict[str, int]:
    """Map package_name → current_phase fuer alle aktiven Rollouts.
    Fuer Kiosk-Filter: zeigt einen Update nur wenn sein Ring erreicht ist."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT package_name, current_phase FROM rollouts WHERE status = 'active'"
        ) as cur:
            return {r["package_name"]: r["current_phase"] for r in await cur.fetchall()}


async def get_rollout_latest_per_package() -> dict[str, dict]:
    """Map package_name → letzter Rollout-Record (egal welcher Status).
    Fuer Staged-Overview: zeigt 'letzter Rollout vor 3d' bei fertigen
    Paketen."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM rollouts "
            "WHERE id IN (SELECT MAX(id) FROM rollouts GROUP BY package_name)"
        ) as cur:
            return {r["package_name"]: dict(r) for r in await cur.fetchall()}


async def get_package_error_counts() -> dict[str, int]:
    """Anzahl offener (un-acked) Fehler pro Paket. Fuer Rollout-Badge."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT last_action_package AS pkg, COUNT(*) AS n "
            "FROM agent_scan_meta "
            "WHERE last_action_error IS NOT NULL AND last_action_error != '' "
            "  AND (last_action_error_acked_at IS NULL OR last_action_error_acked_at = '') "
            "  AND last_action_package IS NOT NULL "
            "GROUP BY last_action_package"
        ) as cur:
            return {r["pkg"]: r["n"] for r in await cur.fetchall()}


async def get_package_agents_version_split(
    pkg_name: str, pkg_type: str, target_version: str | None,
) -> dict[str, dict]:
    """Pro Ring: wieviele Agents haben target vs. andere Version vs. missing.

    Gibt {ring:int → {total, on_target, on_old, missing, agents:[{agent_id,
    hostname, installed_version, ring}]}} zurueck. Ring 1/2/3 immer present.
    """
    async with _db() as db:
        db.row_factory = aiosqlite.Row

        # Alle nicht-gesperrten Agents mit Ring holen
        async with db.execute(
            "SELECT a.agent_id, a.hostname, a.ring, a.last_seen "
            "FROM agents a "
            "WHERE a.agent_id NOT IN (SELECT agent_id FROM agent_blocklist) "
            "ORDER BY a.hostname"
        ) as cur:
            all_agents = [dict(r) for r in await cur.fetchall()]

        # Installed-Version pro Agent fuer dieses Paket
        installed_map: dict[str, str | None] = {}
        if pkg_type == "winget":
            async with db.execute(
                "SELECT agent_id, installed_version FROM agent_winget_state "
                "WHERE winget_id = ?", (pkg_name,),
            ) as cur:
                for r in await cur.fetchall():
                    installed_map[r["agent_id"]] = r["installed_version"]
        elif pkg_type == "choco":
            async with db.execute(
                "SELECT agent_id, installed_version FROM agent_choco_state "
                "WHERE choco_name = ?", (pkg_name,),
            ) as cur:
                for r in await cur.fetchall():
                    installed_map[r["agent_id"]] = r["installed_version"]
        else:  # custom
            async with db.execute(
                "SELECT ai.agent_id, pv.version_label "
                "FROM agent_installations ai "
                "LEFT JOIN package_versions pv ON pv.id = ai.version_id "
                "WHERE ai.package_name = ?", (pkg_name,),
            ) as cur:
                for r in await cur.fetchall():
                    installed_map[r["agent_id"]] = r["version_label"]

    out: dict[int, dict] = {1: None, 2: None, 3: None}
    for ring in (1, 2, 3):
        agents_in_ring = [a for a in all_agents if (a["ring"] or 3) == ring]
        on_target = on_old = missing = 0
        agent_items = []
        for a in agents_in_ring:
            iv = installed_map.get(a["agent_id"])
            if not iv:
                state = "missing"
                missing += 1
            elif target_version and iv == target_version:
                state = "on_target"
                on_target += 1
            else:
                state = "on_old"
                on_old += 1
            agent_items.append({
                "agent_id":           a["agent_id"],
                "hostname":           a["hostname"],
                "ring":               ring,
                "last_seen":          a["last_seen"],
                "installed_version":  iv,
                "state":              state,
            })
        out[ring] = {
            "total":     len(agents_in_ring),
            "on_target": on_target,
            "on_old":    on_old,
            "missing":   missing,
            "agents":    agent_items,
        }
    return out


async def delete_agent(agent_id: str):
    """Löscht einen Agent komplett: agent_installations + install_log + agents.
    Tokens werden dadurch automatisch ungültig (verify_machine_token vergleicht
    gegen einen nicht-existenten token_version → default 1, alte Tokens haben tv>1).
    Eintrag im agent_blocklist (falls vorhanden) bleibt bestehen, damit ein
    bewusst gebannter Client nach Re-Register nicht wieder auftaucht."""
    async with _db() as db:
        await db.execute("DELETE FROM agent_installations WHERE agent_id = ?", (agent_id,))
        await db.execute("DELETE FROM install_log WHERE agent_id = ?", (agent_id,))
        await db.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
        await db.commit()


# ── Agent Blocklist (Bann) ────────────────────────────────────────────────────


async def is_agent_banned(agent_id: str) -> bool:
    async with _db() as db:
        async with db.execute(
            "SELECT 1 FROM agent_blocklist WHERE agent_id = ? LIMIT 1",
            (agent_id,),
        ) as cur:
            return (await cur.fetchone()) is not None


async def ban_agent(agent_id: str, hostname: str | None, banned_by: str, reason: str | None):
    """Setzt einen Agent auf die Blocklist (idempotent — überschreibt existing)."""
    async with _db() as db:
        await db.execute(
            "INSERT INTO agent_blocklist (agent_id, hostname, banned_by, reason) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(agent_id) DO UPDATE SET "
            "hostname = excluded.hostname, "
            "banned_by = excluded.banned_by, "
            "reason = excluded.reason, "
            "banned_at = datetime('now')",
            (agent_id, hostname, banned_by, reason),
        )
        await db.commit()


async def unban_agent(agent_id: str) -> bool:
    """Entfernt einen Agent von der Blocklist. Gibt True zurück wenn es einen
    Eintrag gab."""
    async with _db() as db:
        cur = await db.execute(
            "DELETE FROM agent_blocklist WHERE agent_id = ?", (agent_id,)
        )
        await db.commit()
        return cur.rowcount > 0


async def get_blocklist() -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT agent_id, hostname, banned_at, banned_by, reason "
            "FROM agent_blocklist ORDER BY banned_at DESC"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_blocked_agent_ids() -> set[str]:
    """Set aller gebannten agent_ids — für effizienten Bulk-Lookup."""
    async with _db() as db:
        async with db.execute("SELECT agent_id FROM agent_blocklist") as cur:
            return {r[0] for r in await cur.fetchall()}


# ── Install Log ────────────────────────────────────────────────────────────────

async def log_install(agent_id: str, hostname: str, package_name: str,
                      display_name: str, action: str):
    async with _db() as db:
        await db.execute(
            "INSERT INTO install_log (agent_id, hostname, package_name, display_name, action) VALUES (?,?,?,?,?)",
            (agent_id, hostname, package_name, display_name, action),
        )
        await db.commit()


async def get_install_log(agent_id: str | None = None, limit: int = 200) -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        if agent_id:
            async with db.execute(
                "SELECT ts, agent_id, hostname, package_name, display_name, action "
                "FROM install_log WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
                (agent_id, limit),
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]
        else:
            async with db.execute(
                "SELECT ts, agent_id, hostname, package_name, display_name, action "
                "FROM install_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]


# ── Audit Log ─────────────────────────────────────────────────────────────────

async def log_request(method: str, path: str, client_ip: str, status: int, duration_ms: int):
    async with _db() as db:
        await db.execute(
            "INSERT INTO audit_log (method, path, client_ip, status, duration_ms) VALUES (?,?,?,?,?)",
            (method, path, client_ip, status, duration_ms),
        )
        await db.commit()


async def get_audit_log(limit: int = 200) -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT ts, method, path, client_ip, status, duration_ms FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


# ── Settings ──────────────────────────────────────────────────────────────────

async def get_setting(key: str, default: str = "") -> str:
    """Lesen eines Runtime-Settings aus dem DB (sub-ms via Index)."""
    async with _db() as db:
        async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
            return row[0] if row and row[0] else default


async def get_all_settings() -> dict[str, str]:
    async with _db() as db:
        async with db.execute("SELECT key, value FROM settings") as cur:
            return {k: v for k, v in await cur.fetchall()}


async def set_setting(key: str, value: str):
    async with _db() as db:
        await db.execute("""
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
        """, (key, value))
        await db.commit()


async def set_settings_bulk(items: dict[str, str]):
    async with _db() as db:
        for k, v in items.items():
            await db.execute("""
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
            """, (k, v))
        await db.commit()


# ── Build Log ─────────────────────────────────────────────────────────────────

async def start_build_log(proxy_url: str, version: str) -> int:
    async with _db() as db:
        cur = await db.execute(
            "INSERT INTO build_log (status, proxy_url, version) VALUES ('running', ?, ?)",
            (proxy_url, version),
        )
        await db.commit()
        return cur.lastrowid


async def finish_build_log(build_id: int, status: str, log: str):
    async with _db() as db:
        await db.execute(
            "UPDATE build_log SET status = ?, log = ?, finished_at = datetime('now') WHERE id = ?",
            (status, log, build_id),
        )
        await db.commit()


async def get_builds(limit: int = 10) -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, started_at, finished_at, status, proxy_url, version, "
            "substr(log, 1, 200) AS log_preview "
            "FROM build_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_build(build_id: int) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, started_at, finished_at, status, proxy_url, version, log "
            "FROM build_log WHERE id = ?",
            (build_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_latest_successful_build() -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, started_at, finished_at, status, proxy_url, version "
            "FROM build_log WHERE status = 'success' ORDER BY id DESC LIMIT 1"
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


# ── Admin Users ───────────────────────────────────────────────────────────────

_USER_COLS = (
    "id, username, display_name, email, password_hash, sso_provider, "
    "sso_subject, is_active, created_at, last_login, role"
)


async def get_admin_users() -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT {_USER_COLS} FROM admin_users ORDER BY username"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_admin_user_by_username(username: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT {_USER_COLS} FROM admin_users WHERE username = ? COLLATE NOCASE",
            (username,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_admin_user_by_id(user_id: int) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT {_USER_COLS} FROM admin_users WHERE id = ?", (user_id,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_admin_user_by_sso(provider: str, subject: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT {_USER_COLS} FROM admin_users "
            f"WHERE sso_provider = ? AND sso_subject = ?",
            (provider, subject),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def create_admin_user(
    username: str,
    display_name: str | None,
    email: str | None,
    password_hash: str | None,
    sso_provider: str | None = None,
    sso_subject: str | None = None,
    is_active: bool = True,
    role: str = "admin",
) -> int:
    if role not in ("admin", "operator", "viewer"):
        raise ValueError(f"Invalid role: {role!r}")
    async with _db() as db:
        cur = await db.execute(
            "INSERT INTO admin_users (username, display_name, email, password_hash, "
            "sso_provider, sso_subject, is_active, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (username, display_name, email, password_hash, sso_provider, sso_subject,
             1 if is_active else 0, role),
        )
        await db.commit()
        return cur.lastrowid


async def update_admin_user(
    user_id: int,
    *,
    display_name: str | None = None,
    email: str | None = None,
    password_hash: str | None = None,
    is_active: bool | None = None,
    role: str | None = None,
):
    fields, values = [], []
    if display_name is not None:
        fields.append("display_name = ?")
        values.append(display_name)
    if email is not None:
        fields.append("email = ?")
        values.append(email)
    if password_hash is not None:
        fields.append("password_hash = ?")
        values.append(password_hash)
    if is_active is not None:
        fields.append("is_active = ?")
        values.append(1 if is_active else 0)
    if role is not None:
        if role not in ("admin", "operator", "viewer"):
            raise ValueError(f"Invalid role: {role!r}")
        fields.append("role = ?")
        values.append(role)
    if not fields:
        return
    values.append(user_id)
    async with _db() as db:
        await db.execute(
            f"UPDATE admin_users SET {', '.join(fields)} WHERE id = ?",
            values,
        )
        await db.commit()


async def delete_admin_user(user_id: int):
    async with _db() as db:
        await db.execute("DELETE FROM admin_users WHERE id = ?", (user_id,))
        await db.commit()


async def touch_admin_login(user_id: int):
    async with _db() as db:
        await db.execute(
            "UPDATE admin_users SET last_login = datetime('now') WHERE id = ?",
            (user_id,),
        )
        await db.commit()


async def count_active_admins() -> int:
    async with _db() as db:
        async with db.execute(
            "SELECT COUNT(*) FROM admin_users WHERE is_active = 1"
        ) as cur:
            return (await cur.fetchone())[0]


# ── Admin Sessions ────────────────────────────────────────────────────────────

async def create_admin_session(
    token: str, user_id: int, expires_at: str, ip: str | None, user_agent: str | None
):
    async with _db() as db:
        await db.execute(
            "INSERT INTO admin_sessions (token, user_id, expires_at, ip, user_agent) "
            "VALUES (?, ?, ?, ?, ?)",
            (token, user_id, expires_at, ip, user_agent),
        )
        await db.commit()


async def get_admin_session(token: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT s.token, s.user_id, s.created_at, s.expires_at, s.last_active, "
            "s.ip, s.user_agent, "
            "u.username, u.display_name, u.email, u.is_active, u.sso_provider, u.role "
            "FROM admin_sessions s JOIN admin_users u ON u.id = s.user_id "
            "WHERE s.token = ?",
            (token,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def touch_admin_session(token: str):
    async with _db() as db:
        await db.execute(
            "UPDATE admin_sessions SET last_active = datetime('now') WHERE token = ?",
            (token,),
        )
        await db.commit()


async def delete_admin_session(token: str):
    async with _db() as db:
        await db.execute("DELETE FROM admin_sessions WHERE token = ?", (token,))
        await db.commit()


async def delete_user_sessions(user_id: int):
    async with _db() as db:
        await db.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))
        await db.commit()


async def cleanup_expired_sessions():
    async with _db() as db:
        await db.execute(
            "DELETE FROM admin_sessions WHERE expires_at < datetime('now')"
        )
        await db.commit()


async def get_user_sessions(user_id: int) -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT token, created_at, expires_at, last_active, ip, user_agent "
            "FROM admin_sessions WHERE user_id = ? ORDER BY last_active DESC",
            (user_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


# ── Winget Packages ───────────────────────────────────────────────────────────


async def upsert_winget_package(
    name: str,
    display_name: str,
    category: str,
    publisher: str | None = None,
    version_pin: str | None = None,
    winget_scope: str = "auto",
):
    """Winget-Paket einfügen oder aktualisieren. `name` ist die winget
    PackageIdentifier (z. B. 'Mozilla.Firefox'). winget_scope steuert ob
    wir --scope machine erzwingen (=machine), per-user via run_as_user
    installieren (=user), oder ersteren versuchen mit run_as_user-Fallback
    (=auto, Default)."""
    async with _db() as db:
        await db.execute(
            """
            INSERT INTO packages (
                name, display_name, category, type,
                winget_publisher, version_pin, winget_scope
            )
            VALUES (?, ?, ?, 'winget', ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                display_name     = excluded.display_name,
                category         = excluded.category,
                type             = 'winget',
                winget_publisher = excluded.winget_publisher,
                version_pin      = excluded.version_pin,
                winget_scope     = excluded.winget_scope,
                updated_at       = datetime('now')
            """,
            (name, display_name, category, publisher, version_pin, winget_scope),
        )
        await db.commit()


async def update_package_auto_advance(name: str, auto: bool):
    async with _db() as db:
        await db.execute(
            "UPDATE packages SET auto_advance = ?, updated_at = datetime('now') WHERE name = ?",
            (1 if auto else 0, name),
        )
        await db.commit()


async def update_package_hidden(name: str, hidden: bool):
    async with _db() as db:
        await db.execute(
            "UPDATE packages SET hidden_in_kiosk = ?, updated_at = datetime('now') WHERE name = ?",
            (1 if hidden else 0, name),
        )
        await db.commit()


async def update_package_staged(name: str, staged: bool):
    async with _db() as db:
        await db.execute(
            "UPDATE packages SET staged_rollout = ?, updated_at = datetime('now') WHERE name = ?",
            (1 if staged else 0, name),
        )
        await db.commit()


async def update_package_required(name: str, required: bool):
    async with _db() as db:
        await db.execute(
            "UPDATE packages SET required = ?, updated_at = datetime('now') WHERE name = ?",
            (1 if required else 0, name),
        )
        await db.commit()


async def update_package_notes(name: str, notes: str):
    async with _db() as db:
        await db.execute(
            "UPDATE packages SET notes = ?, updated_at = datetime('now') WHERE name = ?",
            (notes or None, name),
        )
        await db.commit()


async def get_required_packages() -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT {_PKG_COLS}, required, notes "
            "FROM packages WHERE required = 1 ORDER BY display_name COLLATE NOCASE"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_compliance_overview() -> dict:
    """Pro required-Paket: auf welchen Agents installiert / fehlend.

    Returns:
      {
        required_packages: [{name, display_name, type, installed_count,
                             missing: [agent_id,hostname,...], total_agents}],
        fully_compliant_agents: N,
        noncompliant_agents: N,
      }
    """
    required = await get_required_packages()
    if not required:
        return {"required_packages": [], "fully_compliant_agents": 0, "noncompliant_agents": 0}

    all_agents = await get_agents()
    total_agents = len(all_agents)
    agent_map = {a["agent_id"]: a for a in all_agents}

    async with _db() as db:
        db.row_factory = aiosqlite.Row
        result_packages: list[dict] = []
        # Fuer Compliance-Summary je Agent
        missing_by_agent: dict[str, int] = {a["agent_id"]: 0 for a in all_agents}

        for pkg in required:
            ptype = pkg.get("type") or "choco"
            installed_ids: set[str] = set()
            if ptype == "winget":
                async with db.execute(
                    "SELECT agent_id FROM agent_winget_state WHERE winget_id = ?",
                    (pkg["name"],),
                ) as cur:
                    installed_ids = {r["agent_id"] for r in await cur.fetchall()}
            elif ptype == "choco":
                async with db.execute(
                    "SELECT agent_id FROM agent_choco_state WHERE choco_name = ?",
                    (pkg["name"],),
                ) as cur:
                    installed_ids = {r["agent_id"] for r in await cur.fetchall()}
            else:  # custom
                async with db.execute(
                    "SELECT agent_id FROM agent_installations WHERE package_name = ?",
                    (pkg["name"],),
                ) as cur:
                    installed_ids = {r["agent_id"] for r in await cur.fetchall()}

            missing = []
            for a in all_agents:
                if a["agent_id"] not in installed_ids:
                    missing.append({"agent_id": a["agent_id"], "hostname": a.get("hostname")})
                    missing_by_agent[a["agent_id"]] = missing_by_agent.get(a["agent_id"], 0) + 1

            result_packages.append({
                "name":            pkg["name"],
                "display_name":    pkg["display_name"],
                "type":            ptype,
                "installed_count": len(installed_ids),
                "total_agents":    total_agents,
                "missing":         missing,
            })

        fully_compliant = sum(1 for v in missing_by_agent.values() if v == 0)
        noncompliant = total_agents - fully_compliant

    return {
        "required_packages":       result_packages,
        "fully_compliant_agents":  fully_compliant,
        "noncompliant_agents":     noncompliant,
        "total_agents":            total_agents,
    }


async def update_winget_scope(name: str, scope: str):
    """Aendert nur das winget_scope-Feld eines existierenden Pakets."""
    if scope not in ("auto", "machine", "user"):
        raise ValueError(f"Invalid winget_scope: {scope!r}")
    async with _db() as db:
        await db.execute(
            "UPDATE packages SET winget_scope = ?, updated_at = datetime('now') "
            "WHERE name = ? AND type = 'winget'",
            (scope, name),
        )
        await db.commit()


async def update_winget_package(
    name: str,
    display_name: str,
    category: str,
    version_pin: str | None = None,
):
    async with _db() as db:
        await db.execute(
            """
            UPDATE packages
            SET display_name = ?, category = ?, version_pin = ?,
                updated_at = datetime('now')
            WHERE name = ? AND type = 'winget'
            """,
            (display_name, category, version_pin, name),
        )
        await db.commit()


async def set_version_pin(name: str, version: str | None):
    """Generischer Version-Pin-Setter fuer alle Pakettypen."""
    async with _db() as db:
        await db.execute(
            "UPDATE packages SET version_pin = ?, updated_at = datetime('now') WHERE name = ?",
            (version, name),
        )
        await db.commit()


async def get_choco_known_versions(choco_name: str) -> list[str]:
    """Alle bekannten Versionen eines choco-Pakets aus Fleet-Scan-Daten."""
    async with _db() as db:
        async with db.execute(
            "SELECT DISTINCT installed_version FROM agent_choco_state "
            "WHERE choco_name = ? AND installed_version IS NOT NULL "
            "UNION "
            "SELECT DISTINCT available_version FROM agent_choco_state "
            "WHERE choco_name = ? AND available_version IS NOT NULL",
            (choco_name, choco_name),
        ) as cur:
            rows = await cur.fetchall()
    versions = [r[0] for r in rows if r[0]]
    versions.sort(reverse=True)
    return versions


async def get_whitelisted_winget_ids() -> set[str]:
    """Set aller winget PackageIdentifier in der Whitelist — für Discovery-
    Filtering (zeige nur das was *nicht* whitelisted ist)."""
    async with _db() as db:
        async with db.execute(
            "SELECT name FROM packages WHERE type = 'winget'"
        ) as cur:
            return {r[0] for r in await cur.fetchall()}


# ── Agent Winget State ────────────────────────────────────────────────────────


async def replace_agent_winget_state(
    agent_id: str, rows: list[dict]
):
    """Atomarer Replace aller winget-State-Rows eines Agents.
    `rows` ist eine Liste von dicts mit den Keys
    `winget_id, installed_version, available_version, source`.
    Wird nach jedem Scan aufgerufen und ersetzt den kompletten State des Agents.
    """
    async with _db() as db:
        await db.execute(
            "DELETE FROM agent_winget_state WHERE agent_id = ?", (agent_id,)
        )
        if rows:
            await db.executemany(
                "INSERT INTO agent_winget_state "
                "(agent_id, winget_id, installed_version, available_version, source, scanned_at) "
                "VALUES (?, ?, ?, ?, ?, datetime('now'))",
                [
                    (
                        agent_id,
                        r["winget_id"],
                        r.get("installed_version"),
                        r.get("available_version"),
                        r.get("source"),
                    )
                    for r in rows
                ],
            )
        await db.commit()


async def get_agent_winget_state(agent_id: str) -> dict[str, dict]:
    """Liefert den aktuellen winget-State eines Agents als dict[winget_id → row]."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT winget_id, installed_version, available_version, source, scanned_at "
            "FROM agent_winget_state WHERE agent_id = ?",
            (agent_id,),
        ) as cur:
            return {r["winget_id"]: dict(r) for r in await cur.fetchall()}


async def upsert_scan_meta(
    agent_id: str,
    status: str,
    error: str | None = None,
):
    """
    Schreibt das Scan-Ergebnis in agent_scan_meta. Bei `status='ok'` wird
    consecutive_failures auf 0 zurückgesetzt, sonst inkrementiert.
    """
    async with _db() as db:
        if status == "ok":
            await db.execute(
                "INSERT INTO agent_scan_meta "
                "(agent_id, last_scan_at, last_status, last_error, consecutive_failures) "
                "VALUES (?, datetime('now'), 'ok', NULL, 0) "
                "ON CONFLICT(agent_id) DO UPDATE SET "
                "last_scan_at = datetime('now'), "
                "last_status = 'ok', "
                "last_error = NULL, "
                "consecutive_failures = 0",
                (agent_id,),
            )
        else:
            await db.execute(
                "INSERT INTO agent_scan_meta "
                "(agent_id, last_scan_at, last_status, last_error, consecutive_failures) "
                "VALUES (?, datetime('now'), ?, ?, 1) "
                "ON CONFLICT(agent_id) DO UPDATE SET "
                "last_scan_at = datetime('now'), "
                "last_status = excluded.last_status, "
                "last_error = excluded.last_error, "
                "consecutive_failures = consecutive_failures + 1",
                (agent_id, status, error),
            )
        await db.commit()


async def get_scan_meta(agent_id: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT agent_id, last_scan_at, last_status, last_error, "
            "consecutive_failures, last_action_error, last_action_at, "
            "last_action_package "
            "FROM agent_scan_meta WHERE agent_id = ?",
            (agent_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def upsert_action_result(
    agent_id: str,
    package_name: str,
    error: str | None,
    full_output: str | None = None,
    action: str | None = None,
):
    """Schreibt das Ergebnis einer User- oder Admin-Aktion (Install/Upgrade/
    Uninstall) in agent_scan_meta. error=None bedeutet Aktion erfolgreich,
    bei Erfolg wird last_action_error gelöscht. full_output ist der ganze
    stdout-Tail der Operation — landet in last_action_full_output und kann
    im Admin-UI ueber das Fehler-Detail-Modal geoeffnet werden."""
    # Output auf vernuenftiges Limit kuerzen — winget kann Megabytes Progress-
    # Bars rauspucken die wir nicht in der DB brauchen.
    if full_output and len(full_output) > 32_000:
        full_output = full_output[:16_000] + "\n[...]\n" + full_output[-16_000:]
    async with _db() as db:
        # Neue Aktion → Ack zuruecksetzen damit ein neuer Fehler (oder auch
        # ein Erfolgs-Reset) wieder im UI auftaucht. Sonst wuerde ein
        # gestern ack'd Agent stumm bleiben trotz frischem Problem.
        await db.execute(
            "INSERT INTO agent_scan_meta "
            "(agent_id, last_action_at, last_action_package, last_action_error, "
            " last_action_full_output, last_action_action, last_action_error_acked_at) "
            "VALUES (?, datetime('now'), ?, ?, ?, ?, NULL) "
            "ON CONFLICT(agent_id) DO UPDATE SET "
            "last_action_at = datetime('now'), "
            "last_action_package = excluded.last_action_package, "
            "last_action_error = excluded.last_action_error, "
            "last_action_full_output = excluded.last_action_full_output, "
            "last_action_action = excluded.last_action_action, "
            "last_action_error_acked_at = NULL",
            (agent_id, package_name, error, full_output, action),
        )
        await db.commit()


async def get_last_action_output(agent_id: str) -> dict | None:
    """Liefert den vollen Output + Metadaten der letzten Aktion fuer einen Agent.
    Wird vom Admin-UI Fehler-Detail-Modal gerufen."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT last_action_at, last_action_package, last_action_action, "
            "       last_action_error, last_action_full_output "
            "FROM agent_scan_meta WHERE agent_id = ?",
            (agent_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_all_scan_meta() -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT agent_id, last_scan_at, last_status, last_error, consecutive_failures "
            "FROM agent_scan_meta"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_fleet_errors(limit: int = 200, include_acked: bool = False) -> list[dict]:
    """Alle Agents mit aktivem last_action_error, joined mit hostname.
    Fuer Home-Dashboard + Fleet-Error-Zentrale.

    Default: nur UN-acked Fehler (acked_at IS NULL). include_acked=True
    zeigt alles mit Flag."""
    where = "WHERE m.last_action_error IS NOT NULL AND m.last_action_error != ''"
    if not include_acked:
        where += " AND (m.last_action_error_acked_at IS NULL OR m.last_action_error_acked_at = '')"
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT m.agent_id, a.hostname, m.last_action_at, m.last_action_package, "
            f"       m.last_action_action, m.last_action_error, "
            f"       m.last_action_error_acked_at "
            f"FROM agent_scan_meta m "
            f"LEFT JOIN agents a ON a.agent_id = m.agent_id "
            f"{where} "
            f"ORDER BY m.last_action_at DESC LIMIT ?",
            (limit,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def ack_agent_error(agent_id: str):
    """Markiert den letzten Fehler eines Agents als bestaetigt. Fehler-Text
    und -Output bleiben fuer Audit-Zwecke erhalten."""
    async with _db() as db:
        await db.execute(
            "UPDATE agent_scan_meta SET last_action_error_acked_at = datetime('now') "
            "WHERE agent_id = ?",
            (agent_id,),
        )
        await db.commit()


async def ack_all_errors() -> int:
    """Bulk-Ack aller offenen Fehler. Gibt Count zurueck."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT COUNT(*) AS n FROM agent_scan_meta "
            "WHERE last_action_error IS NOT NULL AND last_action_error != '' "
            "AND (last_action_error_acked_at IS NULL OR last_action_error_acked_at = '')"
        ) as cur:
            count = (await cur.fetchone())["n"]
        await db.execute(
            "UPDATE agent_scan_meta SET last_action_error_acked_at = datetime('now') "
            "WHERE last_action_error IS NOT NULL AND last_action_error != '' "
            "AND (last_action_error_acked_at IS NULL OR last_action_error_acked_at = '')"
        )
        await db.commit()
        return count


async def get_fleet_stats() -> dict:
    """Aggregierte Fleet-KPIs fuer das Home-Dashboard.

    Returns:
      {
        agents: {total, online, recent, banned},
        packages: {total, winget, choco, custom},
        outdated: {winget, choco, custom, total_edges},
        errors: {count_7d},
        installs: {today, last_7d},
      }
    """
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    today_iso = now.date().isoformat()
    seven_days_ago = (now - timedelta(days=7)).isoformat(timespec='seconds')
    five_min_ago = (now - timedelta(minutes=5)).isoformat(timespec='seconds')
    day_ago = (now - timedelta(hours=24)).isoformat(timespec='seconds')

    async with _db() as db:
        db.row_factory = aiosqlite.Row

        # Agents
        async with db.execute("SELECT COUNT(*) AS n FROM agents") as cur:
            agents_total = (await cur.fetchone())["n"]
        async with db.execute(
            "SELECT COUNT(*) AS n FROM agents WHERE last_seen >= ?",
            (five_min_ago,),
        ) as cur:
            agents_online = (await cur.fetchone())["n"]
        async with db.execute(
            "SELECT COUNT(*) AS n FROM agents WHERE last_seen >= ?",
            (day_ago,),
        ) as cur:
            agents_recent = (await cur.fetchone())["n"]
        async with db.execute("SELECT COUNT(*) AS n FROM agent_blocklist") as cur:
            agents_banned = (await cur.fetchone())["n"]

        # Pakete
        async with db.execute(
            "SELECT type, COUNT(*) AS n FROM packages GROUP BY type"
        ) as cur:
            pkg_by_type = {r["type"]: r["n"] for r in await cur.fetchall()}
        pkg_total = sum(pkg_by_type.values())

        # Outdated edges
        async with db.execute(
            "SELECT COUNT(*) AS n FROM agent_winget_state aws "
            "JOIN packages p ON p.name = aws.winget_id "
            "JOIN agents a ON a.agent_id = aws.agent_id "
            "WHERE aws.available_version IS NOT NULL"
        ) as cur:
            outdated_winget = (await cur.fetchone())["n"]
        async with db.execute(
            "SELECT COUNT(*) AS n FROM agent_choco_state acs "
            "JOIN packages p ON p.name = acs.choco_name "
            "JOIN agents a ON a.agent_id = acs.agent_id "
            "WHERE acs.available_version IS NOT NULL"
        ) as cur:
            outdated_choco = (await cur.fetchone())["n"]
        # Custom: agent_installations wo version_id != package.current_version_id
        async with db.execute(
            "SELECT COUNT(*) AS n FROM agent_installations ai "
            "JOIN packages p ON p.name = ai.package_name "
            "JOIN agents a ON a.agent_id = ai.agent_id "
            "WHERE p.type = 'custom' AND p.current_version_id IS NOT NULL "
            "  AND ai.version_id IS NOT NULL "
            "  AND ai.version_id != p.current_version_id"
        ) as cur:
            outdated_custom = (await cur.fetchone())["n"]

        # Fehler letzte 7 Tage
        async with db.execute(
            "SELECT COUNT(*) AS n FROM agent_scan_meta "
            "WHERE last_action_error IS NOT NULL AND last_action_error != '' "
            "AND (last_action_error_acked_at IS NULL OR last_action_error_acked_at = '') "
            "AND last_action_at >= ?",
            (seven_days_ago,),
        ) as cur:
            errors_count = (await cur.fetchone())["n"]

        # Installs today / last 7d (aus install_log falls vorhanden)
        try:
            async with db.execute(
                "SELECT COUNT(*) AS n FROM install_log WHERE ts >= ?",
                (today_iso,),
            ) as cur:
                installs_today = (await cur.fetchone())["n"]
            async with db.execute(
                "SELECT COUNT(*) AS n FROM install_log WHERE ts >= ?",
                (seven_days_ago,),
            ) as cur:
                installs_7d = (await cur.fetchone())["n"]
        except Exception:
            installs_today = installs_7d = 0

    ring_counts = await get_ring_counts()

    return {
        "agents": {
            "total":   agents_total,
            "online":  agents_online,
            "recent":  agents_recent,
            "banned":  agents_banned,
            "rings":   ring_counts,
        },
        "packages": {
            "total":  pkg_total,
            "winget": pkg_by_type.get("winget", 0),
            "choco":  pkg_by_type.get("choco", 0),
            "custom": pkg_by_type.get("custom", 0),
        },
        "outdated": {
            "winget": outdated_winget,
            "choco":  outdated_choco,
            "custom": outdated_custom,
            "total":  outdated_winget + outdated_choco + outdated_custom,
        },
        "errors": {"count_7d": errors_count},
        "installs": {"today": installs_today, "last_7d": installs_7d},
    }


async def get_recent_installs(limit: int = 20) -> list[dict]:
    """Letzte Installs/Uninstalls fleet-weit fuer Dashboard-Widget."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        try:
            async with db.execute(
                "SELECT l.ts, l.agent_id, l.hostname, l.package_name, "
                "       l.display_name, l.action "
                "FROM install_log l "
                "ORDER BY l.ts DESC LIMIT ?",
                (limit,),
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]
        except Exception:
            return []


# ── Scheduled Jobs (Maintenance-Window dispatches) ─────────────────────────

async def create_scheduled_job(
    run_at: str, action_type: str, action_params: dict,
    description: str, created_by: int | None,
) -> int:
    import json as _json
    async with _db() as db:
        cur = await db.execute(
            "INSERT INTO scheduled_jobs "
            "(run_at, action_type, action_params, description, created_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (run_at, action_type, _json.dumps(action_params), description, created_by),
        )
        await db.commit()
        return cur.lastrowid


async def get_scheduled_job(job_id: int) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM scheduled_jobs WHERE id = ?", (job_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def list_scheduled_jobs(status: str | None = None, limit: int = 100) -> list[dict]:
    where = "WHERE status = ?" if status else ""
    params = (status, limit) if status else (limit,)
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT * FROM scheduled_jobs {where} "
            f"ORDER BY run_at ASC LIMIT ?",
            params,
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def list_pending_scheduled_jobs() -> list[dict]:
    """Pending jobs fuer APScheduler-Wiederaufnahme beim Start."""
    return await list_scheduled_jobs(status="pending", limit=500)


async def update_scheduled_job_status(
    job_id: int, status: str, result: str | None = None,
):
    async with _db() as db:
        await db.execute(
            "UPDATE scheduled_jobs SET status = ?, executed_at = datetime('now'), "
            "result = ? WHERE id = ?",
            (status, result, job_id),
        )
        await db.commit()


async def cancel_scheduled_job(job_id: int):
    async with _db() as db:
        await db.execute(
            "UPDATE scheduled_jobs SET status = 'cancelled', "
            "executed_at = datetime('now') WHERE id = ? AND status = 'pending'",
            (job_id,),
        )
        await db.commit()


# ── Rollouts (phased rollout state machine) ─────────────────────────────────

async def create_rollout(
    package_name: str, display_name: str, action: str,
    created_by: int | None,
) -> int:
    import json as _json
    async with _db() as db:
        cur = await db.execute(
            "INSERT INTO rollouts "
            "(package_name, display_name, action, current_phase, status, "
            " created_by, last_advanced_at, phase_history) "
            "VALUES (?, ?, ?, 1, 'active', ?, datetime('now'), ?)",
            (package_name, display_name, action, created_by, _json.dumps([])),
        )
        await db.commit()
        return cur.lastrowid


async def get_rollout(rollout_id: int) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM rollouts WHERE id = ?", (rollout_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def list_rollouts_for_package(name: str, limit: int = 50) -> list[dict]:
    """Alle Rollouts eines Pakets, neueste zuerst. Fuer Per-Paket-Historie
    im Rollout-Details-Expand."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM rollouts WHERE package_name = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (name, limit),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def list_rollouts(status: str | None = None, limit: int = 50) -> list[dict]:
    where = "WHERE status = ?" if status else "WHERE 1=1"
    params = (status, limit) if status else (limit,)
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT * FROM rollouts {where} "
            f"ORDER BY (status='active') DESC, created_at DESC LIMIT ?",
            params,
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def advance_rollout(rollout_id: int, phase_result: dict,
                          expected_phase: int | None = None) -> dict | None:
    """Naechste Phase — compare-and-swap gegen aktuelle Phase.

    Wenn expected_phase gesetzt ist: UPDATE greift nur wenn current_phase
    noch genau diesen Wert hat. Damit kann bei gleichzeitigem Klick von
    zwei Admins nicht von 1 auf 3 gesprungen werden — zweiter Aufruf
    laeuft ins Leere und bekommt None zurueck.

    Returns updated rollout oder None wenn Rollout weg, inaktiv oder
    Phase inzwischen weitergelaufen ist."""
    import json as _json
    r = await get_rollout(rollout_id)
    if not r or r["status"] != "active":
        return None
    if expected_phase is None:
        expected_phase = r["current_phase"]
    if r["current_phase"] != expected_phase:
        return None
    hist = []
    try:
        hist = _json.loads(r["phase_history"] or "[]")
    except Exception:
        hist = []
    hist.append({
        "phase": r["current_phase"],
        "at": phase_result.get("at"),
        **phase_result,
    })
    next_phase = r["current_phase"] + 1
    new_status = "done" if next_phase > 3 else "active"
    async with _db() as db:
        cur = await db.execute(
            "UPDATE rollouts SET current_phase = ?, status = ?, "
            "last_advanced_at = datetime('now'), phase_history = ? "
            "WHERE id = ? AND current_phase = ? AND status = 'active'",
            (next_phase, new_status, _json.dumps(hist), rollout_id, expected_phase),
        )
        await db.commit()
        if cur.rowcount == 0:
            # Race verloren — anderer Request hat advanced
            return None
    return await get_rollout(rollout_id)


async def cancel_rollout(rollout_id: int):
    async with _db() as db:
        await db.execute(
            "UPDATE rollouts SET status = 'cancelled', "
            "last_advanced_at = datetime('now') WHERE id = ? AND status = 'active'",
            (rollout_id,),
        )
        await db.commit()


async def get_top_outdated_packages(limit: int = 10) -> list[dict]:
    """Pakete mit den meisten outdated Clients — priorisierte Update-Liste."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        # Winget
        async with db.execute(
            "SELECT s.winget_id AS name, p.display_name, 'winget' AS type, COUNT(*) AS outdated "
            "FROM agent_winget_state s "
            "JOIN packages p ON p.name = s.winget_id "
            "WHERE s.available_version IS NOT NULL "
            "GROUP BY s.winget_id, p.display_name "
            "ORDER BY outdated DESC LIMIT ?",
            (limit,),
        ) as cur:
            wg = [dict(r) for r in await cur.fetchall()]
        # Choco
        async with db.execute(
            "SELECT s.choco_name AS name, p.display_name, 'choco' AS type, COUNT(*) AS outdated "
            "FROM agent_choco_state s "
            "JOIN packages p ON p.name = s.choco_name "
            "WHERE s.available_version IS NOT NULL "
            "GROUP BY s.choco_name, p.display_name "
            "ORDER BY outdated DESC LIMIT ?",
            (limit,),
        ) as cur:
            ch = [dict(r) for r in await cur.fetchall()]
    combined = wg + ch
    combined.sort(key=lambda r: r["outdated"], reverse=True)
    return combined[:limit]


async def get_agents_due_for_scan(
    online_threshold_seconds: int = 300,
    skip_failures_above: int = 7,
) -> list[dict]:
    """
    Gibt Agents zurück die für den nightly-Scan in Frage kommen:
      - last_seen <= online_threshold_seconds (Kiosk-Client war kürzlich online)
      - nicht gebannt
      - consecutive_failures < skip_failures_above
    """
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT a.agent_id, a.hostname, a.last_seen, "
            "       COALESCE(m.consecutive_failures, 0) AS failures "
            "FROM agents a "
            "LEFT JOIN agent_scan_meta m ON m.agent_id = a.agent_id "
            "LEFT JOIN agent_blocklist b ON b.agent_id = a.agent_id "
            "WHERE b.agent_id IS NULL "
            "  AND (julianday('now') - julianday(a.last_seen)) * 86400 <= ? "
            "  AND COALESCE(m.consecutive_failures, 0) < ?",
            (online_threshold_seconds, skip_failures_above),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def reset_scan_failures(agent_id: str):
    """Setzt consecutive_failures auf 0 — wird vom manuellen Re-Scan-Button
    aufgerufen, damit ein als 'gestoppt' markierter Agent wieder am nightly
    Batch teilnimmt."""
    async with _db() as db:
        await db.execute(
            "UPDATE agent_scan_meta SET consecutive_failures = 0 WHERE agent_id = ?",
            (agent_id,),
        )
        await db.commit()


# ── Discovery (Fleet) ─────────────────────────────────────────────────────────


async def query_winget_discovery() -> list[dict]:
    """
    Liefert alle winget-IDs die irgendwo in der Flotte installiert sind,
    aber NICHT in der packages-Whitelist. Sortiert nach Install-Count
    absteigend.
    """
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT s.winget_id, "
            "       COUNT(DISTINCT s.agent_id) AS install_count, "
            "       MAX(s.installed_version) AS sample_version "
            "FROM agent_winget_state s "
            "LEFT JOIN packages p "
            "  ON p.name = s.winget_id AND p.type = 'winget' "
            "WHERE p.name IS NULL "
            "GROUP BY s.winget_id "
            "ORDER BY install_count DESC, s.winget_id ASC"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_winget_discovery_count() -> int:
    """Anzahl distincter winget-IDs in der Flotte ohne Whitelist-Match.
    Wird vom Header-Banner einmal pro Page-Load abgerufen."""
    async with _db() as db:
        async with db.execute(
            "SELECT COUNT(DISTINCT s.winget_id) "
            "FROM agent_winget_state s "
            "LEFT JOIN packages p "
            "  ON p.name = s.winget_id AND p.type = 'winget' "
            "WHERE p.name IS NULL"
        ) as cur:
            return (await cur.fetchone())[0] or 0


async def query_software_discovery() -> list[dict]:
    """
    Bonus-Discovery: liefert alle Tactical-software-scan Display-Namen aus
    dem discovery_enrichment Cache, gefiltert auf Einträge mit install_count > 0
    UND nicht-whitelisted winget_id (oder gar keine winget_id zugewiesen).
    Reihenfolge: install_count desc, dann confidence (high zuerst).
    """
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT e.display_name, e.winget_id, e.confidence, e.install_count, e.checked_at "
            "FROM discovery_enrichment e "
            "LEFT JOIN packages p "
            "  ON p.name = e.winget_id AND p.type = 'winget' "
            "WHERE e.install_count > 0 "
            "  AND p.name IS NULL "
            "ORDER BY e.install_count DESC, "
            "         CASE e.confidence "
            "           WHEN 'high'   THEN 0 "
            "           WHEN 'medium' THEN 1 "
            "           WHEN 'low'    THEN 2 "
            "           ELSE 3 END, "
            "         e.display_name"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


# ── Discovery Enrichment Cache ────────────────────────────────────────────────


async def upsert_enrichment(
    display_name: str,
    winget_id: str | None,
    confidence: str,
    install_count: int,
):
    """
    Schreibt einen Enrichment-Cache-Eintrag. Wird vom täglichen
    enrichment Job aufgerufen — install_count ist die Anzahl Agents in
    der Flotte auf denen dieser Display-Name aktuell installiert ist.
    """
    async with _db() as db:
        await db.execute(
            "INSERT INTO discovery_enrichment "
            "(display_name, winget_id, confidence, install_count, checked_at) "
            "VALUES (?, ?, ?, ?, datetime('now')) "
            "ON CONFLICT(display_name) DO UPDATE SET "
            "winget_id = excluded.winget_id, "
            "confidence = excluded.confidence, "
            "install_count = excluded.install_count, "
            "checked_at = datetime('now')",
            (display_name, winget_id, confidence, install_count),
        )
        await db.commit()


async def get_enrichment(display_name: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT display_name, winget_id, confidence, install_count, checked_at "
            "FROM discovery_enrichment WHERE display_name = ?",
            (display_name,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def reset_enrichment_counts():
    """Setzt alle install_count auf 0. Wird am Anfang jedes enrichment
    Job runs aufgerufen, danach werden die aktuellen Counts gesetzt — so
    fallen Display-Namen die nicht mehr in der Flotte sind aus der
    Discovery-Liste raus (install_count = 0)."""
    async with _db() as db:
        await db.execute("UPDATE discovery_enrichment SET install_count = 0")
        await db.commit()


async def cleanup_stale_enrichment(days: int = 30):
    """Löscht discovery_enrichment Einträge die länger als N Tage nicht
    mehr aktualisiert wurden UND install_count = 0 haben. Verhindert
    unbegrenztes DB-Wachstum durch Software die mal kurz drauf war und
    dann wieder verschwand."""
    async with _db() as db:
        await db.execute(
            "DELETE FROM discovery_enrichment "
            "WHERE install_count = 0 "
            "  AND checked_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()


async def cleanup_winget_state_for_package(package_name: str):
    """Wird beim Disable eines winget-Pakets aufgerufen, um State-Rows zu
    entfernen die niemand mehr referenziert. Nicht strikt nötig — der State
    bleibt sonst im DB liegen und taucht beim nächsten Scan wieder auf —
    aber sauber."""
    async with _db() as db:
        await db.execute(
            "DELETE FROM agent_winget_state WHERE winget_id = ?", (package_name,)
        )
        await db.commit()


# ── Agent Choco State ────────────────────────────────────────────────────────


async def replace_agent_choco_state(agent_id: str, rows: list[dict]):
    """Atomarer Replace aller choco-State-Rows eines Agents. `rows` ist eine
    Liste von dicts mit den Keys `choco_name, installed_version,
    available_version`. Wird nach jedem nightly oder targeted Choco-Scan
    aufgerufen."""
    async with _db() as db:
        await db.execute(
            "DELETE FROM agent_choco_state WHERE agent_id = ?", (agent_id,)
        )
        if rows:
            await db.executemany(
                "INSERT INTO agent_choco_state "
                "(agent_id, choco_name, installed_version, available_version, scanned_at) "
                "VALUES (?, ?, ?, ?, datetime('now'))",
                [
                    (
                        agent_id,
                        r["choco_name"],
                        r.get("installed_version"),
                        r.get("available_version"),
                    )
                    for r in rows
                ],
            )
        await db.commit()


async def get_agent_choco_state(agent_id: str) -> dict[str, dict]:
    """Liefert den aktuellen choco-State eines Agents als dict[choco_name → row].
    Wird vom packages.py /api/v1/packages und vom admin agent_software endpoint
    benutzt um installed_version / available_version pro choco-Paket
    deterministisch zu zeigen."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT choco_name, installed_version, available_version, scanned_at "
            "FROM agent_choco_state WHERE agent_id = ?",
            (agent_id,),
        ) as cur:
            return {r["choco_name"]: dict(r) for r in await cur.fetchall()}


async def cleanup_choco_state_for_package(package_name: str):
    """Bei Disable eines choco-Pakets — analog zu winget. State bleibt sonst
    im DB liegen und kommt beim nächsten Scan wieder."""
    async with _db() as db:
        await db.execute(
            "DELETE FROM agent_choco_state WHERE choco_name = ?", (package_name,)
        )
        await db.commit()


async def get_agents_with_winget_package(winget_id: str) -> list[dict]:
    """Alle Agents die ein bestimmtes winget-Paket installiert haben, inkl.
    Version + last_seen. Für die Paket-Detail-Sicht im Admin-UI."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT a.agent_id, a.hostname, a.last_seen, "
            "       s.installed_version, s.available_version, s.scanned_at "
            "FROM agent_winget_state s "
            "JOIN agents a ON a.agent_id = s.agent_id "
            "WHERE s.winget_id = ? "
            "ORDER BY a.hostname",
            (winget_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_agents_with_choco_package(choco_name: str) -> list[dict]:
    """Alle Agents die ein bestimmtes choco-Paket installiert haben, inkl.
    Version + last_seen."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT a.agent_id, a.hostname, a.last_seen, "
            "       s.installed_version, s.available_version, s.scanned_at "
            "FROM agent_choco_state s "
            "JOIN agents a ON a.agent_id = s.agent_id "
            "WHERE s.choco_name = ? "
            "ORDER BY a.hostname",
            (choco_name,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


# ── Profile ────────────────────────────────────────────────────────────────────

async def list_profiles() -> list[dict]:
    """Alle Profile mit Paket-Count und Agent-Count fuer die Liste im Admin-UI."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT p.id, p.name, p.description, p.color, "
            "       p.auto_update, p.auto_update_at, "
            "       p.created_at, p.updated_at, "
            "       (SELECT COUNT(*) FROM profile_packages WHERE profile_id = p.id) AS package_count, "
            "       (SELECT COUNT(*) FROM agent_profiles  WHERE profile_id = p.id) AS agent_count "
            "FROM profiles p "
            "ORDER BY p.name COLLATE NOCASE"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_profile(profile_id: int) -> dict | None:
    """Detail eines Profils inkl. der zugewiesenen Pakete (in sort_order)."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, name, description, color, auto_update, auto_update_at, "
            "       created_at, updated_at "
            "FROM profiles WHERE id = ?",
            (profile_id,),
        ) as cur:
            row = await cur.fetchone()
            if not row:
                return None
            profile = dict(row)
        async with db.execute(
            "SELECT pp.package_name, pp.version_pin, pp.sort_order, "
            "       p.display_name, p.type, p.category "
            "FROM profile_packages pp "
            "JOIN packages p ON p.name = pp.package_name "
            "WHERE pp.profile_id = ? "
            "ORDER BY pp.sort_order, pp.package_name",
            (profile_id,),
        ) as cur:
            profile["packages"] = [dict(r) for r in await cur.fetchall()]
        return profile


async def get_profile_by_name(name: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id FROM profiles WHERE name = ? COLLATE NOCASE", (name,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def create_profile(
    name: str,
    description: str,
    color: str | None = None,
    auto_update: bool = False,
) -> int:
    """Legt ein neues Profil an. Wirft IntegrityError wenn der Name schon existiert."""
    async with _db() as db:
        cur = await db.execute(
            "INSERT INTO profiles (name, description, color, auto_update) "
            "VALUES (?, ?, ?, ?)",
            (name, description or "", color, 1 if auto_update else 0),
        )
        await db.commit()
        return cur.lastrowid


async def update_profile_meta(
    profile_id: int,
    name: str | None = None,
    description: str | None = None,
    color: str | None = None,
    auto_update: bool | None = None,
):
    """Aktualisiert nur die Meta-Felder, NICHT die Pakete (das macht set_profile_packages)."""
    fields, params = [], []
    if name is not None:
        fields.append("name = ?"); params.append(name)
    if description is not None:
        fields.append("description = ?"); params.append(description)
    if color is not None:
        fields.append("color = ?"); params.append(color)
    if auto_update is not None:
        fields.append("auto_update = ?"); params.append(1 if auto_update else 0)
    if not fields:
        return
    fields.append("updated_at = datetime('now')")
    params.append(profile_id)
    async with _db() as db:
        await db.execute(
            f"UPDATE profiles SET {', '.join(fields)} WHERE id = ?",
            params,
        )
        await db.commit()


async def list_auto_update_profiles() -> list[dict]:
    """Alle Profile mit auto_update=1, fuer den nightly Job."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, name FROM profiles WHERE auto_update = 1 ORDER BY id"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def mark_profile_auto_update_run(profile_id: int):
    """Setzt auto_update_at = jetzt — wird vom Auto-Update-Job nach jedem Lauf
    pro Profil gesetzt damit die UI „letzter Lauf vor X Stunden" anzeigen kann."""
    async with _db() as db:
        await db.execute(
            "UPDATE profiles SET auto_update_at = datetime('now') WHERE id = ?",
            (profile_id,),
        )
        await db.commit()


async def delete_profile(profile_id: int):
    """Loescht das Profil. Cascades auf profile_packages und agent_profiles —
    aber NICHT auf installierte Pakete (das waere destruktiv)."""
    async with _db() as db:
        await db.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
        await db.commit()


async def set_profile_packages(
    profile_id: int,
    packages: list[dict],
) -> tuple[set[str], set[str]]:
    """Setzt die Paket-Liste eines Profils auf den uebergebenen Stand.

    Eingabe: list of {package_name, version_pin?, sort_order?}.
    Returns (added, removed) mit den Paketnamen die neu hinzugekommen bzw.
    rausgeflogen sind — fuer Auto-Propagation und Audit-Logging.
    """
    async with _db() as db:
        async with db.execute(
            "SELECT package_name FROM profile_packages WHERE profile_id = ?",
            (profile_id,),
        ) as cur:
            old = {r[0] for r in await cur.fetchall()}

        new = {p["package_name"] for p in packages}
        added = new - old
        removed = old - new

        await db.execute("DELETE FROM profile_packages WHERE profile_id = ?", (profile_id,))
        for idx, pkg in enumerate(packages):
            await db.execute(
                "INSERT INTO profile_packages (profile_id, package_name, version_pin, sort_order) "
                "VALUES (?, ?, ?, ?)",
                (profile_id, pkg["package_name"], pkg.get("version_pin"),
                 pkg.get("sort_order", idx)),
            )
        await db.execute(
            "UPDATE profiles SET updated_at = datetime('now') WHERE id = ?",
            (profile_id,),
        )
        await db.commit()
        return added, removed


async def list_agent_profiles(agent_id: str) -> list[dict]:
    """Alle Profile die einem Agent zugewiesen sind (mit Profil-Namen)."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT p.id, p.name, p.description, p.color, ap.assigned_at, ap.assigned_by "
            "FROM agent_profiles ap "
            "JOIN profiles p ON p.id = ap.profile_id "
            "WHERE ap.agent_id = ? "
            "ORDER BY p.name COLLATE NOCASE",
            (agent_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_agents_for_profile(profile_id: int) -> list[dict]:
    """Alle Agents die ein bestimmtes Profil zugewiesen haben."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT a.agent_id, a.hostname, a.last_seen, a.ring, ap.assigned_at "
            "FROM agent_profiles ap "
            "JOIN agents a ON a.agent_id = ap.agent_id "
            "WHERE ap.profile_id = ? "
            "ORDER BY a.hostname",
            (profile_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def assign_profile_to_agent(agent_id: str, profile_id: int, assigned_by: str | None = None) -> bool:
    """Returns True wenn neu zugewiesen, False wenn schon assigned (idempotent)."""
    async with _db() as db:
        try:
            await db.execute(
                "INSERT INTO agent_profiles (agent_id, profile_id, assigned_by) VALUES (?, ?, ?)",
                (agent_id, profile_id, assigned_by),
            )
            await db.commit()
            return True
        except Exception:
            return False


async def unassign_profile_from_agent(agent_id: str, profile_id: int) -> bool:
    async with _db() as db:
        cur = await db.execute(
            "DELETE FROM agent_profiles WHERE agent_id = ? AND profile_id = ?",
            (agent_id, profile_id),
        )
        await db.commit()
        return cur.rowcount > 0


async def get_packages_in_profile(profile_id: int) -> list[dict]:
    """Nur die Paket-Liste eines Profils (ohne Profil-Meta) — fuer Apply-Pfad."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT pp.package_name, pp.version_pin, pp.sort_order "
            "FROM profile_packages "
            "AS pp WHERE pp.profile_id = ? "
            "ORDER BY pp.sort_order, pp.package_name",
            (profile_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_profile_names_for_package(package_name: str) -> list[str]:
    """Welche Profile referenzieren ein bestimmtes Paket — fuer die
    'in Profilen' Spalte in der Pakete-Liste."""
    async with _db() as db:
        async with db.execute(
            "SELECT p.name FROM profile_packages pp "
            "JOIN profiles p ON p.id = pp.profile_id "
            "WHERE pp.package_name = ? "
            "ORDER BY p.name COLLATE NOCASE",
            (package_name,),
        ) as cur:
            return [r[0] for r in await cur.fetchall()]


# ── Event Log (typed business events, nicht HTTP-Audit) ───────────────────────

async def log_audit_event(event_type: str, actor: str | None = None,
                          details: dict | None = None):
    """Schreibt einen typisierten Business-Event ins event_log.

    Verwendet fuer Profile-Aktionen, Bulk-Operationen und andere
    Admin-getriggerte Vorgaenge die nicht im HTTP-Audit-Log auftauchen.
    """
    import json as _json
    detail_json = _json.dumps(details, ensure_ascii=False) if details else None
    async with _db() as db:
        await db.execute(
            "INSERT INTO event_log (event_type, actor, details) VALUES (?, ?, ?)",
            (event_type, actor, detail_json),
        )
        await db.commit()


async def get_event_log(
    limit: int = 200,
    event_type_prefix: str | None = None,
) -> list[dict]:
    """Liefert die letzten N typisierten Events. Optional gefiltert nach
    event_type-Prefix (z.B. 'profile_' fuer alle Profile-Events)."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        if event_type_prefix:
            query = (
                "SELECT id, ts, event_type, actor, details FROM event_log "
                "WHERE event_type LIKE ? ORDER BY id DESC LIMIT ?"
            )
            params = (event_type_prefix + "%", limit)
        else:
            query = (
                "SELECT id, ts, event_type, actor, details FROM event_log "
                "ORDER BY id DESC LIMIT ?"
            )
            params = (limit,)
        async with db.execute(query, params) as cur:
            rows = []
            for r in await cur.fetchall():
                row = dict(r)
                # JSON detail-string optional zurueck-parsen
                if row.get("details"):
                    try:
                        import json as _json
                        row["details"] = _json.loads(row["details"])
                    except Exception:
                        pass
                rows.append(row)
            return rows


# ── action_log ──────────────────────────────────────────────

async def create_action_log(
    agent_id: str, hostname: str, package_name: str,
    display_name: str, pkg_type: str, action: str,
    job_id: str | None = None, metadata: str | None = None,
    workflow_run_id: int | None = None,
) -> int:
    """INSERT pending action, returns id. Dual-write in install_log."""
    async with _db() as db:
        cur = await db.execute(
            "INSERT INTO action_log "
            "(agent_id, hostname, package_name, display_name, pkg_type, action, "
            " job_id, metadata, workflow_run_id) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (agent_id, hostname, package_name, display_name, pkg_type, action,
             job_id, metadata, workflow_run_id),
        )
        log_id = cur.lastrowid
        await db.execute(
            "INSERT INTO install_log (agent_id, hostname, package_name, display_name, action) "
            "VALUES (?,?,?,?,?)",
            (agent_id, hostname, package_name, display_name,
             action if action in ("install", "uninstall") else "install"),
        )
        await db.commit()
        return log_id


async def update_action_log_status(log_id: int, status: str):
    async with _db() as db:
        await db.execute(
            "UPDATE action_log SET status = ? WHERE id = ?", (status, log_id)
        )
        await db.commit()


async def complete_action_log(
    log_id: int, status: str, exit_code: int | None = None,
    error_summary: str | None = None, stdout: str | None = None,
):
    async with _db() as db:
        await db.execute(
            "UPDATE action_log SET status = ?, exit_code = ?, error_summary = ?, "
            "stdout = ?, completed_at = datetime('now') WHERE id = ?",
            (status, exit_code, error_summary, stdout, log_id),
        )
        await db.commit()


async def get_action_log(
    agent_id: str | None = None, package_name: str | None = None,
    status: str | None = None, pkg_type: str | None = None,
    limit: int = 50, offset: int = 0,
) -> list[dict]:
    """Filterbarer Query OHNE stdout (nur in Detail-Endpoint)."""
    clauses: list[str] = []
    params: list = []
    if agent_id:
        clauses.append("agent_id = ?"); params.append(agent_id)
    if package_name:
        clauses.append("package_name = ?"); params.append(package_name)
    if status:
        clauses.append("status = ?"); params.append(status)
    if pkg_type:
        clauses.append("pkg_type = ?"); params.append(pkg_type)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT id, agent_id, hostname, package_name, display_name, "
            f"pkg_type, action, status, exit_code, error_summary, "
            f"created_at, completed_at "
            f"FROM action_log {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params,
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_action_log_detail(log_id: int) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM action_log WHERE id = ?", (log_id,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def update_action_log_output(log_id: int, stdout: str):
    """Inkrementelles stdout-Update ohne Statusaenderung (fuer Progress-Callbacks)."""
    async with _db() as db:
        await db.execute(
            "UPDATE action_log SET stdout = ? WHERE id = ? AND status IN ('pending', 'running')",
            (stdout, log_id),
        )
        await db.commit()


async def get_action_log_by_job_id(job_id: str) -> dict | None:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM action_log WHERE job_id = ?", (job_id,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_agent_error_counts(since_hours: int = 24) -> dict:
    """Returns {agent_id: error_count} fuer Agents mit Fehlern."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT agent_id, COUNT(*) as cnt FROM action_log "
            "WHERE status = 'error' AND created_at > datetime('now', ? || ' hours') "
            "GROUP BY agent_id",
            (f"-{since_hours}",),
        ) as cur:
            return {r["agent_id"]: r["cnt"] for r in await cur.fetchall()}


async def get_package_failed_counts() -> dict:
    """Returns {package_name: count} — Agents wo letzte Aktion error war."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT package_name, COUNT(DISTINCT agent_id) as cnt FROM action_log "
            "WHERE status = 'error' "
            "AND id IN ("
            "  SELECT MAX(id) FROM action_log "
            "  GROUP BY agent_id, package_name"
            ") GROUP BY package_name",
        ) as cur:
            return {r["package_name"]: r["cnt"] for r in await cur.fetchall()}


async def cleanup_action_logs(days: int = 30) -> int:
    async with _db() as db:
        cur = await db.execute(
            "DELETE FROM action_log WHERE created_at < datetime('now', ? || ' days')",
            (f"-{days}",),
        )
        await db.commit()
        return cur.rowcount


# ── Workflows ─────────────────────────────────────────────────────────────────


async def get_workflows() -> list[dict]:
    """Alle Workflows, alphabetisch sortiert."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, name, description, steps, created_at, updated_at "
            "FROM workflows ORDER BY name COLLATE NOCASE"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_workflow(workflow_id: int) -> dict | None:
    """Einzelner Workflow per ID."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, name, description, steps, created_at, updated_at "
            "FROM workflows WHERE id = ?",
            (workflow_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def create_workflow(name: str, description: str, steps: str) -> int:
    """Neuen Workflow anlegen. `steps` ist ein JSON-String (Liste von Step-Objekten).
    Wirft IntegrityError bei doppeltem Name. Gibt die neue ID zurueck."""
    async with _db() as db:
        cur = await db.execute(
            "INSERT INTO workflows (name, description, steps) VALUES (?, ?, ?)",
            (name, description or "", steps or "[]"),
        )
        await db.commit()
        return cur.lastrowid


async def update_workflow(
    workflow_id: int, name: str, description: str, steps: str
):
    """Workflow-Metadaten + Steps aktualisieren. updated_at wird gesetzt."""
    async with _db() as db:
        await db.execute(
            "UPDATE workflows "
            "SET name = ?, description = ?, steps = ?, updated_at = datetime('now') "
            "WHERE id = ?",
            (name, description or "", steps or "[]", workflow_id),
        )
        await db.commit()


async def delete_workflow(workflow_id: int):
    """Loescht einen Workflow inkl. agent_workflows und abgeschlossener Runs.
    Wirft ValueError wenn noch aktive (pending/running) Runs vorhanden sind."""
    async with _db() as db:
        async with db.execute(
            "SELECT COUNT(*) FROM workflow_runs "
            "WHERE workflow_id = ? AND status IN ('pending', 'running')",
            (workflow_id,),
        ) as cur:
            active = (await cur.fetchone())[0]
        if active:
            raise ValueError(
                f"Workflow hat noch {active} aktive Run(s) — erst abbrechen."
            )
        # workflow_runs FK auf workflows — explizit loeschen (kein ON DELETE CASCADE
        # in der DDL, SQLite erlaubt kein nachtraegliches ALTER FOREIGN KEY).
        # action_log.workflow_run_id wird auf NULL gesetzt damit die Logs erhalten bleiben.
        await db.execute(
            "UPDATE action_log SET workflow_run_id = NULL "
            "WHERE workflow_run_id IN ("
            "  SELECT id FROM workflow_runs WHERE workflow_id = ?"
            ")",
            (workflow_id,),
        )
        await db.execute(
            "DELETE FROM workflow_runs WHERE workflow_id = ?", (workflow_id,)
        )
        await db.execute(
            "DELETE FROM agent_workflows WHERE workflow_id = ?", (workflow_id,)
        )
        await db.execute("DELETE FROM workflows WHERE id = ?", (workflow_id,))
        await db.commit()


# ── Workflow Assignments ──────────────────────────────────────────────────────


async def assign_workflow_to_agent(
    agent_id: str, workflow_id: int, assigned_by: str | None = None
) -> bool:
    """Weist einem Agent einen Workflow zu (idempotent).
    Gibt True zurueck wenn neu angelegt, False wenn schon vorhanden."""
    async with _db() as db:
        try:
            await db.execute(
                "INSERT INTO agent_workflows (agent_id, workflow_id, assigned_by) "
                "VALUES (?, ?, ?)",
                (agent_id, workflow_id, assigned_by),
            )
            await db.commit()
            return True
        except Exception:
            return False


async def unassign_workflow_from_agent(agent_id: str, workflow_id: int) -> bool:
    """Entfernt Workflow-Zuweisung fuer einen Agent. True wenn vorhanden war."""
    async with _db() as db:
        cur = await db.execute(
            "DELETE FROM agent_workflows WHERE agent_id = ? AND workflow_id = ?",
            (agent_id, workflow_id),
        )
        await db.commit()
        return cur.rowcount > 0


async def list_agent_workflows(agent_id: str) -> list[dict]:
    """Alle Workflows die einem Agent zugewiesen sind (mit Workflow-Meta)."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT w.id, w.name, w.description, w.steps, "
            "       aw.assigned_at, aw.assigned_by "
            "FROM agent_workflows aw "
            "JOIN workflows w ON w.id = aw.workflow_id "
            "WHERE aw.agent_id = ? "
            "ORDER BY w.name COLLATE NOCASE",
            (agent_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_agents_for_workflow(workflow_id: int) -> list[dict]:
    """Alle Agents denen ein bestimmter Workflow zugewiesen ist."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT a.agent_id, a.hostname, a.last_seen, aw.assigned_at "
            "FROM agent_workflows aw "
            "JOIN agents a ON a.agent_id = aw.agent_id "
            "WHERE aw.workflow_id = ? "
            "ORDER BY a.hostname",
            (workflow_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


# ── Workflow Runs ──────────────────────────────────────────────────────────────


async def create_workflow_run(
    workflow_id: int, agent_id: str, hostname: str, step_snapshot: str
) -> int:
    """Neuen Workflow-Run anlegen. Status=running, started_at=now.
    `step_snapshot` ist ein JSON-String (Kopie der Steps zum Zeitpunkt des Starts).
    Gibt die neue Run-ID zurueck."""
    async with _db() as db:
        cur = await db.execute(
            "INSERT INTO workflow_runs "
            "(workflow_id, agent_id, hostname, step_snapshot, "
            " current_step, status, started_at) "
            "VALUES (?, ?, ?, ?, 0, 'running', datetime('now'))",
            (workflow_id, agent_id, hostname, step_snapshot),
        )
        await db.commit()
        return cur.lastrowid


async def get_workflow_run(run_id: int) -> dict | None:
    """Einzelner Workflow-Run per ID."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, workflow_id, agent_id, hostname, step_snapshot, "
            "       current_step, status, step_state, step_deadline_at, "
            "       started_at, updated_at "
            "FROM workflow_runs WHERE id = ?",
            (run_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_active_run_for_agent(agent_id: str) -> dict | None:
    """Aktiver (pending oder running) Workflow-Run fuer einen Agent.
    Pro Agent darf es laut UNIQUE-Index nur einen geben."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, workflow_id, agent_id, hostname, step_snapshot, "
            "       current_step, status, step_state, step_deadline_at, "
            "       started_at, updated_at "
            "FROM workflow_runs "
            "WHERE agent_id = ? AND status IN ('pending', 'running')",
            (agent_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def update_workflow_run(run_id: int, **kwargs):
    """Flexibles Update fuer workflow_runs. updated_at wird immer gesetzt.

    Unterstuetzte kwargs: status, current_step, step_state, step_deadline_at,
    started_at. Der spezielle Sentinel-String 'SQL:datetime(now)' wird als
    nackter SQL-Ausdruck eingefuegt statt als gebundener Parameter."""
    if not kwargs:
        return
    _ALLOWED = {"status", "current_step", "step_state", "step_deadline_at", "started_at"}
    for key in kwargs:
        if key not in _ALLOWED:
            raise ValueError(f"update_workflow_run: unerlaubter Key {key!r}")
    fields: list[str] = []
    params: list = []
    # Spezielle SQL-Ausdruecke die nicht als Parameter gebunden werden sollen
    _SQL_EXPRS = {"datetime('now')"}
    for key, val in kwargs.items():
        if isinstance(val, str) and val in _SQL_EXPRS:
            fields.append(f"{key} = {val}")
        else:
            fields.append(f"{key} = ?")
            params.append(val)
    fields.append("updated_at = datetime('now')")
    params.append(run_id)
    async with _db() as db:
        await db.execute(
            f"UPDATE workflow_runs SET {', '.join(fields)} WHERE id = ?",
            params,
        )
        await db.commit()


async def get_workflow_runs_for_agent(
    agent_id: str, limit: int = 20
) -> list[dict]:
    """Letzte Workflow-Runs eines Agents, neueste zuerst, mit Workflow-Name."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT r.id, r.workflow_id, r.agent_id, r.hostname, "
            "       r.current_step, r.status, r.step_state, r.step_snapshot, "
            "       r.step_deadline_at, r.started_at, r.updated_at, "
            "       w.name AS workflow_name "
            "FROM workflow_runs r "
            "JOIN workflows w ON w.id = r.workflow_id "
            "WHERE r.agent_id = ? "
            "ORDER BY r.id DESC LIMIT ?",
            (agent_id, limit),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_overdue_workflow_runs() -> list[dict]:
    """Laufende Runs deren step_deadline_at in der Vergangenheit liegt.
    Wird vom Scheduler-Job fuer Timeout-Handling aufgerufen."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, workflow_id, agent_id, hostname, "
            "       current_step, status, step_state, step_deadline_at, "
            "       started_at, updated_at "
            "FROM workflow_runs "
            "WHERE status = 'running' "
            "  AND step_deadline_at IS NOT NULL "
            "  AND step_deadline_at < datetime('now')"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_running_workflow_runs() -> list[dict]:
    """Alle aktuell laufenden Workflow-Runs (status=running)."""
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT r.id, r.workflow_id, r.agent_id, r.hostname, "
            "       r.current_step, r.status, r.step_state, "
            "       r.step_deadline_at, r.started_at, r.updated_at, "
            "       w.name AS workflow_name "
            "FROM workflow_runs r "
            "JOIN workflows w ON w.id = r.workflow_id "
            "WHERE r.status = 'running' "
            "ORDER BY r.started_at"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_pending_actions_for_agent(agent_id: str) -> list[dict]:
    """Liefert Reboot-Pending-Aktionen fuer einen Agent — aus dem aktuell
    laufenden Workflow-Run.

    Gibt eine Liste von Action-Dicts zurueck. Jedes Dict hat mindestens:
      {type, message, countdown, can_defer}

    Aktuell werden nur Schritte vom Typ 'reboot' ausgewertet, bei denen
    der Run auf diesen Schritt wartet (current_step zeigt auf einen
    reboot-Step der noch nicht abgeschlossen ist)."""
    run = await get_active_run_for_agent(agent_id)
    if not run or run["status"] != "running":
        return []

    try:
        steps = json.loads(run["step_snapshot"] or "[]")
    except Exception:
        return []

    step_idx = run.get("current_step", 0)
    if step_idx < 0 or step_idx >= len(steps):
        return []

    current = steps[step_idx]
    if current.get("type") != "reboot":
        return []

    try:
        state = json.loads(run.get("step_state") or "{}")
    except Exception:
        state = {}

    # Nicht anzeigen wenn Reboot schon getriggert wurde
    if state.get("reboot_triggered"):
        return []

    # Nicht anzeigen wenn noch im Verschieben-Zeitfenster
    deferred_until = state.get("deferred_until")
    if deferred_until:
        from datetime import datetime, timezone
        try:
            dt = datetime.fromisoformat(deferred_until.replace(" ", "T"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt > datetime.now(timezone.utc):
                return []
        except Exception:
            pass

    payload = current.get("payload", {})
    max_deferrals = int(payload.get("max_deferrals", 3))
    deferrals = int(state.get("deferrals", 0))

    action = {
        "type": "reboot",
        "message": payload.get("message", "Ein Neustart ist erforderlich."),
        "countdown": int(payload.get("countdown", 300)),
        "can_defer": deferrals < max_deferrals,
        "run_id": run["id"],
        "step": step_idx,
    }
    return [action]
