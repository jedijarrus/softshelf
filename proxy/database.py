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

            CREATE INDEX IF NOT EXISTS idx_install_log_agent  ON install_log(agent_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_agent_winget_id    ON agent_winget_state(winget_id);
            CREATE INDEX IF NOT EXISTS idx_agent_winget_avail ON agent_winget_state(available_version) WHERE available_version IS NOT NULL;
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
            ("winget_publisher",   "TEXT"),
        ]:
            if col not in pkg_cols:
                await db.execute(f"ALTER TABLE packages ADD COLUMN {col} {ddl}")

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
    """Löscht audit_log und install_log Einträge älter als N Tage."""
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
        await db.commit()


# ── Packages ──────────────────────────────────────────────────────────────────

_PKG_COLS = (
    "name, display_name, category, type, filename, sha256, size_bytes, "
    "install_args, uninstall_cmd, detection_name, current_version_id, "
    "archive_type, entry_point, winget_version, winget_publisher"
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
            "(b.agent_id IS NOT NULL) AS banned "
            "FROM agents a "
            "LEFT JOIN agent_blocklist b ON b.agent_id = a.agent_id "
            "ORDER BY a.hostname"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


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
            "SELECT agent_id, hostname, registered_at, last_seen, token_version "
            "FROM agents WHERE agent_id = ?",
            (agent_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


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
    "sso_subject, is_active, created_at, last_login"
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
) -> int:
    async with _db() as db:
        cur = await db.execute(
            "INSERT INTO admin_users (username, display_name, email, password_hash, "
            "sso_provider, sso_subject, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, display_name, email, password_hash, sso_provider, sso_subject,
             1 if is_active else 0),
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
            "u.username, u.display_name, u.email, u.is_active, u.sso_provider "
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
    winget_version: str | None = None,
):
    """Winget-Paket einfügen oder aktualisieren. `name` ist die winget
    PackageIdentifier (z. B. 'Mozilla.Firefox')."""
    async with _db() as db:
        await db.execute(
            """
            INSERT INTO packages (
                name, display_name, category, type,
                winget_publisher, winget_version
            )
            VALUES (?, ?, ?, 'winget', ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                display_name     = excluded.display_name,
                category         = excluded.category,
                type             = 'winget',
                winget_publisher = excluded.winget_publisher,
                winget_version   = excluded.winget_version,
                updated_at       = datetime('now')
            """,
            (name, display_name, category, publisher, winget_version),
        )
        await db.commit()


async def update_winget_package(
    name: str,
    display_name: str,
    category: str,
    winget_version: str | None,
):
    async with _db() as db:
        await db.execute(
            """
            UPDATE packages
            SET display_name = ?, category = ?, winget_version = ?,
                updated_at = datetime('now')
            WHERE name = ? AND type = 'winget'
            """,
            (display_name, category, winget_version, name),
        )
        await db.commit()


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
):
    """Schreibt das Ergebnis einer User- oder Admin-Aktion (Install/Upgrade/
    Uninstall) in agent_scan_meta. error=None bedeutet Aktion erfolgreich,
    bei Erfolg wird last_action_error gelöscht. Aufgerufen vom
    _run_winget_command_bg in routes/install.py."""
    async with _db() as db:
        await db.execute(
            "INSERT INTO agent_scan_meta "
            "(agent_id, last_action_at, last_action_package, last_action_error) "
            "VALUES (?, datetime('now'), ?, ?) "
            "ON CONFLICT(agent_id) DO UPDATE SET "
            "last_action_at = datetime('now'), "
            "last_action_package = excluded.last_action_package, "
            "last_action_error = excluded.last_action_error",
            (agent_id, package_name, error),
        )
        await db.commit()


async def get_all_scan_meta() -> list[dict]:
    async with _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT agent_id, last_scan_at, last_status, last_error, consecutive_failures "
            "FROM agent_scan_meta"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


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
