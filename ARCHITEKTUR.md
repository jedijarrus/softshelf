# Softshelf – Systemarchitektur

**Version:** 1.3.1

> Dieses Dokument beschreibt die technische Architektur von Softshelf — das
> Datenbankschema, den Datenfluss, die Security-Garantien und den Deployment-
> Prozess. Für einen Schnellstart siehe `README.md`.

## Feature-Stand

Seit v1.2 dazugekommen:
- **Versionierung** pro custom-Paket inkl. Agent-Installations-Tracking +
  Push-Update (v1.3.0)
- **Programm-Ordner-Upload** (multi-file → server-side ZIP) mit Entry-Point-
  Auswahl + „Inhalt verwalten" (add/remove files → neue Version) (v1.3.0)
- **Verteilung-Tab** mit per-Agent Update/Entfernen-Aktionen
- **Storage-Indicator** (freier Plattenplatz) im Upload-Panel und Verteilung-Tab
- **Kiosk-Tray Health-Monitor** — periodischer Health-Check mit Offline-
  Notification und rotem Icon
- **„Update verfügbar"-Badge + Updaten-Button** im Kiosk-Client pro custom-Paket
- **Agent-Lifecycle im Admin-UI**: Token widerrufen / Löschen / Sperren +
  Unban + `agent_blocklist`-Tabelle (v1.3.1)
- **Security-Review-Fixes** (CRIT+HIGH+MEDIUM): build.sh injection, PRAGMA
  foreign_keys, delete_version TOCTOU, XSS-Refactor via `jsStr()`,
  SSO email_verified, Session-Secure-Flag, Rate-Limit X-Forwarded-For,
  Field-Validators, Exception-Leaks, shutil.disk_usage etc.

## Überblick

Das Softshelf ist ein Self-Service-Softwareportal für verwaltete
Windows-PCs. End-User können über ein Tray-Icon freigegebene Software installieren
und deinstallieren – ohne Admin-Rechte, ohne direkte Tactical-RMM-Verbindung, und
**ohne** dass der IT-Admin für jedes neue Paket einen Ticket-Vorgang durchlaufen muss.

Das System besteht aus **drei** deploybaren Komponenten in einer docker-compose-
Orchestrierung plus den kompilierten Windows-Client-Binaries:

```
┌────────────────────────────────────────────────────────────────────┐
│  docker-compose.yml (auf jedem Linux-Host deploybar)               │
│                                                                    │
│  ┌──────────────┐     HTTP      ┌─────────────────────────┐        │
│  │ softshelf-proxy  │──────────────▶│ softshelf-builder           │        │
│  │ FastAPI+SQL  │   (internal)  │ Ubuntu+Wine+PyInstaller │        │
│  │ :8765        │               │ :8766 (internal only)   │        │
│  └──────┬───────┘               └───────────┬─────────────┘        │
│         │                                   │                      │
│         └───────┐        ┌──────────────────┘                      │
│                 ▼        ▼                                          │
│            ┌────────────────────┐                                   │
│            │ downloads volume   │  ← shared zwischen proxy+builder  │
│            │ softshelf-setup.exe    │                                   │
│            │ softshelf.exe          │                                   │
│            └────────────────────┘                                   │
└────────────────────────────────────────────────────────────────────┘
                │                                   │
          HTTP + JWT Bearer                   HTTPS + API-Key
                │                                   │
                ▼                                   ▼
     ┌──────────────────┐                  ┌──────────────────┐
     │  softshelf.exe       │                  │  Tactical RMM    │
     │  Windows PCs     │                  │  (extern, Cloud) │
     │  (Endnutzer)     │                  └──────────────────┘
     └──────────────────┘
```

Der **Kiosk-Proxy** ist das Hirn des Systems: er pflegt die kuratierte Paket-Whitelist,
authentifiziert Clients, leitet Install-Aufträge an Tactical weiter, hostet Custom-
Dateien und stellt die Admin-Web-UI bereit.

Der **Kiosk-Builder** ist ein optionaler Cross-Compile-Container, der Windows-EXEs
aus der eingebetteten Client-Source-Base baut, mit der aktuellen Proxy-URL eingebacken.
Wird nur getriggert wenn der Admin im UI "EXEs bauen" klickt, läuft sonst idle.

---

## Konfigurations-Schichten

Das System hat **bewusst zwei Konfigurations-Ebenen**, die unterschiedliche Volatilität
und Änderungsprozeduren erlauben:

### 1. Bootstrap-Konfiguration (`.env`)

Minimal, statisch nach dem ersten Deploy. Enthält nur was nötig ist um den Proxy
überhaupt hochfahren zu können:

```
SECRET_KEY=<64 hex chars>        # Crypto-Wurzel, NIEMALS ändern
ADMIN_USERNAME=admin             # Bootstrap-Admin für erstes Login
ADMIN_PASSWORD=<min 8 Zeichen>   # Bootstrap-Passwort (später im UI überschreibbar)

# Optional: Initial-Seeds für die Runtime-Settings beim ersten Start
INITIAL_TACTICAL_URL=...
INITIAL_TACTICAL_API_KEY=...
INITIAL_REGISTRATION_SECRET=...
INITIAL_PROXY_PUBLIC_URL=...
```

Wird einmalig per `cp .env.example .env && $EDITOR .env` gesetzt. Nach Deploy unverändert.

### 2. Runtime-Konfiguration (SQLite `settings`-Tabelle)

Alles andere. Im Admin-UI unter **Einstellungen** editierbar, Änderungen greifen
**sofort** ohne Container-Restart. Jeder Request zieht seine Werte frisch aus der DB.

| Key | Typ | Default | Zweck |
|---|---|---|---|
| `tactical_url` | URL | – | Basis-URL der Tactical-RMM-API |
| `tactical_api_key` | Secret | – | API-Key des TRMM-Users |
| `registration_secret` | Secret | – | Shared Secret für Client-Deployment |
| `proxy_public_url` | URL | – | Externe Proxy-URL, wird in softshelf-setup.exe eingebacken |
| `token_ttl_days` | int | 365 | Machine-Token-Ablauf (0 = unbegrenzt) |
| `log_retention_days` | int | 90 | Audit/Install-Log-Bereinigung |
| `max_upload_mb` | int | 500 | Größenlimit für custom MSI/EXE Uploads |
| `admin_password_override` | Secret | – | Überschreibt Bootstrap-Admin-Passwort aus .env |
| `client_app_name` | String | `Softshelf` | UI-Titel im Kiosk-Client |

Secrets werden timing-safe verglichen (`secrets.compare_digest`), im UI maskiert
mit einem separaten Reveal-Endpoint für Klartext-Ansicht on demand.

### Migration aus alter `.env`-Struktur

Beim ersten Start nach einem Upgrade liest das Seeding auch die alten Keys ohne
`INITIAL_`-Prefix (`TACTICAL_URL`, `TACTICAL_API_KEY`, `REGISTRATION_SECRET`,
`PROXY_PUBLIC_URL`). Bestehende Deployments upgraden ohne manuellen .env-Edit.

---

## Komponenten

### Proxy-Container (`softshelf-proxy`)

**Image-Basis:** `python:3.11-slim`
**Wichtige apt-Pakete:** `gosu`, `msitools`
**Runtime-User:** `softshelf` (UID 1001) via `entrypoint.sh` + gosu-Drop
**Port:** 8765 (extern exposed)
**Volumes:**
- `./data:/app/data` — SQLite-DB, Uploads
- `./downloads:/app/downloads` — Build-Artefakte (shared mit Builder)

**Framework:** FastAPI + aiosqlite

**Middleware-Pipeline** (von außen nach innen):
1. **Audit-Logger** — fire-and-forget DB-Write via `asyncio.create_task`, blockt nicht den Request
2. **Rate-Limit** — In-Memory Per-IP, 5/min auf `/api/v1/register`, 60/min auf `/admin*`
3. **CSRF** — POST/PUT/PATCH/DELETE auf `/admin/api/*` erfordern Origin-Match ODER `X-Requested-With: XMLHttpRequest`

**Module:**

| Datei | Aufgabe |
|---|---|
| `main.py` | FastAPI-App, Lifespan (Settings-Seeding, Log-Cleanup, Session-Cleanup), public endpoints (health, client-config, downloads, file-download mit signed token) |
| `config.py` | `BootstrapSettings` (pydantic, .env) + `RUNTIME_KEYS`-Dict (inkl. SSO-Settings) + `runtime_value()`/`runtime_int()`/`validate_runtime_value()` |
| `database.py` | aiosqlite-Wrapper, Migration (ALTER TABLE + automatische `_migrate_custom_packages_to_versions`), alle Queries inkl. Versions/Installations-Helper |
| `auth.py` | JWT-Erzeugung (`create_machine_token`), Verify (`verify_machine_token`), Download-Token (`create_download_token`/`verify_download_token`) |
| `admin_auth.py` | Admin-Login-Logik: scrypt-Hashing, Session-Cookies, Bootstrap-Admin-Migration, Microsoft-Entra-OIDC-Flow (state cache + JWKS-Validierung) |
| `tactical_client.py` | Tactical-RMM-API-Wrapper, liest URL+API-Key bei jedem Call aus Runtime-Settings |
| `file_uploads.py` | Multipart-Upload-Streaming, SHA-256-Hashing, MSI-Metadaten via `msiinfo` (msitools) |
| `middleware/audit_logger.py` | HTTP-Request-Logging (fire-and-forget) |
| `middleware/csrf.py` | CSRF-Check auf state-changing Admin-Calls |
| `middleware/rate_limit.py` | In-Memory Rate-Limiter |
| `routes/register.py` | `POST /api/v1/register` mit Agent-ID + Hostname-Validierung + Token-Version-Bump |
| `routes/packages.py` | `GET /api/v1/packages` mit Installations-Detection via Tactical-Software-Scan |
| `routes/install.py` | `POST /api/v1/install` und `/uninstall`, Choco-Pfad synchron, Custom-Pfad fire-and-forget mit Version-Tracking, exportiert `_build_install_command`/`_build_uninstall_command`/`_run_custom_command_bg` für admin-getriggerte Calls |
| `routes/admin.py` | Alle `/admin/api/*` Endpoints: Login/Logout/SSO, Users-CRUD, Whitelist, Upload, Versionen, Distributions, Push-Update, admin-getriggerter (Un)Install pro Agent, Settings, Build-Trigger, Reveal, Detect-Uninstall, Hilfe |
| `templates/admin.html` | Single-Page Admin-UI (Vanilla JS, 7 Tabs + mehrere Slide-in-Panels + Confirm-/Passwort-Modals) |
| `templates/admin_login.html` | Standalone Login-Form mit konditionalem SSO-Button |
| `templates/admin_help.html` | HTML-Fragment für den Hilfe-Tab (lazy loaded) |

### Builder-Container (`softshelf-builder`)

**Image-Basis:** `tobix/pywine:3.11` (Debian + Wine 9.x staging + Windows-Python-3.11 unter Wine)
**Port:** 8766 (nur internes docker-Netz, nicht exposed)
**Volumes:**
- `./downloads:/app/downloads` — Ziel für Build-Artefakte (shared mit Proxy)

**Zweck:** Cross-Compile von `softshelf.exe` und `softshelf-setup.exe` aus der in der Image
gebackenen Client-Source. Wird vom Proxy via interne HTTP-API getriggert, nicht
permanent aktiv (Idle-FastAPI).

**Baked-in:**
- Wine-Prefix mit Windows-Python 3.11
- PyInstaller 6.11.1 + PyQt5 5.15.11 + httpx + pystray + Pillow + pywin32
- Linux-native FastAPI + uvicorn für den Trigger-Endpoint
- Client-Source (`client/`-Copy vom Projekt-Root via Docker-Build-Context)
- `server.py` (FastAPI-App) + `build.sh`

**HTTP-API:**
- `GET /health` — Liveness
- `POST /build` — Body `{proxy_url, version}` → serieller Build (Lock), returns `{ok, log}`

**Build-Workflow (`build.sh`):**

1. Arbeitskopie von `/app/client_src/*` → `/tmp/build-$$/`
2. Injiziert `_build_config.py`:
   ```python
   DEFAULT_PROXY_URL = "<current proxy_public_url from settings>"
   BUILD_VERSION = "<version>"
   ```
3. Überschreibt `_version.py` mit der Build-Version
4. `wine python -m PyInstaller --onefile --windowed --name softshelf main.py`
5. `wine python -m PyInstaller --onefile --windowed --name softshelf-setup --add-data "$(pwd)/dist/softshelf.exe;." setup.py`
6. `cp dist/*.exe /app/downloads/`
7. Räumt `/tmp/build-$$` auf

**Dauer:** Erster Build nach Container-Bau: ~4-5 min. Cached Builds: ~4-5 min (PyInstaller
ist nicht cachebar pro Rebuild — Wine-Overhead zusätzlich).

**Warum Wine statt Windows-Container:** Windows-Container brauchen Windows-Host, nicht
portabel. Wine ermöglicht reinen Linux-Deploy auf jedem Docker-Host.

### Kiosk-Client (`softshelf.exe`)

**Framework:** PyQt5 (5.15) mit custom-paint-Widgets
**Theme:** Refined light (Linear-inspired), zinc-Farbskala, Segoe UI
**Architektur:**
- `main.py` — `QApplication` + `KioskTray.start()`
- `config.py` — `ClientConfig` via `HKLM\SOFTWARE\Softshelf`
- `api_client.py` — httpx-Sync-Client + `Package`-Dataclass
- `_version.py` — statische Versions-Konstante
- `_build_config.py` — vom Builder überschriebene `DEFAULT_PROXY_URL`
- `ui/tray.py` — pystray-Icon, Qt-Signals für Thread-Sicherheit, Confirm-Beenden
- `ui/package_window.py` — Haupt-UI, Sidebar mit Kategorien, Paket-Cards, Install/Uninstall-Buttons, Worker-Threads

**Ablauf Client-Start:**
1. Registry wird gelesen (`ProxyUrl` + `MachineToken`)
2. API-Client holt `/api/v1/client-config` (app_name für UI-Titel)
3. Tray-Icon via `pystray.run_detached()` in Hintergrundthread
4. Klick auf Tray → Qt-Signal → `PackageWindow` auf Main-Thread
5. `_Loader`-Thread fetcht `/api/v1/packages`
6. Install-Klick → `_ActionWorker`-Thread → `POST /api/v1/install`
7. Bei "started"-Response: optimistisches UI-Update, Status-Abgleich beim nächsten Refresh

**Konfiguration (Registry):**

```
HKLM\SOFTWARE\Softshelf
    ProxyUrl     = "http://proxy.intern:8765"
    MachineToken = "<JWT>"
```

### Installer (`softshelf-setup.exe`)

**Basis:** `client/setup.py` via PyInstaller `--onefile --windowed`
**Enthält:** `softshelf.exe` als `--add-data` embedded resource
**Modi:**
- **Silent CLI:** `softshelf-setup.exe --proxy-url URL --reg-secret SECRET [--agent-id ID]`
- **GUI:** Doppelklick → tkinter-Wizard mit URL-Validierung, Show-Password-Toggle, friendly Errors
- **Uninstall:** `softshelf-setup.exe --uninstall`

**Default-Proxy-URL:** Aus `_build_config.DEFAULT_PROXY_URL` (vom Builder eingebacken).
Bei manuellem PyInstaller-Lauf aus dem Repo: leerer String, muss via `--proxy-url` angegeben werden.

**Installationsschritte:**
1. `softshelf.exe` → `C:\Program Files\Softshelf\softshelf.exe`
2. `POST /api/v1/register` → Machine-Token holen
3. Token + ProxyUrl → `HKLM\SOFTWARE\Softshelf`
4. ProxyUrl → System-Umgebungsvariable `SOFTSHELF_PROXY_URL`
5. Autostart-Key in `HKLM\...\CurrentVersion\Run`
6. `softshelf.exe` direkt starten

**Agent-ID Auto-Detection:** Liest `HKLM\SOFTWARE\TacticalRMM\agentid` (und `Wow6432Node`-Variante).

---

## Datenbank-Schema

```sql
-- Kuratierte Paket-Whitelist (choco + custom)
CREATE TABLE packages (
    name               TEXT PRIMARY KEY,        -- choco-Name oder slug aus filename
    display_name       TEXT NOT NULL,
    category           TEXT NOT NULL DEFAULT 'Allgemein',
    created_at         TEXT DEFAULT (datetime('now')),
    updated_at         TEXT DEFAULT (datetime('now')),
    type               TEXT NOT NULL DEFAULT 'choco',  -- 'choco' | 'custom'
    filename           TEXT,                    -- Spiegelt die current_version
    sha256             TEXT,                    -- "
    size_bytes         INTEGER,                 -- "
    install_args       TEXT,                    -- "
    uninstall_cmd      TEXT,                    -- "
    detection_name     TEXT,                    -- Windows-Display-Name für Match (nur custom)
    current_version_id INTEGER                  -- FK auf package_versions.id
);

-- Versionen pro custom-Paket. Die "current" Version wird über
-- packages.current_version_id verlinkt. Die flachen Felder in `packages`
-- (filename/sha256/...) spiegeln die current-Version für Rückwärtskompatibilität.
CREATE TABLE package_versions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name  TEXT NOT NULL,
    version_label TEXT NOT NULL,                -- z.B. "v1", "1.2.3", "2026-Q2"
    filename      TEXT,
    sha256        TEXT,
    size_bytes    INTEGER,
    install_args  TEXT,
    uninstall_cmd TEXT,
    notes         TEXT,                         -- Freitext / Changelog
    uploaded_at   TEXT DEFAULT (datetime('now')),
    UNIQUE(package_name, version_label),
    FOREIGN KEY (package_name) REFERENCES packages(name) ON DELETE CASCADE
);

-- Pro Agent + Paket: welche Version ist dort installiert? Wird beim
-- erfolgreichen Install/Uninstall geschrieben (nur custom-Pakete).
-- Speist Outdated-Detection und Push-Update.
CREATE TABLE agent_installations (
    agent_id     TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version_id   INTEGER,                       -- FK auf package_versions.id
    installed_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (agent_id, package_name)
);

-- Permanente Sperrliste für Agents. Eintrag überlebt das Löschen aus
-- der `agents`-Tabelle und blockt /api/v1/register sowie verify_machine_token.
-- Wird im Admin-UI per "Sperren" gesetzt, per "Entsperren" gelöscht.
CREATE TABLE agent_blocklist (
    agent_id   TEXT PRIMARY KEY,
    hostname   TEXT,                          -- Snapshot zum Zeitpunkt der Sperre
    banned_at  TEXT DEFAULT (datetime('now')),
    banned_by  TEXT,                          -- Admin-Username
    reason     TEXT
);

-- Tactical-Chocos-Cache
CREATE TABLE chocos_cache (
    name       TEXT PRIMARY KEY,
    cached_at  TEXT DEFAULT (datetime('now'))
);

-- Registrierte Kiosk-Clients
CREATE TABLE agents (
    agent_id      TEXT PRIMARY KEY,
    hostname      TEXT NOT NULL,
    registered_at TEXT DEFAULT (datetime('now')),
    last_seen     TEXT DEFAULT (datetime('now')),
    token_version INTEGER NOT NULL DEFAULT 1  -- Bump = alle bisherigen Tokens ungültig
);

-- Install-Aktionen (audit history)
CREATE TABLE install_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT DEFAULT (datetime('now')),
    agent_id     TEXT NOT NULL,
    hostname     TEXT NOT NULL,
    package_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    action       TEXT NOT NULL CHECK(action IN ('install','uninstall'))
);

-- HTTP-Request-Audit (auto-pruning)
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT DEFAULT (datetime('now')),
    method      TEXT,
    path        TEXT,
    client_ip   TEXT,
    status      INTEGER,
    duration_ms INTEGER
);

-- Runtime-Settings (key-value, im Admin-UI editierbar)
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at TEXT DEFAULT (datetime('now'))
);

-- EXE-Build-Historie
CREATE TABLE build_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT DEFAULT (datetime('now')),
    finished_at TEXT,
    status      TEXT NOT NULL,               -- 'running' | 'success' | 'failed'
    log         TEXT NOT NULL DEFAULT '',
    proxy_url   TEXT,                        -- was in _build_config eingebacken wurde
    version     TEXT
);

-- Lokale Admin-User (mit optionaler SSO-Bindung an Microsoft Entra ID)
CREATE TABLE admin_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT,
    email         TEXT,
    password_hash TEXT,                      -- scrypt(N=16384, r=8, p=1) | NULL bei SSO-only
    sso_provider  TEXT,                      -- 'entra' | NULL
    sso_subject   TEXT,                      -- oid aus Entra | NULL
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT DEFAULT (datetime('now')),
    last_login    TEXT
);

-- Login-Sessions für admin_users (Cookie-Token)
CREATE TABLE admin_sessions (
    token       TEXT PRIMARY KEY,            -- random 32 bytes hex
    user_id     INTEGER NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL,
    last_active TEXT DEFAULT (datetime('now')),
    user_agent  TEXT,
    ip          TEXT,
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
);

-- Indexe
CREATE INDEX idx_install_log_agent      ON install_log(agent_id, id DESC);
CREATE INDEX idx_audit_log_ts           ON audit_log(ts);
CREATE INDEX idx_build_log_ts           ON build_log(started_at DESC);
CREATE INDEX idx_admin_sessions_user    ON admin_sessions(user_id);
CREATE INDEX idx_admin_sessions_exp     ON admin_sessions(expires_at);
CREATE INDEX idx_package_versions_pkg   ON package_versions(package_name);
CREATE INDEX idx_package_versions_sha   ON package_versions(sha256);
CREATE INDEX idx_agent_installations_pkg ON agent_installations(package_name);
CREATE UNIQUE INDEX idx_admin_users_sso  ON admin_users(sso_provider, sso_subject)
    WHERE sso_subject IS NOT NULL;
```

**Migration-Strategie:** `init_db()` nutzt `PRAGMA table_info` + idempotentes
`ALTER TABLE ADD COLUMN`. Bestehende DBs bekommen neue Spalten ohne Datenverlust.

---

## Authentifizierung & Sicherheit

### Machine-Token (JWT, HS256)

**Payload:**
```json
{
  "agent_id": "<tactical agent-id>",
  "hostname": "<pc hostname>",
  "iat":      <unix>,
  "exp":      <unix>,        ← optional, wenn token_ttl_days > 0
  "tv":       <int>          ← Token-Version für Revocation
}
```

**Erzeugung:** `create_machine_token()` liest aktuelle `token_version` aus DB und bäckt sie in den Token ein.

**Verify-Pipeline (`verify_machine_token`):**
1. JWT-Signatur prüfen (`algorithms=["HS256"]`, Algorithmus gepinnt)
2. `exp` prüfen → `ExpiredSignatureError` → 401 „Token abgelaufen"
3. `agent_id`+`hostname` Pflichtfelder prüfen → 401 „Token fehlt Pflichtfelder"
4. **Blocklist-Check:** `is_agent_banned(agent_id)` → bei Treffer 403 „Gerät gesperrt"
5. `tv` aus Payload mit `agents.token_version` aus DB vergleichen → bei Mismatch 401 „Token widerrufen"
6. `last_seen` für den Agent aktualisieren

**Revocation-Mechanismen:**
- **Ablauf:** via `exp`-Claim nach `token_ttl_days` (0 = nie, Default 365)
- **Re-Register:** bumpt `token_version` in DB → alle bisherigen Tokens für diesen Agent sind sofort tot
- **Admin-Revoke:** Button im Agent-Detail-Panel → `bump_token_version` ohne Re-Register
- **Admin-Delete:** Button im Agent-Detail-Panel → cascading delete
  (`agent_installations`, `install_log`, `agents`); Tokens werden ungültig weil
  `get_token_version` für unbekannte Agents 1 zurückliefert
- **Admin-Ban:** Button im Agent-Detail-Panel → Eintrag in `agent_blocklist`,
  überlebt Re-Register; auch nach Delete weiter wirksam (PK ist `agent_id`)

### Download-Token (signed URL)

Für den Tactical-Agent-Download einer custom MSI/EXE wird ein separates JWT mit
Kurz-TTL erzeugt:

```json
{
  "typ":      "dl",
  "sha":      "<sha256>",
  "agent_id": "<tactical agent-id>",
  "iat":      <unix>,
  "exp":      <unix + 300s>
}
```

Wird in der Install-Command-PowerShell als Query-Parameter in die Download-URL
gepackt. Der Endpoint `GET /api/v1/file/{sha256}?token=<jwt>` verifiziert:
- Signatur + exp (5 min TTL)
- `typ == "dl"`
- `sha` matcht den URL-Parameter
- Paket mit diesem Hash existiert in der DB
- Physische Datei im `/app/data/uploads/` vorhanden

Das Token ist **an Hash + Agent-ID gebunden**: selbst wenn ein Angreifer die URL
aus dem Tactical-Audit-Log zieht, ist sie nur für den spezifischen Agent gültig und
nach 5 min tot.

### Admin-Authentifizierung

**Session-Cookie-basiert** (kein HTTP Basic Auth mehr) mit zwei Login-Wegen:

**1. Lokal (Username + Passwort):**
- User-Verwaltung in `admin_users`-Tabelle, mehrere Admins möglich
- Passwort-Hashing via `hashlib.scrypt` (N=16384, r=8, p=1, 16-byte salt)
- Vergleich via `secrets.compare_digest` (timing-safe)
- Login: `POST /admin/login` → erzeugt random 32-Byte-Token in `admin_sessions`,
  setzt `softshelf_admin_session` Cookie (HttpOnly, SameSite=Strict, Secure-conditional,
  path=/admin)
- Bootstrap: beim ersten Start wird der `.env`-Admin-User in die DB übernommen.
  Wenn alle aktiven Admins deaktiviert sind, kann sich der Bootstrap-Admin einmalig
  einloggen und der Account wird neu provisioniert (Recovery-Pfad).
- Self-Service Passwort-Change: User können ihr eigenes Passwort ändern
  (Old-Password-Check). Bei Erfolg werden **alle anderen Sessions des Users
  weggeworfen** (gestohlene Cookies sollen die Rotation nicht überleben), und
  ein frischer Cookie wird ausgestellt.
- Safeguards: letzter aktiver Admin kann nicht deaktiviert/gelöscht werden;
  Deaktivierung beendet alle bestehenden Sessions des Users; SSO-only User
  bekommen beim Password-Change-Versuch eine sprechende Fehlermeldung.

**2. Microsoft Entra ID SSO** (optional, in Settings aktivierbar):
- Authorization Code Flow mit OpenID Connect
- ID-Token-Validierung via `PyJWT.PyJWKClient` gegen Microsofts JWKS-Endpoint
  (Issuer + Audience + Signature, RS256, alle Pflichtfelder erforderlich)
- Mapping über `oid` (object ID) → `admin_users.sso_subject`
- E-Mail-Linking nur wenn:
  - Entra-Claim `email_verified=true` (sonst Spoofing möglich)
  - bestehender lokaler User noch keine SSO-Bindung hat (kein Hijack via
    nachträgliche E-Mail-Änderung)
- `preferred_username` wird **bewusst ignoriert** — der Wert ist in Entra ID
  nicht verifiziert und ein Tenant-Admin könnte ihn auf jede beliebige Adresse
  setzen
- `sso_auto_create=true` → erster SSO-Login provisioniert automatisch einen
  Admin-User; sonst muss der User vorher manuell mit derselben E-Mail angelegt
  sein
- State-Token im OAuth-Flow gegen CSRF; in-memory Cache mit 600s TTL, single-use

**Session-Lifecycle:**
- TTL: 12 Stunden, sliding window via `last_active`-Update bei jedem Request
- Logout: `POST /admin/logout` → DB-Eintrag löschen + Cookie clear
- `cleanup_expired_sessions()` läuft beim Container-Start

### Cookie-Härtung

Session-Cookie wird mit folgenden Flags gesetzt:

| Flag | Wert | Zweck |
|---|---|---|
| `HttpOnly` | true | JS auf der Seite kann den Cookie nicht lesen → XSS kann ihn nicht stehlen |
| `SameSite` | Strict | Browser sendet den Cookie nicht Cross-Origin (auch nicht bei Top-Level-Navigation von fremden Sites) |
| `Secure` | conditional | wird gesetzt wenn der Request über HTTPS kam (`request.url.scheme == "https"` ODER `X-Forwarded-Proto: https` von vertrauenswürdigem Reverse-Proxy). Bei plain HTTP weggelassen, damit der Cookie überhaupt funktioniert |
| `Path` | /admin | nur an Admin-Endpoints gesendet |

### CSRF-Schutz

Auf state-changing Requests (`POST|PUT|PATCH|DELETE`) unter `/admin/api/*`:
- Entweder `Origin`/`Referer`-Header matcht `Host`
- Oder `X-Requested-With: XMLHttpRequest` gesetzt (Browser senden den Header
  NIE automatisch cross-origin)

Die Admin-UI-JavaScript-Funktion `api()` setzt beides automatisch, fremde
JavaScript-Aufrufer (cross-origin) bekommen 403.

### XSS-Härtung im Admin-UI

- Standard-HTML-Escape via `esc(s)` für content-Kontexte (innerHTML-Body)
- Für **JS-String-Literal in HTML-Attribut** (z.B. `onclick="foo('${...}')"`)
  wird `jsStr(value) = esc(JSON.stringify(value))` verwendet — `esc()` allein
  reicht nicht, weil der HTML-Parser `&#39;` zu `'` zurück-dekodiert, was den
  JS-String terminieren würde
- Alle inline-`onclick`-Handler die admin-controlled Daten enthalten
  (display_name, version_label, hostname, file paths) wurden auf `jsStr`
  umgestellt
- Login-Page: `errEl.textContent` statt `innerHTML` für defense-in-depth

### XSS-Härtung im Kiosk-Client

- `QLabel.setTextFormat(Qt.PlainText)` für admin-controlled `display_name`
- Alle interpolierten Werte aus Tactical (Version, Publisher) und der DB
  (Version-Labels) werden mit `html.escape()` behandelt, bevor sie in das
  rich-text QLabel landen
- `setOpenExternalLinks(True)` ist nur für Chocolatey-Pakete aktiv; bei
  custom-Paketen werden Links nicht klickbar gemacht (verhindert
  `file://`-Schlepperei aus Tactical-Daten)

### Rate-Limit

In-Memory Per-IP-Bucket, ohne externe Dependency. Limits:
- `/api/v1/register`: **5 Requests / 60 s** (Brute-Force-Schutz auf Registration-Secret)
- `/admin/login` + `/admin/*`: **60 Requests / 60 s** (Brute-Force auf Login +
  normale UI-Nutzung)

**X-Forwarded-For:** wenn der Proxy hinter einem Reverse-Proxy auf demselben
Host läuft (peer-IP `127.0.0.1` / `::1`), wird der erste Eintrag aus dem
`X-Forwarded-For`-Header als echte Client-IP verwendet. Damit zählt jeder
echte Client einzeln. X-Forwarded-For von externen IPs wird ignoriert
(sonst trivial spoofbar).

**Memory-Cleanup:** alle 500 Requests läuft ein Sweep über die Buckets, der
IPs mit leeren Deques wegwirft. Damit wächst der Speicher nicht unbegrenzt.

### Input-Validierung

| Feld | Regex / Regel | Wo verwendet |
|---|---|---|
| **Paketname** | `^[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,99}$` | DB-Key, PowerShell-Commands, URLs |
| **Agent-ID** | `^[a-zA-Z0-9\-]{8,64}$` | Tactical-API, Tracking |
| **Hostname** | `^[a-zA-Z0-9._\-]{1,253}$` | Logs, Anzeige |
| **Username** | `^[a-zA-Z0-9._\-@]{2,80}$` | Admin-Login |
| **Display-Name / Kategorie** | `^[^\x00-\x1f\x7f]{1,80}$` | UI-Anzeige |
| **Version-Label** | `^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,49}$` | Versions-Liste, URLs |
| **Install-Args / Uninstall-Cmd / Entry-Point / Detection-Name** | Keine Steuerzeichen / Newlines (`^[^\x00-\x1f\x7f]*$`) | PowerShell-Commands |
| **Entry-Point (zusätzlich)** | Kein `..`, kein leading `/`, validiert gegen `archive_entries` | Archive-Pakete |
| **Upload-Extension** (Single-File) | Nur `.msi` und `.exe` | save_upload |
| **Folder-Upload-Pfade** | Kein `..`, kein leading `/`, kein Drive-Letter, keine empty segments | save_folder_upload + edit_archive (defense-in-depth) |
| **Upload-Größe** | `max_upload_mb` Runtime-Setting (Default 500 MB) — geprüft auf **dekomprimierter** Größe für ZIP-Bomb-Defense | alle Upload-Pfade |
| **proxy_public_url** | Nur `http://` oder `https://`, urlparse-validiert, keine Quotes/Backslashes/Steuerzeichen | config-validator |

### Datenbank-Integrität

- **Parametrisierte Queries:** alle aiosqlite-Aufrufe verwenden `?`-Platzhalter.
  User-Input landet nie verbatim im SQL. Dynamische Update-Builder verwenden
  ein Whitelist-Mapping (`update_admin_user`).
- **Foreign Keys:** jede Connection wird über den `_db()`-Helper geöffnet, der
  `PRAGMA foreign_keys = ON` setzt — SQLite enforced FKs nicht automatisch.
  Damit greifen die `ON DELETE CASCADE`-Klauseln im Schema (z.B.
  `package_versions → packages`).
- **Migrations:** `init_db()` nutzt idempotente `PRAGMA table_info`-Checks +
  `ALTER TABLE ADD COLUMN`. Bestehende DBs bekommen neue Spalten ohne
  Datenverlust.
- **delete_package_version**: prüft `expected_package_name` **VOR** dem Delete
  (nicht danach), um TOCTOU-Bugs durch falsche Pfad-Parameter zu verhindern.

### Build-Pipeline-Härtung

Die `build.sh` schreibt `_build_config.py` (mit der eingebackenen
`proxy_public_url`) NICHT mehr direkt per Bash-Heredoc. Stattdessen wird URL
und Version per ENV an einen Python-Subprozess übergeben, der die Werte mit
`repr()` ausgibt. Plus zusätzlich validiert der Python-Block jeden Character
gegen Quotes/Backslashes/Steuerzeichen (defense-in-depth).

Damit ist die Code-Injection-Schwachstelle geschlossen, bei der ein Admin
(oder XSS-Opfer) mit einer URL wie `http://x"; import os; ...` arbiträren
Python-Code in jede gebaute `softshelf.exe` einbacken konnte.

### Background-Task-Tracking

Alle `asyncio.create_task(...)` Aufrufe gehen über `_spawn_bg(coro)`, der eine
Strong-Reference im modul-globalen `_bg_tasks: set[asyncio.Task]` hält und sie
nach Done wieder rauswirft. Verhindert dass der GC laufende Tasks einsammelt
(siehe Python-Doku zu `asyncio.create_task`).

### Container-Hardening

- Proxy läuft als `softshelf` (UID 1001), nicht als root
- `entrypoint.sh` chownt `/app/data` beim Start und droppt via `gosu`
- Keine SSH/anderen Services im Container
- Non-root Dockerfile-User implementiert

### Noch offen (bewusst)

- **TLS:** der Proxy selbst kann kein TLS — produktiv hinter Reverse-Proxy
  (Caddy/Traefik). Cookie-Secure-Flag und URL-basierte Sicherheit greifen
  automatisch sobald `proxy_public_url` https ist.
- **One-Time-Registration-Tokens:** aktuell shared secret + Rate-Limit + min_length=16
- **MFA für lokales Login:** nicht implementiert. Wer MFA will, aktiviert SSO
  mit Microsoft Entra ID (Conditional Access etc.).
- **4-Augen-Prinzip auf Paket-Pushes:** ein Admin allein kann jeden Custom-Cmd
  auf jeden Endpoint pushen. Effektiv SYSTEM-RCE — die Admin-Rolle ist
  Domain-Admin-Niveau und sollte minimal gehalten werden.
- **Code-Signing-Verifikation auf hochgeladenen MSI/EXE:** nicht implementiert.

---

## API-Referenz

### Public Endpoints

| Methode | Pfad | Auth | Zweck |
|---|---|---|---|
| `GET` | `/api/v1/health` | – | DB-Ping + `{status, version}` |
| `GET` | `/api/v1/client-config` | – | `{app_name, version}` für Kiosk-Client-UI |
| `POST` | `/api/v1/register` | Registration-Secret + Rate-Limit | JWT-Token ausstellen, token_version bump |
| `GET` | `/api/v1/packages` | Bearer JWT | Whitelist + Install-Status pro Paket |
| `POST` | `/api/v1/install` | Bearer JWT | Choco-Install synchron, Custom-Install fire-and-forget |
| `POST` | `/api/v1/uninstall` | Bearer JWT | Analog zu /install |
| `GET` | `/api/v1/file/{sha256}?token=...` | Signed JWT | Custom-File-Download für Tactical-Agent |
| `GET` | `/download/softshelf-setup.exe` | – | Installer-EXE aus /app/downloads/ |
| `GET` | `/download/softshelf.exe` | – | Standalone-Kiosk-EXE |

### Admin Endpoints

Alle unter `/admin/api/*` brauchen Session-Cookie + CSRF-Middleware + Rate-Limit.
Die Login/SSO-Endpoints darunter sind die Ausnahme.

**Auth & Session:**

| Methode | Pfad | Body | Zweck |
|---|---|---|---|
| `GET` | `/admin/login` | – | HTML Login-Form |
| `POST` | `/admin/login` | form: `username`, `password` | Lokal-Login → Session-Cookie |
| `POST` | `/admin/logout` | – | Session in DB löschen + Cookie clear |
| `GET` | `/admin/api/whoami` | – | aktuell eingeloggter User |
| `GET` | `/admin/sso/login` | – | Redirect zu Microsoft-OIDC-Authorize |
| `GET` | `/admin/sso/callback` | code, state | OIDC-Callback → Session-Cookie |
| `POST` | `/admin/api/users/me/change-password` | `{old_password, new_password}` | Eigenes Passwort ändern |

**Admin-User-Verwaltung:**

| Methode | Pfad | Body |
|---|---|---|
| `GET` | `/admin/api/users` | – |
| `POST` | `/admin/api/users` | `{username, display_name, email, password, is_active}` |
| `PATCH` | `/admin/api/users/{id}` | partial: `{display_name?, email?, password?, is_active?}` |
| `DELETE` | `/admin/api/users/{id}` | – (mit Last-Active-Admin-Schutz) |

**Paket-Whitelist:**

| Methode | Pfad | Body |
|---|---|---|
| `GET` | `/admin/api/enabled` | – |
| `GET` | `/admin/api/search?q=` | – |
| `POST` | `/admin/api/enable` | `{name, display_name, category}` |
| `PATCH` | `/admin/api/enable/{name}` | `{name, display_name, category}` |
| `DELETE` | `/admin/api/enable/{name}` | – (cascading delete: alle Versionen + Tracking + Files) |

**Custom-Pakete & Versionierung:**

| Methode | Pfad | Body |
|---|---|---|
| `POST` | `/admin/api/upload` | multipart: `file` + (`display_name`, `category`, `install_args`, `detection_name`, `uninstall_cmd`) bei neuem Paket ODER (`target_package`, `version_label?`, `version_notes?`, `set_current=true`) zum Anhängen einer Version |
| `PATCH` | `/admin/api/custom/{name}` | `{display_name, category, install_args, detection_name, uninstall_cmd}` |
| `GET` | `/admin/api/custom/{name}/detect-uninstall` | – scannt Agents, extrahiert Uninstall aus Tactical |
| `DELETE` | `/admin/api/upload/{name}` | – (Alias für `DELETE /admin/api/enable/{name}`) |
| `GET` | `/admin/api/packages/{name}/versions` | – Liste aller Versionen eines Pakets + Summary |
| `POST` | `/admin/api/packages/{name}/versions/{version_id}/set-current` | – flatten flache packages.*-Felder neu |
| `DELETE` | `/admin/api/packages/{name}/versions/{version_id}` | – (verweigert wenn current; File-Cleanup bei letzter Referenz) |

**Verteilung & Push-Update:**

| Methode | Pfad | Body |
|---|---|---|
| `GET` | `/admin/api/distributions` | – Übersicht ALLER custom-Pakete + Installationen + Summary |
| `GET` | `/admin/api/packages/{name}/installations` | – nur die Installationen eines Pakets |
| `POST` | `/admin/api/packages/{name}/push-update` | – Reinstall current-Version auf alle outdated Agents (fire-and-forget) |
| `POST` | `/admin/api/agents/{agent_id}/install/{package_name}` | – admin-getriggerter (Re-)Install der current-Version auf einem einzelnen Agent |
| `POST` | `/admin/api/agents/{agent_id}/uninstall/{package_name}` | – admin-getriggerter Uninstall auf einem einzelnen Agent |

**Clients & Audit:**

| Methode | Pfad | Body |
|---|---|---|
| `GET` | `/admin/api/agents` | – (inkl. `banned`-Flag pro Agent) |
| `GET` | `/admin/api/agents/{id}/installs` | – install_log Einträge des Agents |
| `GET` | `/admin/api/agents/{id}/managed` | – per Self-Service installierte Pakete + Version-Status |
| `POST` | `/admin/api/agents/{id}/revoke` | – bumpt token_version (alter Token wird ungültig) |
| `DELETE` | `/admin/api/agents/{id}` | – cascading delete: installations + install_log + agents |
| `POST` | `/admin/api/agents/{id}/ban` | `{reason}` — setzt Agent auf Blocklist + bumpt token_version |
| `POST` | `/admin/api/agents/{id}/unban` | – entfernt Agent von Blocklist |
| `GET` | `/admin/api/blocklist` | – Liste aller gesperrten Agents (auch der gelöschten) |
| `GET` | `/admin/api/audit?limit=` | – |

**Settings:**

| Methode | Pfad | Body |
|---|---|---|
| `GET` | `/admin/api/settings` | – (secrets maskiert) |
| `PATCH` | `/admin/api/settings` | `{values: {key: value, ...}}` |
| `GET` | `/admin/api/settings/{key}/reveal` | – (echter Wert für Secret-Keys) |
| `POST` | `/admin/api/settings/rotate-registration-secret` | – |

**Build-System:**

| Methode | Pfad | Body |
|---|---|---|
| `GET` | `/admin/api/build/status` | – letzter Build + Artefakt-Infos |
| `GET` | `/admin/api/build/{id}` | – vollständiger Log eines Builds |
| `POST` | `/admin/api/build` | – triggert neuen Build (async, background) |

**Hilfe:**

| Methode | Pfad | Body |
|---|---|---|
| `GET` | `/admin/api/help` | – HTML-Fragment für den Hilfe-Tab (lazy loaded) |

---

## Datenfluss: Install-Szenarien

### Choco-Paket (synchron)

```
1. softshelf.exe → POST /api/v1/install {package_name: "firefox"}
     ├─ Bearer JWT
2. Proxy: verify_machine_token → agent_id aus JWT
3. Proxy: Regex-Check + Whitelist-Lookup
4. Proxy: TacticalClient.install_software(agent_id, "firefox")
     └─ POST https://tactical/software/{id}/  {name: "firefox"}
        ← Tactical antwortet SOFORT mit "firefox will be installed shortly"
5. Proxy: log_install(...)
6. softshelf.exe: "Installation gestartet"
   (Tactical-Agent führt später choco install asynchron aus)
```

### Custom-MSI (fire-and-forget, mit Version-Tracking)

```
1. softshelf.exe → POST /api/v1/install {package_name: "OpenVPN-2.7.1-I001-amd64"}
2. Proxy: verify_machine_token
3. Proxy: DB-Lookup → type=custom, sha256, install_args, filename, current_version_id
4. Proxy: create_download_token(sha, agent_id, ttl=300s)
5. Proxy: baut PowerShell-Command:
     $tmp = Join-Path $env:TEMP 'kiosk_install_xxx.msi'
     Invoke-WebRequest -Uri 'http://proxy/api/v1/file/<sha>?token=<jwt>' -OutFile $tmp
     Start-Process -FilePath msiexec -ArgumentList '/i', $tmp, '/qn', '/norestart' -Wait -PassThru
     Remove-Item $tmp -Force
6. Proxy: asyncio.create_task(_run_custom_command_bg(..., version_id)) → return SOFORT
7. Proxy: log_install(...)  (audit history)
8. softshelf.exe: "Installation gestartet, dauert einige Minuten"
   (im Hintergrund:)
9. Background-Task: TacticalClient.run_command(agent_id, ps_cmd, timeout=600)
     └─ POST https://tactical/agents/{id}/cmd/
10. Tactical-Agent: download (signed URL), msiexec, cleanup
11. Bei Erfolg: Background-Task → set_agent_installation(agent_id, name, version_id)
    Damit weiß der Proxy: dieser Agent hat jetzt Version X.
12. Tactical's Software-Scan erkennt neue Installation (Minuten bis Stunden später)
13. Bei nächstem softshelf.exe → GET /api/v1/packages: detection_name matcht → "Installiert"
```

### Custom-EXE

Identisch zu MSI, nur dass der PowerShell-Command einen direkten `Start-Process`
auf den EXE-Pfad macht statt msiexec:

```
Start-Process -FilePath $tmp -ArgumentList '/S' -Wait -PassThru -NoNewWindow
```

### Uninstall (choco + custom)

- **Choco:** `TacticalClient.uninstall_software()` → POST `/software/{id}/uninstall/`
  mit `choco uninstall <name> -y --no-progress` als Command
- **Custom:** fire-and-forget, ausgeführt wird der beim Upload gespeicherte `uninstall_cmd`
  via `cmd /c` gewrappt in PowerShell (Exit-Code-Propagation + Tolerant bei 3010/1605).
  Bei Erfolg → `delete_agent_installation(agent_id, name)` entfernt den Tracking-Eintrag.

### Push-Update (admin-getriggert)

Wenn der Admin im Verteilung-Tab oder Edit-Panel auf „Update pushen" klickt:

```
1. Admin → POST /admin/api/packages/{name}/push-update
2. Proxy: get_outdated_agents_for_package(name)
     → alle Agents, die das Paket installiert haben aber nicht auf current_version_id sind
3. Pro Agent:
     a. _build_install_command(pkg, agent_id) — neue signed-URL pro Agent
     b. asyncio.create_task(_run_custom_command_bg(..., 'install', current_version_id))
     c. log_install(...)
4. Sofort return: {dispatched: N, outdated: N}
5. Im Hintergrund laufen die einzelnen Installs parallel über Tactical-cmd.
6. Bei jedem erfolgreichen Install wird agent_installations.version_id aktualisiert,
   die Outdated-Liste schrumpft entsprechend.
```

Dasselbe Schema gilt für `POST /admin/api/agents/{agent_id}/install/{name}` —
nur eben für genau einen Agent statt für alle outdated.

### Versionierung — Datei-Lebenszyklus

```
1. Admin lädt MSI v1 hoch:
   → file_uploads.save_upload() → /app/downloads/<sha-v1>.bin
   → packages-Row angelegt (flache Felder spiegeln v1)
   → package_versions-Row v1 angelegt
   → packages.current_version_id = v1.id

2. Admin lädt v2 hoch (target_package=name, set_current=true):
   → /app/downloads/<sha-v2>.bin
   → package_versions-Row v2 angelegt
   → set_current_package_version(name, v2.id)
     → packages.current_version_id = v2.id
     → packages.filename/sha256/size_bytes/install_args/uninstall_cmd ← v2

3. Alle Agents auf v1 sind jetzt 'outdated'.
   Push-Update installiert v2 (siehe oben) und aktualisiert agent_installations.

4. Admin löscht v1:
   → DELETE /admin/api/packages/{name}/versions/{v1.id}
   → 400 wenn current — sonst:
     → package_versions-Row gelöscht
     → File <sha-v1>.bin gelöscht WENN count_versions_with_sha(sha-v1) == 0
       UND sha256_usage_count(sha-v1) == 0
```

---

## Build-Pipeline (EXE-Rebuild)

**Trigger:** Admin klickt im UI-Tab „Einstellungen" auf **„EXEs bauen"**.

**Ablauf:**

```
1. Admin → POST /admin/api/build
2. Proxy: liest proxy_public_url aus Runtime-Settings
3. Proxy: legt build_log-Eintrag an (status='running')
4. Proxy: asyncio.create_task(_run_build_async) → return build_id
5. Background-Task:
   └─ POST http://softshelf-builder:8766/build {proxy_url, version}
        └─ builder: lock erwerben
        └─ builder: env setzen, /app/build.sh starten
        └─ build.sh: /app/client_src → /tmp/build-$$ kopieren
        └─ build.sh: _build_config.py + _version.py schreiben
        └─ build.sh: wine python -m PyInstaller (softshelf.exe)
        └─ build.sh: wine python -m PyInstaller (softshelf-setup.exe)
        └─ build.sh: cp dist/*.exe /app/downloads/
        └─ builder: return {ok: true, log: "..."}
6. Proxy: finish_build_log(build_id, status, log)
7. Admin-UI: polling /admin/api/build/status erkennt status='success'
8. softshelf-setup.exe sofort via /download/softshelf-setup.exe verfügbar
```

**Eingebackene Werte:** `DEFAULT_PROXY_URL` aus Runtime-Setting → der frisch gebaute
Installer findet nach Default-Aufruf (ohne `--proxy-url`) direkt den richtigen Proxy.

---

## Admin-UI

**Datei:** `proxy/templates/admin.html` (Single-Page, Vanilla JS, handgeschriebenes CSS)
**Login:** `proxy/templates/admin_login.html` (separate Page mit SSO-Button-Conditional)
**Style:** Refined light theme, Geist Sans + Geist Mono, zinc-Skala

**Tabs:**

| Tab | Zweck |
|---|---|
| **Pakete** | Whitelist-Management: Chocolatey-Suche, Upload, Edit (inkl. Versions-Liste + Push-Update + Installations-View pro Paket), Delete |
| **Verteilung** | Cross-package Übersicht: pro custom-Paket eine Karte mit allen Geräten + ihrer Version + Update-/Entfernen-Buttons pro Zeile + Push-all für Outdated |
| **Kiosk-Clients** | Liste registrierter Agents, Online-Status, Install-Historie pro Agent |
| **Audit-Log** | Letzte 200 HTTP-Requests, Filter auf Pfad/IP |
| **Benutzer** | Admin-User-Verwaltung (lokal + SSO), Last-Login-Anzeige, Aktiv-Toggle |
| **Einstellungen** | Runtime-Settings-Editor (inkl. SSO-Sektion), Reveal für Secrets, Build-Button + Historie |
| **Hilfe** | Aufgaben-orientierte Admin-Dokumentation (lazy loaded HTML-Fragment) |

**Slide-in-Panels:**
- Such-Panel (Choco-Suche + Upload-Form mit Tab-Toggle)
- Kategorie-Picker
- Agent-Detail (Install-Historie pro Gerät)
- Custom-Paket Edit-Panel (inkl. Versions-Sektion: Liste + Set-Current + Delete + Inline-Upload neuer Versionen + Installations-Liste pro Paket + Push-Update-Button)
- User-Edit-Panel (Anlegen + Bearbeiten)

**Modals:**
- Confirm-Action (parametrisierbarer Button-Label und -Style)
- Passwort-Ändern (Live-Strength-Indicator + Match-Validation)

**User-Menu im Header:**
- Avatar-Initial mit Dropdown
- Anzeigename, E-Mail, SSO-Provider-Hinweis
- Passwort ändern (öffnet Modal)
- Logout

**Besonderheiten:**
- Live-Uhr im Header + Connection-Indicator (Pulse bei Verbindungsverlust)
- Outdated-Badge auf Paket-Karten zeigt Anzahl Geräte auf veralteter Version
- Lazy-loaded Help-Tab (großes HTML-Fragment, einmal pro Session)
- Vanilla-JS, keine Frameworks, keine Build-Tools — direkt editierbar
- 401 vom Server → automatischer Redirect zur Login-Page

---

## Deployment auf einen neuen Host

**Voraussetzungen:** Linux-Host mit Docker + docker-compose

```bash
# 1. Repo auf den Host
git clone <repo> /opt/softshelf
cd /opt/softshelf

# 2. Bootstrap-Konfiguration
cp .env.example .env
$EDITOR .env
# Mindestens SECRET_KEY (openssl rand -hex 32), ADMIN_USERNAME, ADMIN_PASSWORD setzen

# 3. Container bauen und starten
docker-compose up -d --build
# First-time build:
#   softshelf-proxy:    ~60 s
#   softshelf-builder:  ~5-8 min (pullt tobix/pywine, installiert PyQt5 unter Wine)

# 4. Browser öffnen:
#    http://<host>:8765/admin
#    Admin-Credentials aus .env
#    → Einstellungen → Tactical URL, API-Key, Registration-Secret, Proxy-URL ausfüllen
#    → Speichern
#    → EXEs bauen (dauert ~4 min)

# 5. softshelf-setup.exe vom Proxy ziehen und auf Test-PC installieren
#    Download-URL: http://<host>:8765/download/softshelf-setup.exe
```

**Upgrade auf neuer Version:**

```bash
cd /opt/softshelf
git pull
docker-compose up -d --build
# Settings bleiben (in data/ Volume)
# Downloads bleiben (in downloads/ Volume)
# Bestehende Clients bleiben aktiv (Token-Version bleibt gleich)
```

---

## Verzeichnisstruktur

```
softshelf/
├── ARCHITEKTUR.md              Dieses Dokument
├── docker-compose.yml          Multi-Service (proxy + builder)
├── .env.example                Bootstrap-Template
├── .env                        (lokal, nicht im Repo)
│
├── proxy/
│   ├── Dockerfile              python:3.11-slim + msitools + non-root
│   ├── entrypoint.sh           chownt data/ und droppt auf 'softshelf'
│   ├── requirements.txt        fastapi, uvicorn, httpx, PyJWT, aiosqlite, python-multipart
│   ├── main.py                 App-Setup, public endpoints
│   ├── config.py               Bootstrap + RUNTIME_KEYS
│   ├── database.py             SQLite + Migration + Helpers
│   ├── auth.py                 JWT (Machine-Token + Download-Token)
│   ├── tactical_client.py      Tactical-RMM-API-Wrapper
│   ├── file_uploads.py         MSI-Parsing + File-Storage
│   ├── middleware/
│   │   ├── audit_logger.py
│   │   ├── csrf.py
│   │   └── rate_limit.py
│   ├── admin_auth.py           scrypt + Sessions + Microsoft-Entra-OIDC
│   ├── routes/
│   │   ├── register.py
│   │   ├── packages.py
│   │   ├── install.py
│   │   └── admin.py            (~1000 Zeilen, alle admin-Endpoints inkl. Versionierung + Distribution)
│   └── templates/
│       ├── admin.html          Single-Page Admin-UI (7 Tabs)
│       ├── admin_login.html    Login-Form (lokal + SSO-Button)
│       └── admin_help.html     Hilfe-Tab Inhalt (HTML-Fragment)
│
├── builder/
│   ├── Dockerfile              tobix/pywine:3.11 + client-deps
│   ├── server.py               FastAPI-Trigger auf :8766
│   └── build.sh                PyInstaller unter Wine
│
├── client/
│   ├── main.py
│   ├── _version.py
│   ├── _build_config.py        vom Builder überschrieben
│   ├── config.py
│   ├── api_client.py
│   ├── setup.py                Installer mit tkinter-GUI
│   ├── requirements.txt        PyQt5, httpx, pystray, Pillow, pywin32
│   └── ui/
│       ├── tray.py
│       └── package_window.py
│
├── installer/
│   ├── build.ps1               Manueller Local-Build (Windows-Host)
│   ├── deploy_via_trmm.ps1     Tactical-Deployment-Script
│   └── generate_token.py       Admin-Tool: manuelles JWT
│
├── data/                       (Volume, persistent)
│   ├── softshelf.db                SQLite
│   └── uploads/                Custom MSI/EXE Files (sha256-named)
│
└── downloads/                  (Volume, shared proxy+builder)
    ├── softshelf.exe               vom Builder erzeugt
    └── softshelf-setup.exe         vom Builder erzeugt
```

---

## Offene Punkte / TODO

| Item | Priorität | Aufwand | Notiz |
|---|---|---|---|
| **TLS vor dem Proxy** | hoch | klein | via Caddy/Traefik Reverse-Proxy. Session-Cookie ist HttpOnly+Strict, aber HTTP exponiert ihn auf Layer-7 |
| One-Time-Registration-Tokens | mittel | mittel | aktuell durch Rate-Limit + `min_length=16` mitigiert |
| Auto-Refresh von Machine-Tokens | niedrig | mittel | aktuell: `token_ttl_days=0` für unbegrenzt, oder Re-Deploy |
| pytest für Proxy + Smoke-Tests Client | niedrig | groß | |
| Sortierbare Spalten in Tabellen | niedrig | klein | kosmetisch |
| Pagination im Install-Log | niedrig | klein | aktuell `LIMIT 200` |
| Build-Log-Streaming (statt Polling) | niedrig | mittel | SSE oder WebSocket |
| Backfill Tracking aus install_log | niedrig | klein | optionales One-Off zum Vorbefüllen von `agent_installations` aus historischen install-Aktionen |
