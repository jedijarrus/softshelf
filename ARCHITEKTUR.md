# Softshelf – Systemarchitektur

**Version:** 1.5.0

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
- **Winget als dritte Paket-Quelle** (v1.4.0): Lokal gemirrowter Microsoft-
  Catalog (täglicher Download von `cdn.winget.microsoft.com/cache/source.msix`,
  SQLite-Index extrahiert nach `/app/data/winget_index.db`, semver-aware
  Suche), nightly Per-Agent-Scan via Tactical `winget export` + `winget upgrade`,
  Discovery-Tab, Aktivierungs-Flow, Install/Upgrade/Uninstall-Dispatch
  als SYSTEM via Tactical mit `winget.exe`-Resolver aus
  `C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*` (per-user-
  Shim ist unter SYSTEM nicht im PATH), targeted Re-Scan nach jeder Aktion
- **Agent-Detail-Page** (v1.4.0): Vollbild-Detail-Sicht im Kiosk-Clients-Tab
  ersetzt die alte Slide-in-Sidebar. Zeigt zusammengeführte Software-Liste
  (Tactical-Scan + winget_state, dedupt mit Token-Score-Matching), Status-
  Badges (verwaltet/unverwaltet/Update verfügbar), per-Row Aktionen
  (Updaten/Deinstallieren/Aktivieren/Entfernen), Polling-basiertes
  Auto-Refresh nach Aktionen via `agent_scan_meta.last_scan_at`-Vergleich,
  Lifecycle-Aktionen (Re-Scan, Token-Revoke, Ban, Delete) im Header-Toolbar
- **APScheduler im Proxy** (v1.4.0): drei tägliche Background-Jobs für
  Catalog-Refresh (01:30), Fleet-Scan (02:00), Discovery-Enrichment (02:30)
- **Vereinheitlichung der drei Paket-Pipelines** (v1.5.0): Choco wird genau
  so verwaltet wie winget — eigener `choco_scanner.py`, neue Tabelle
  `agent_choco_state` (analog zu `agent_winget_state`), nightly Job um 02:15
  UTC der `choco list --limit-output` + `choco outdated --limit-output` über
  Tactical run_command absetzt und die Pakete pro Agent strukturiert
  inventarisiert. Choco install/uninstall geht jetzt auch über `run_command`
  statt über das fire-and-forget-Endpoint `/software/{id}/`, mit
  Output-Capture, Soft-Error-Detection (Patterns wie „Likely broken for
  FOSS users", 404-Download-Failures, „0/1 packages") und persistierter
  `agent_scan_meta.last_action_error`. Custom-Pakete bekommen denselben
  Soft-Error-Mechanismus. Nach jedem User-Click triggert das Frontend ein
  Polling auf `max(last_scan_at, last_action_at)` — alle drei Pipelines
  refreshen das UI automatisch sobald der Background-Task fertig ist.

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
| `main.py` | FastAPI-App, Lifespan (Settings-Seeding, Log-Cleanup, Session-Cleanup, **APScheduler-Start mit vier Cron-Jobs**: winget catalog refresh 01:30, winget fleet scan 02:00, choco fleet scan 02:15, winget enrichment 02:30), public endpoints (health, client-config, downloads, file-download mit signed token) |
| `config.py` | `BootstrapSettings` (pydantic, .env) + `RUNTIME_KEYS`-Dict (inkl. SSO-Settings) + `runtime_value()`/`runtime_int()`/`validate_runtime_value()` |
| `database.py` | aiosqlite-Wrapper, Migration (ALTER TABLE + automatische `_migrate_custom_packages_to_versions` + `_backfill_choco_agent_installations`), alle Queries inkl. Versions/Installations-Helper, winget-state/scan-meta/discovery-enrichment-Helper **und choco-state-Helper** |
| `auth.py` | JWT-Erzeugung (`create_machine_token`), Verify (`verify_machine_token`), Download-Token (`create_download_token`/`verify_download_token`) |
| `admin_auth.py` | Admin-Login-Logik: scrypt-Hashing, Session-Cookies, Bootstrap-Admin-Migration, Microsoft-Entra-OIDC-Flow (state cache + JWKS-Validierung) |
| `tactical_client.py` | Tactical-RMM-API-Wrapper, liest URL+API-Key bei jedem Call aus Runtime-Settings |
| `file_uploads.py` | Multipart-Upload-Streaming, SHA-256-Hashing, MSI-Metadaten via `msiinfo` (msitools) |
| `winget_catalog.py` | Lokal gemirrowter Microsoft-winget-Source. Lädt einmal pro Tag `cdn.winget.microsoft.com/cache/source.msix`, extrahiert die SQLite-Index-Datei nach `/app/data/winget_index.db`, queryed lokal mit Token-Score-Ranking und semver-aware Versionsvergleich. Exponiert `search(q)` und `get_details(id)`. |
| `winget_scanner.py` | Per-Agent winget-Inventur. `scan_agent(agent_id)` für targeted Re-Scans nach User-Aktionen, `run_nightly_scan()` für den Fleet-wide Batch (Pre-Filter via `agents.last_seen`, Concurrency-Semaphore 20, Per-Agent-Timeout 120s). Triggert via Tactical `run_command` ein PowerShell-Skript das `winget export` (für die installed-Liste, JSON, kein Truncation) + `winget upgrade` (für die available-Versionen, Text mit Truncation-toleranter Prefix-Auflösung) ausführt. Resolver für `winget.exe` aus `C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*` weil der per-user Shim unter SYSTEM nicht im PATH ist. |
| `winget_enrichment.py` | Daily Bonus-Discovery: holt die Tactical-Software-Scan Display-Namen über die ganze Flotte, dedupliziert, matcht jeden distinct Name gegen den lokalen winget-Catalog mit Confidence-Heuristik (`high`/`medium`/`low`/`none`, generic-Token-Filter für `64bit`/`x64`/`pro`/...), cached in `discovery_enrichment` mit `install_count` für die Anzeige im Aktivieren-Panel. |
| `choco_scanner.py` | Per-Agent choco-Inventur (Pendant zu `winget_scanner.py`). `scan_agent(agent_id)` für targeted Re-Scans nach User-Aktionen, `run_nightly_scan()` für den Fleet-wide Batch (Pre-Filter via `agents.last_seen`, Concurrency-Semaphore 20, Per-Agent-Timeout 180s). Triggert via Tactical run_command ein PowerShell-Skript das `choco list --limit-output` (für die installed-Liste) + `choco outdated --limit-output` (für available-Versionen) ausführt. Output ist pipe-separiert, Parser ist deterministisch. Schreibt in `agent_choco_state` und bumpt `agent_scan_meta.last_scan_at` damit das Frontend-Polling nach choco-Aktionen triggert. |
| `middleware/audit_logger.py` | HTTP-Request-Logging (fire-and-forget) |
| `middleware/csrf.py` | CSRF-Check auf state-changing Admin-Calls |
| `middleware/rate_limit.py` | In-Memory Rate-Limiter |
| `routes/register.py` | `POST /api/v1/register` mit Agent-ID + Hostname-Validierung + Token-Version-Bump |
| `routes/packages.py` | `GET /api/v1/packages` mit Installations-Detection via Tactical-Software-Scan UND `agent_winget_state`-Join für winget-Pakete (kein Tactical-Round-Trip nötig für reine winget-Setups) |
| `routes/install.py` | `POST /api/v1/install` und `/uninstall` mit type-Dispatch. **Alle drei Pipelines (custom/winget/choco) laufen jetzt einheitlich über Tactical run_command** mit PowerShell-Wrapper, output-Capture, soft-error Detection, persistierter `agent_scan_meta.last_action_error` und chained targeted Re-Scan. Helper: `_build_winget_command` + `_run_winget_command_bg` für winget, `_build_choco_command` + `_run_choco_command_bg` (mit `_detect_choco_soft_error` für Patterns wie „Likely broken for FOSS users" und 404-Download-Failures) für choco, `_build_install_command` + `_build_uninstall_command` + `_run_custom_command_bg` für custom. Custom uninstall verwendet weiter den Whitelist-`uninstall_cmd`. Alle Helper sind exportiert für die admin-getriggerten Endpoints. |
| `routes/admin.py` | Alle `/admin/api/*` Endpoints: Login/Logout/SSO, Users-CRUD, Whitelist, Upload, Versionen, Distributions, Push-Update, admin-getriggerter (Un)Install pro Agent (mit Type-Dispatch für choco/custom/winget), Settings, Build-Trigger, Reveal, Detect-Uninstall, Hilfe, **winget-search/activate/discovery/discovery-count/rescan/run-nightly/run-enrichment/winget-uninstall**, **agent-software-Endpoint** der Tactical-Scan + winget_state + Whitelist mergt und mit Token-Score-Heuristik dedupt |
| `templates/admin.html` | Single-Page Admin-UI (Vanilla JS, 7 Tabs + mehrere Slide-in-Panels + Confirm-/Passwort-Modals + **Winget-Tab im Aktivieren-Panel** + **Agent-Detail-Page** als Vollbild-Sicht im Kiosk-Clients-Tab + **Header-Discovery-Banner**) |
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
-- Kuratierte Paket-Whitelist (choco + custom + winget)
CREATE TABLE packages (
    name               TEXT PRIMARY KEY,        -- choco-Name, slug aus filename, oder winget PackageIdentifier
    display_name       TEXT NOT NULL,
    category           TEXT NOT NULL DEFAULT 'Allgemein',
    created_at         TEXT DEFAULT (datetime('now')),
    updated_at         TEXT DEFAULT (datetime('now')),
    type               TEXT NOT NULL DEFAULT 'choco',  -- 'choco' | 'custom' | 'winget'
    filename           TEXT,                    -- Spiegelt die current_version (nur custom)
    sha256             TEXT,                    -- "
    size_bytes         INTEGER,                 -- "
    install_args       TEXT,                    -- "
    uninstall_cmd      TEXT,                    -- "
    detection_name     TEXT,                    -- Windows-Display-Name für Match (nur custom)
    current_version_id INTEGER,                 -- FK auf package_versions.id (nur custom)
    archive_type       TEXT NOT NULL DEFAULT 'single',  -- 'single' | 'archive' (nur custom)
    entry_point        TEXT,                    -- relativer Pfad im Archiv (nur custom/archive)
    winget_publisher   TEXT,                    -- Cached Publisher-String (nur winget)
    winget_version     TEXT                     -- Optional fixe Version (NULL = latest, nur winget; Phase-2 UI)
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

-- Per-Agent winget-Inventur aus dem nightly Scan + targeted Re-Scans.
-- Wird bei jedem Scan komplett ersetzt (DELETE+INSERT pro Agent).
CREATE TABLE agent_winget_state (
    agent_id          TEXT NOT NULL,
    winget_id         TEXT NOT NULL,           -- z. B. 'Mozilla.Firefox'
    installed_version TEXT,
    available_version TEXT,                    -- NULL = up-to-date
    source            TEXT,                    -- 'winget' | 'msstore'
    scanned_at        TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (agent_id, winget_id)
);

-- Per-Agent choco-Inventur (Pendant zu agent_winget_state). Wird vom
-- choco_scanner geschrieben aus `choco list --limit-output` und
-- `choco outdated --limit-output`. choco_name ist der literale
-- Choco-Paket-Name (lowercase, kein Namespace wie bei winget).
CREATE TABLE agent_choco_state (
    agent_id          TEXT NOT NULL,
    choco_name        TEXT NOT NULL,
    installed_version TEXT,
    available_version TEXT,                    -- NULL = up-to-date
    scanned_at        TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (agent_id, choco_name)
);

-- Per-Agent Scan-Health: für UI-Anzeige stale-Agents, Polling nach
-- User-Aktionen, und Retry-Backoff bei consecutive_failures.
CREATE TABLE agent_scan_meta (
    agent_id              TEXT PRIMARY KEY,
    last_scan_at          TEXT,
    last_status           TEXT,                -- 'ok' | 'no_winget' | 'offline' | 'error' | 'parse_error' | 'timeout'
    last_error            TEXT,                -- human-readable
    consecutive_failures  INTEGER NOT NULL DEFAULT 0
);

-- Discovery-Bonus: Mapping Tactical-software-scan Display-Name → winget-ID
-- mit Confidence-Heuristik. Wird vom täglichen enrichment-Job geschrieben.
-- install_count = Anzahl Agents in der Flotte mit diesem Display-Namen.
CREATE TABLE discovery_enrichment (
    display_name  TEXT PRIMARY KEY,
    winget_id     TEXT,                        -- NULL wenn kein Match
    confidence    TEXT,                        -- 'high' | 'medium' | 'low' | 'none'
    install_count INTEGER NOT NULL DEFAULT 0,
    checked_at    TEXT DEFAULT (datetime('now'))
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
CREATE INDEX idx_agent_winget_id        ON agent_winget_state(winget_id);
CREATE INDEX idx_agent_winget_avail     ON agent_winget_state(available_version)
    WHERE available_version IS NOT NULL;
CREATE INDEX idx_agent_choco_name       ON agent_choco_state(choco_name);
CREATE INDEX idx_agent_choco_avail      ON agent_choco_state(available_version)
    WHERE available_version IS NOT NULL;
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
| `POST` | `/admin/api/agents/{agent_id}/install/{package_name}` | – admin-getriggerter (Re-)Install bzw. Upgrade auf einem einzelnen Agent. Dispatched nach `packages.type`: choco/custom/winget |
| `POST` | `/admin/api/agents/{agent_id}/uninstall/{package_name}` | – admin-getriggerter Uninstall auf einem einzelnen Agent. Dispatched nach `packages.type` |

**Winget:**

| Methode | Pfad | Body |
|---|---|---|
| `GET` | `/admin/api/winget/search?q=` | – Substring-Suche im lokalen winget-Catalog. Token-Score-Ranking, semver-aware "latest version", Result enthält `enabled`-Flag wenn schon whitelisted |
| `POST` | `/admin/api/winget/activate` | `{id, display_name, category, publisher?, latest_version?}` — fügt ein winget-Paket in die Whitelist ein. Fehlende Felder werden via `winget_catalog.get_details()` nachgeholt |
| `GET` | `/admin/api/winget/discovery` | – Fleet-Discovery: alle winget-IDs aus `agent_winget_state` die NICHT whitelisted sind (Primary), plus aufgelöste Tactical-software-scan Display-Namen aus `discovery_enrichment` (Bonus). Pro Eintrag: `winget_id`, `display_name`, `install_count`, `confidence`, `source` (`winget_scan` oder `tactical_scan`) |
| `GET` | `/admin/api/winget/discovery-count` | – Zahl für das Header-Banner. Wird beim Page-Load + nach jeder Aktion gefetched |
| `POST` | `/admin/api/winget/rescan/{agent_id}` | – sofortiger targeted Re-Scan eines einzelnen Agents. Setzt `consecutive_failures` zurück |
| `POST` | `/admin/api/winget/run-nightly` | – manueller Trigger für den Fleet-Scan (sonst per APScheduler 02:00 UTC) |
| `POST` | `/admin/api/winget/run-enrichment` | – manueller Trigger für den Enrichment-Job |
| `POST` | `/admin/api/agents/{agent_id}/winget-uninstall` | `{winget_id}` — `winget uninstall --id … --force` auf einem einzelnen Agent OHNE Whitelist-Pflicht. Wird vom Agent-Detail benutzt um unerwünschte unverwaltete Software runterzuhauen |

**Clients & Audit:**

| Methode | Pfad | Body |
|---|---|---|
| `GET` | `/admin/api/agents` | – (inkl. `banned`-Flag pro Agent) |
| `GET` | `/admin/api/agents/{id}/installs` | – install_log Einträge des Agents |
| `GET` | `/admin/api/agents/{id}/managed` | – per Self-Service installierte Pakete + Version-Status |
| `GET` | `/admin/api/agents/{id}/software` | – **Vereinte Software-Sicht** für die Agent-Detail-Page: Tactical-software-scan + `agent_winget_state`, dedupt mit Token-Score-Matching, pro Eintrag die Felder `name, winget_id, installed_version, available_version, publisher, source, managed, managed_type, package_name, can_activate, update_available`. Antwort enthält ausserdem `scan_meta` für das Polling nach User-Aktionen |
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

### Choco-Paket (run_command, fire-and-forget bg-task)

Seit v1.5.0 läuft choco genauso wie winget: über Tactical run_command mit
einem PowerShell-Wrapper, capture stdout, soft-error-Detection, persistierter
last_action_error, und chained Re-Scan.

```
1. softshelf.exe → POST /api/v1/install {package_name: "firefox"}
     ├─ Bearer JWT
2. Proxy: verify_machine_token → agent_id aus JWT
3. Proxy: Regex-Check + Whitelist-Lookup → type=choco
4. Proxy: _build_choco_command('install', 'firefox') baut
     PowerShell-Wrapper:
       Get-Command choco oder C:\ProgramData\chocolatey\bin\choco.exe Fallback
       & $choco install 'firefox' -y --no-progress --limit-output 2>&1
       success codes: 0, 1641 (reboot initiated), 3010 (reboot required)
       sonst: Write-Error mit ExitCode + exit $code
5. Proxy: asyncio.create_task(_run_choco_command_bg(...)) → return SOFORT
6. Proxy: log_install(...)  (audit history)
7. softshelf.exe: "Installation gestartet, dauert einige Minuten"
   (im Hintergrund:)
8. Background-Task: TacticalClient.run_command(agent_id, ps_cmd, timeout=600)
9. _detect_choco_soft_error(output, exit_code):
     - 'Likely broken for FOSS users' → "Paket erfordert Lizenz/private CDN"
     - '404' Download-Fehler → "Hersteller-Download-URL existiert nicht mehr"
     - '0/1 packages failed' → generischer Choco-Fehler
     - sonst exit != 0 → "choco beendete mit ExitCode N"
10. database.upsert_action_result(agent_id, package_name, error_msg)
    → schreibt agent_scan_meta.last_action_error für UI-Banner
11. Bei Erfolg: database.set_agent_installation(agent_id, package_name, NULL)
    → tracking-Eintrag damit Pass 3 das Paket deterministisch matched
12. choco_scanner.scan_agent(agent_id) wird sofort danach getriggert
    → ersetzt agent_choco_state Rows komplett, bumpt scan_meta.last_scan_at
13. Frontend-Polling sieht den Fingerprint sich bewegen → Refresh,
    Banner mit Fehlermeldung erscheint falls error_msg gesetzt
```

### Choco-Scan (nightly + targeted)

```
APScheduler 02:15 UTC → choco_scanner.run_nightly_scan()
  ├─ database.get_agents_due_for_scan(online_threshold=300, skip_failures>=7)
  ├─ asyncio.Semaphore(20)
  └─ Pro Agent (parallel max 20):
       └─ scan_agent(agent_id, timeout=180)
            ├─ TacticalClient.run_command mit dem Scan-Skript:
            │     - Find $choco (PATH oder C:\ProgramData\...)
            │     - choco list --limit-output --no-progress
            │     - choco outdated --limit-output --no-progress
            │     - ConvertTo-Json {ok, list_text, outdated_text}
            ├─ parse_scan_payload(text)
            │     - Doppel-Decode (Tactical wrappt stdout als JSON-string)
            │     - list_text per pipe parsen → installed[name] = version
            │     - outdated_text per pipe → upgradable[name] = available
            │     - state_rows mit (choco_name, installed_version, available_version)
            ├─ database.replace_agent_choco_state(agent_id, state_rows)
            └─ database.upsert_scan_meta(agent_id, status='ok')
```

Targeted Re-Scan ist exakt derselbe Code-Pfad, einmalig pro Agent statt
über die ganze Flotte. Wird nach jeder Choco-Aktion gechained.

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

### Winget-Paket

Winget-Pakete laufen über denselben Tactical-`run_command`-Kanal wie custom,
brauchen aber keine signierte Download-URL — winget zieht den Installer selbst
aus seinem konfigurierten Source-Repository.

```
1. softshelf.exe → POST /api/v1/install {package_name: "Mozilla.Firefox"}
2. Proxy: verify_machine_token + Whitelist-Lookup → type=winget
3. Proxy: agent_winget_state lesen → schon installiert mit available_version?
     → Ja: action='upgrade'
     → Nein: action='install'
4. Proxy: _build_winget_command(action, "Mozilla.Firefox", winget_version)
     baut PowerShell-Wrapper:
       Find-WingetExe (PATH-Lookup, Fallback C:\Program Files\WindowsApps\
                       Microsoft.DesktopAppInstaller_*_x64__*\winget.exe)
       & $wingetExe install --id 'Mozilla.Firefox' --scope machine --silent
                            --accept-package-agreements --accept-source-agreements
                            --disable-interactivity -h
       Tolerant gegenüber Exit-Codes 0, -1978335212 (bereits installiert),
                                       -1978335189 (no upgrade available)
5. Proxy: asyncio.create_task(_run_winget_command_bg(...)) → return SOFORT
6. Background-Task: TacticalClient.run_command(agent_id, ps_cmd, timeout=600)
     └─ POST https://tactical/agents/{id}/cmd/  (run_as_user=False, also SYSTEM)
7. Tactical-Agent: Find-WingetExe → winget install/upgrade läuft als SYSTEM
8. Background-Task wartet auf Tactical-Response (sync), egal ob Erfolg oder Fehler:
     → winget_scanner.scan_agent(agent_id) wird sofort danach getriggert
       (targeted Re-Scan via winget export + winget upgrade)
     → ersetzt agent_winget_state Rows für diesen Agent komplett
     → schreibt agent_scan_meta.last_scan_at = jetzt
9. Admin-UI pollt /admin/api/agents/{id}/software jede 5s und vergleicht
   scan_meta.last_scan_at gegen den Snapshot vom Klick-Zeitpunkt
   → sobald sich der Timestamp bewegt: automatischer Refresh der Sicht
```

**Resolver-Hintergrund:** `Get-Command winget` unter SYSTEM findet nichts, weil
der per-user-Shim in `%LocalAppData%\Microsoft\WindowsApps\winget.exe` lebt und
SYSTEM kein Profil-Mapping hat. Die echte Binary in `C:\Program Files\WindowsApps\
Microsoft.DesktopAppInstaller_*_x64__*\winget.exe` ist von SYSTEM aber lesbar
(WindowsApps-ACLs blocken nur reguläre User). Der Find-WingetExe-Helper macht
beide Pfade durch.

### Winget-Scan (nightly + targeted)

Das ist der zweite Datenfluss-Pfad für winget — nicht User-getriggert sondern
periodisch, schreibt aber denselben State.

```
APScheduler 02:00 UTC → run_nightly_scan()
  ├─ database.get_agents_due_for_scan(online_threshold=300, skip_failures>=7)
  │   → Liste online Kiosk-Clients, gebannte Agents geskippt,
  │     Agents mit hoher Failure-Rate temporär ausgeschlossen
  ├─ asyncio.Semaphore(20)
  └─ Pro Agent (parallel max 20):
       └─ scan_agent(agent_id, timeout=120)
            ├─ TacticalClient.run_command mit dem Scan-Skript:
            │     - Find-WingetExe
            │     - winget export -o /tmp/x.json --include-versions
            │     - $installedJson = [System.IO.File]::ReadAllText($exportPath)
            │     - winget upgrade (Text-Output für Available-Versionen)
            │     - ConvertTo-Json {ok, installed_json, upgradable}
            ├─ parse_scan_payload(text)
            │     - Doppel-Decode (Tactical wrappt stdout als JSON-string)
            │     - winget export JSON parsen → kanonische installed-Liste
            │     - winget upgrade Text-Tabelle parsen, Truncation tolerant
            │       via Prefix-Auflösung gegen die installed-IDs
            │     - state_rows mit (winget_id, installed_version, available_version)
            ├─ database.replace_agent_winget_state(agent_id, state_rows)
            │     → DELETE FROM agent_winget_state WHERE agent_id=?
            │     → INSERT alle neuen Rows
            └─ database.upsert_scan_meta(agent_id, status='ok', ...)
                  → Falls 'no_winget' Error: status='no_winget', state=[] (leer)
                  → Falls Tactical-Fehler: status='error', consecutive_failures++
```

Targeted Re-Scan ist exakt derselbe Code-Pfad, nur einmalig pro Agent statt
über die ganze Flotte. Wird nach jeder Install/Upgrade/Uninstall-Aktion
gechained UND vom „Neu scannen"-Button im Agent-Detail.

### Discovery-Enrichment-Job (täglich)

```
APScheduler 02:30 UTC → run_enrichment_job()
  ├─ Catalog Cache Refresh (winget_catalog.refresh_cache)
  │     → einmalig bei stale Cache (TTL 24h)
  ├─ collect_fleet_software()
  │     → Tactical.get_installed_software() für alle online Agents (Semaphore 15)
  │     → Aggregation: dict[normalized_name → {display_name, publisher, count}]
  ├─ database.reset_enrichment_counts()  → install_count=0 für alle Rows
  └─ Pro distinct display_name:
       ├─ Cache-Check via database.get_enrichment(display_name)
       │     → Wenn frisch UND winget_id whitelisted: nur count updaten
       ├─ Sonst: winget_catalog.search(normalized) → Top-Treffer pro Confidence
       │     → confidence ∈ {high, medium, low, none}
       ├─ database.upsert_enrichment(display_name, winget_id, confidence, count)
       └─ asyncio.sleep(0.2)  ← Rate-Limit gegen den lokalen Cache (nicht nötig,
                                aber paranoid für CPU-Lastverteilung)

  → database.cleanup_stale_enrichment(days=30) löscht Einträge mit
    install_count=0 und checked_at älter als 30 Tage
```

Resultat: `discovery_enrichment` ist eine angereicherte Sicht auf die Tactical-
Software-Scans der ganzen Flotte mit aufgelösten winget-IDs für die meisten
Display-Namen — Grundlage für den Discovery-Block im Aktivieren-Panel.

### Uninstall (choco + custom + winget)

- **Choco:** `_build_choco_command('uninstall', name)` → run_command mit
  `choco uninstall '<name>' -y --no-progress --limit-output`. Output wird
  capturet, Soft-Errors detected, last_action_error persistiert,
  `delete_agent_installation` aufgerufen, choco_scanner.scan_agent
  gechained. Identisch zum Install-Pfad.
- **Custom:** fire-and-forget, ausgeführt wird der beim Upload gespeicherte `uninstall_cmd`
  via `cmd /c` gewrappt in PowerShell (Exit-Code-Propagation + Tolerant bei 3010/1605).
  Bei Erfolg → `delete_agent_installation(agent_id, name)` entfernt den Tracking-Eintrag.
  Bei Exception → `upsert_action_result` mit Fehlertext für UI-Banner.
- **Winget (verwaltet):** `_build_winget_command('uninstall', winget_id)` erzeugt
  einen PowerShell-Wrapper um `winget uninstall --id … --silent --force
  --accept-source-agreements --disable-interactivity -h`. Fire-and-forget via
  Tactical, danach targeted Re-Scan. Tolerant gegenüber Exit-Code 0,
  -1978335212, -1978335189. Exit-Code -1978335162 (`NO_UNINSTALL_INFO_FOUND`)
  wird mit klarer Fehlermeldung gepropagiert — passiert bei per-user-Apps und
  Microsoft-Store-Apps die SYSTEM nicht entfernen kann.
- **Winget (unverwaltet, ohne Whitelist):** `POST /admin/api/agents/{id}/winget-uninstall`
  mit Body `{winget_id}`. Skippt den Whitelist-Check und ruft direkt
  `_build_winget_command('uninstall', …)` → Tactical-Dispatch. Wird vom
  Agent-Detail benutzt um Software wegzuräumen die NICHT in der Softshelf-
  Whitelist ist (z.B. eine winget-installierte App die der User selbst
  installiert hat).

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
| **Pakete** | Whitelist-Management: Choco-/Winget-Suche, Upload, Edit (inkl. Versions-Liste + Push-Update + Installations-View pro Paket), Delete. Pro Karte ein Source-Tag (`Chocolatey` / `Winget` / `Eigenes Paket` / `Programm-Ordner`) |
| **Verteilung** | Cross-package Übersicht: pro custom-Paket eine Karte mit allen Geräten + ihrer Version + Update-/Entfernen-Buttons pro Zeile + Push-all für Outdated |
| **Kiosk-Clients** | Liste registrierter Agents, Online-Status. Klick auf eine Zeile öffnet die **Agent-Detail-Page** als Vollbild-Sicht (siehe unten) |
| **Audit-Log** | Letzte 200 HTTP-Requests, Filter auf Pfad/IP |
| **Benutzer** | Admin-User-Verwaltung (lokal + SSO), Last-Login-Anzeige, Aktiv-Toggle |
| **Einstellungen** | Runtime-Settings-Editor (inkl. SSO-Sektion), Reveal für Secrets, Build-Button + Historie |
| **Hilfe** | Aufgaben-orientierte Admin-Dokumentation (lazy loaded HTML-Fragment) |

**Slide-in-Panels:**
- Such-Panel (Aktivieren) mit vier Tabs: **Aus Chocolatey**, **Aus Winget**, **Eigene Datei**, **Programm-Ordner**
  - Winget-Tab: Catalog-Suche im lokalen `winget_index.db` mit Inline-Aktivieren-Button, plus aufklappbarer **Discovery-Block** „In der Flotte gefunden" mit allen unverwalteten winget-IDs (Primary aus `agent_winget_state`, Bonus aus `discovery_enrichment` mit Confidence-Badges)
- Kategorie-Picker
- Custom-Paket Edit-Panel (inkl. Versions-Sektion: Liste + Set-Current + Delete + Inline-Upload neuer Versionen + Installations-Liste pro Paket + Push-Update-Button)
- User-Edit-Panel (Anlegen + Bearbeiten)

**Agent-Detail-Page** (statt Slide-in seit v1.4.0):

| Bereich | Inhalt |
|---|---|
| Header-Toolbar | Back-Button, Hostname (mit `· GESPERRT`-Suffix bei Bann), Agent-ID, Aktion-Buttons: **Neu scannen** (manueller winget-Rescan mit Reset von consecutive_failures), **Token widerrufen**, **Sperren** / **Entsperren**, **Löschen** |
| Installierte Software | Vereinte Liste aus Tactical-Software-Scan + `agent_winget_state`, dedupt mit Token-Score-Matching. Pro Row: Display-Name, Source-Badges (`verwaltet · winget` / `verwaltet · choco` / `verwaltet · eigen` / `winget · unverwaltet` / `unverwaltet`), Update-Hinweis, Sub-Zeile mit `winget_id` + Version + Publisher, Aktion-Buttons. Sortierung: Updates zuerst, dann verwaltet, dann unverwaltet |
| Aktion-Buttons pro Row | **Updaten** (managed + update_available, ruft `winget upgrade`), **Deinstallieren** (managed), **Aktivieren** (unmanaged winget, ruft `/admin/api/winget/activate`), **Entfernen** (unmanaged winget, ruft `/admin/api/agents/{id}/winget-uninstall` ohne Whitelist) |
| Polling | Nach jedem Klick wird die Row mit Spinner gesperrt und das UI pollt `/admin/api/agents/{id}/software` alle 5s. Vergleich `scan_meta.last_scan_at` gegen Snapshot vom Klick-Zeitpunkt. Sobald sich der Timestamp bewegt: automatischer Refresh. 6-Minuten Hartstop |
| Installations-Verlauf | Bisheriger `install_log` für diesen Agent (install/uninstall Audit) |

**Header-Discovery-Banner:**
- Erscheint im `hdr-meta` rechts neben Version + User-Menu wenn `GET /admin/api/winget/discovery-count` eine Zahl > 0 liefert
- Klick öffnet das Aktivieren-Panel direkt auf dem Winget-Tab mit expandiertem Discovery-Block
- Wird nach jeder Activate-/Aktion neu gefetched

**Modals:**
- Confirm-Action (parametrisierbarer Button-Label und -Style)
- Passwort-Ändern (Live-Strength-Indicator + Match-Validation)
- Ban-Reason-Modal (separates kleines Modal vor dem `agentBan()`-Call)

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
│   ├── requirements.txt        fastapi, uvicorn, httpx, PyJWT, aiosqlite,
│   │                           python-multipart, apscheduler
│   ├── main.py                 App-Setup, Lifespan inkl. APScheduler-Wiring,
│   │                           public endpoints
│   ├── config.py               Bootstrap + RUNTIME_KEYS
│   ├── database.py             SQLite + Migration + Helpers (inkl. winget-state,
│   │                           scan-meta, discovery-enrichment)
│   ├── auth.py                 JWT (Machine-Token + Download-Token)
│   ├── tactical_client.py      Tactical-RMM-API-Wrapper
│   ├── file_uploads.py         MSI-Parsing + File-Storage
│   ├── winget_catalog.py       Lokal gemirrowter Microsoft-winget-Source mit
│   │                           SQLite-Index, semver-Sortierung
│   ├── winget_scanner.py       Per-Agent winget-Inventur (nightly + targeted)
│   ├── winget_enrichment.py    Tactical-Scan → winget-id Matcher (täglich)
│   ├── choco_scanner.py        Per-Agent choco-Inventur (nightly + targeted),
│   │                           parsed `choco list` + `choco outdated`
│   ├── middleware/
│   │   ├── audit_logger.py
│   │   ├── csrf.py
│   │   └── rate_limit.py
│   ├── admin_auth.py           scrypt + Sessions + Microsoft-Entra-OIDC
│   ├── routes/
│   │   ├── register.py
│   │   ├── packages.py         /api/v1/packages mit winget-state-Join
│   │   ├── install.py          /api/v1/install + /uninstall mit Type-Dispatch
│   │   │                       (choco/custom/winget) + targeted Re-Scan
│   │   └── admin.py            (~2200 Zeilen, alle admin-Endpoints inkl.
│   │                           Versionierung, Distribution, Winget,
│   │                           Agent-Detail-Software-Endpoint)
│   └── templates/
│       ├── admin.html          Single-Page Admin-UI (7 Tabs +
│       │                       Agent-Detail-Page + Winget-Tab + Discovery-Banner)
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
│   ├── softshelf.db            SQLite (state, settings, packages, …)
│   ├── winget_index.db         Lokaler Mirror der Microsoft-winget-Source
│   │                           (täglich von cdn.winget.microsoft.com gezogen)
│   └── uploads/                Custom MSI/EXE Files (sha256-named)
│
└── downloads/                  (Volume, shared proxy+builder)
    ├── softshelf.exe           vom Builder erzeugt
    └── softshelf-setup.exe     vom Builder erzeugt
```

---

## Offene Punkte / TODO

| Item | Priorität | Aufwand | Notiz |
|---|---|---|---|
| **TLS vor dem Proxy** | hoch | klein | via Caddy/Traefik Reverse-Proxy. Session-Cookie ist HttpOnly+Strict, aber HTTP exponiert ihn auf Layer-7 |
| **Winget run_as_user-Fallback** | mittel | mittel | per-user / Microsoft-Store winget-Pakete lassen sich aus SYSTEM-Kontext nicht entfernen (Exit-Code -1978335162 NO_UNINSTALL_INFO_FOUND, oder „No available upgrade found" für `--scope machine`-gefilterte Per-User-Installs). Lösung: optional `run_as_user=True` an Tactical run_command übergeben wenn ein User eingeloggt ist, mit Retry-Logik nach SYSTEM-Failure. Würde dann für choco genauso gelten. |
| **Winget-Version-Pinning UI** | niedrig | klein | `packages.winget_version`-Spalte existiert bereits, Dispatch-Code unterstützt `--version`, fehlt nur ein Picker im Aktivieren-/Edit-Panel |
| **Choco-Catalog-Suche im Aktivieren-Flow** | niedrig | mittel | Aktuell suchen wir choco-Pakete via Tactical's `/software/chocos/` Endpoint der nur Namen liefert (kein Title, kein Description). Eleganter wäre direkt gegen die chocolatey.org OData-API zu queryen mit Title-Anzeige im Aktivieren-Panel — analog zum lokalen winget-Catalog. |
| **Choco-Discovery analog zu winget** | niedrig | mittel | Genauso wie das winget-Discovery: aus `agent_choco_state` die installierten Pakete der ganzen Flotte sammeln die noch nicht in der Whitelist sind, im Aktivieren-Panel als „in der Flotte gefunden"-Block anzeigen, ein-Klick aktivieren. |
| Tactical-Software-Scan ARP-Direct-Uninstall | niedrig | mittel | Für unverwaltete tactical-only Software einen Uninstall-Pfad via ARP `UninstallString` anbieten — derzeit nur winget-IDs uninstallable im Agent-Detail |
| Discovery-Confidence-Tuning | niedrig | klein | Das Token-Score-Matching gegen den winget-Catalog hat Edge-Cases mit generischen Tokens (`microsoft`, `office`). Die generic-Token-Liste in `routes/admin.py:_GENERIC_WINGET_TOKENS` kann nach Bedarf erweitert werden |
| One-Time-Registration-Tokens | mittel | mittel | aktuell durch Rate-Limit + `min_length=16` mitigiert |
| Auto-Refresh von Machine-Tokens | niedrig | mittel | aktuell: `token_ttl_days=0` für unbegrenzt, oder Re-Deploy |
| pytest für Proxy + Smoke-Tests Client | niedrig | groß | |
| Sortierbare Spalten in Tabellen | niedrig | klein | kosmetisch |
| Pagination im Install-Log | niedrig | klein | aktuell `LIMIT 200` |
| Build-Log-Streaming (statt Polling) | niedrig | mittel | SSE oder WebSocket |
| Backfill Tracking aus install_log | niedrig | klein | optionales One-Off zum Vorbefüllen von `agent_installations` aus historischen install-Aktionen |
