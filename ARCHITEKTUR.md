# Softshelf – Systemarchitektur

**Version:** 2.0.2
**Stand:** 2026-04-16

> **Softshelf ist eine Windows-Software-Verteilungs-Plattform** mit Tactical-
> RMM-Basis. Kern-Features: gestufte Rollouts, RBAC, Compliance-Policy,
> Wartungsfenster, optionaler User-Self-Service. Frühere Positionierung als
> „Self-Service-Portal" war zu eng — seit v2.0 ist Self-Service nur eines von
> mehreren Deployment-Wegen neben Profil-Anwendung, Rollouts und
> Compliance-Enforcement.

## Inhaltsverzeichnis

1. [Überblick](#überblick)
2. [Komponenten](#komponenten)
3. [Deployment-Wege](#deployment-wege-fuer-software)
4. [Datenbank-Schema](#datenbank-schema)
5. [Authentifizierung & RBAC](#authentifizierung--rbac)
6. [Paket-Pipelines](#paket-pipelines)
7. [Phased Rollouts](#phased-rollouts)
8. [Background-Jobs](#background-jobs-apscheduler)
9. [API-Referenz](#api-referenz)
10. [Security-Modell](#security-modell)
11. [Deployment](#deployment)

---

## Überblick

Softshelf kombiniert Admin-getriebene Software-Verteilung mit einem
optionalen End-User-Kiosk. Deploy-Grundlage ist [Tactical RMM](https://github.com/amidaware/tacticalrmm) — Softshelf
dispatch Installs/Uninstalls über dessen `run_command`-API.

```
┌────────────────────────────────────────────────────────────────┐
│ docker-compose Stack (Linux-Host)                              │
│                                                                │
│   ┌──────────────────┐       internal HTTP     ┌─────────────┐ │
│   │ softshelf-proxy  │───────────────────────▶│ softshelf-  │ │
│   │ FastAPI+SQLite   │                         │ builder     │ │
│   │ APScheduler (8)  │                         │ Wine +      │ │
│   │ Port 8765        │                         │ PyInstaller │ │
│   └────────┬─────────┘                         │ Port 8766   │ │
│            │                                   └─────────────┘ │
│            │ HTTPS                                             │
│            ▼                                                   │
│   ┌──────────────────┐                                         │
│   │ Tactical RMM API │                                         │
│   └──────────────────┘                                         │
└────────────────────────────────────────────────────────────────┘
             │                            │
             │ /api/v1/* (Machine-JWT)    │ Agent-Script
             ▼                            ▼
   ┌──────────────────────────────────────────────────┐
   │  Windows-Clients                                 │
   │  - Softshelf.exe (Tray, PyQt5 + pystray)         │
   │  - Tactical-Agent (installiert Software als      │
   │    SYSTEM via run_command)                       │
   └──────────────────────────────────────────────────┘
```

---

## Komponenten

### softshelf-proxy

FastAPI-Server, SQLite-Datenbank (aiosqlite), APScheduler für
Background-Jobs. Auf dem Host unter `/opt/softshelf/`.

| Datei | Verantwortung |
|---|---|
| `main.py` | FastAPI-Lifespan, Routing-Wiring, **8 APScheduler-Jobs**, public Endpoints. |
| `database.py` | Alle SQL + Schema-Migrations (ALTER TABLE add-column idempotent), aiosqlite-Wrapper `_db()` mit PRAGMA `foreign_keys=ON`. |
| `config.py` | `BootstrapSettings` (pydantic, `.env`) + `RUNTIME_KEYS` dict. Runtime-Settings inkl. Rollout-Policy (Ring-Labels, Auto-Advance-Wartezeiten, Max-Fehler-Rate). |
| `auth.py` | Machine-Token JWT (HS256), Download-Token. |
| `admin_auth.py` | scrypt-Passwörter, Sessions, Microsoft-Entra-OIDC. |
| `file_uploads.py` | MSI/EXE/Ordner-Uploads, msiinfo-Metadata, ZIP-Handling. |
| `tactical_client.py` | Tactical RMM API wrapper — `run_command` mit `run_as_user`-Flag. |
| `winget_catalog.py` | Lokal gemirrowter Microsoft-winget-Source (täglich cdn.winget.microsoft.com). |
| `winget_scanner.py` | Per-Agent winget-Inventur via `winget export` + `winget upgrade`. |
| `choco_scanner.py` | Per-Agent choco-Inventur. |
| `winget_enrichment.py` | Nightly: Tactical-Software ↔ winget-Catalog Matching. |
| `middleware/csrf.py` | CSRF-Schutz für state-changing Methoden. |
| `middleware/rate_limit.py` | Per-IP Rate-Limiting mit separaten Buckets für Login / Admin-API / Register. |
| `middleware/audit_logger.py` | HTTP-Request-Log. |
| `routes/register.py` | `POST /api/v1/register`. |
| `routes/packages.py` | `GET /api/v1/packages` — Kiosk-API mit **Phased-Rollout-Gate** (Updates nur sichtbar wenn Rollout-Phase den Agent-Ring erreicht hat) und **Hide-in-Kiosk-Filter**. |
| `routes/install.py` | `/install` + `/uninstall` — Type-Dispatch mit Layer-2-Scope-Fallback (winget) und Ghost-Repair (choco). |
| `routes/admin.py` | ~4300 Zeilen — alle `/admin/api/*`, RBAC-Gate, Rollout-State-Machine, Scheduled-Jobs, Compliance, Stage-Picker, Agent-Assign-Picker. |
| `templates/admin.html` | Single-Page Admin-UI (~9500 Zeilen). Sidebar-Navigation, Dark-Mode, Cmd+K, 13 Tabs. |
| `templates/admin_help.html` | In-App-Hilfe. |

### softshelf-builder

Ubuntu+Wine+PyInstaller Container. Baut `<slug>.exe` (Tray) und `<slug>-setup.exe` (Installer) cross-compile aus Python-Source.

### Client-Binaries

- **`<slug>.exe`** — PyQt5-Tray-App mit Paket-Grid, Install/Update/Uninstall, Health-Monitor
- **`<slug>-setup.exe`** — tkinter-Installer, Session-aware-Launch via Task-Scheduler-Trick, Apps-&-Features-Integration

---

## Deployment-Wege für Software

Softshelf bietet **vier** Wege, Software auf Clients zu bringen —
Admin wählt situativ den passenden:

| Weg | Wann nutzen | Admin-Aufwand |
|---|---|---|
| **User-Self-Service** | Opt-in-Software, User entscheidet | Paket whitelisten, fertig |
| **Profile-Apply** | Team-/Rollen-spezifische Standard-Software | Profil bauen, Agents zuweisen |
| **Phased Rollout** | Breiter Rollout mit Risiko-Minimierung | Als Phased Rollout markieren, Ringe konfigurieren |
| **Compliance-Enforcement** | Sicherheitsrelevante Pflicht-Software | Als required markieren, Fix-Button |

Plus: **Wartungsfenster** zur zeitgesteuerten Ausführung aller obigen.

---

## Datenbank-Schema

SQLite unter `/app/data/softshelf.db`. Migrations idempotent via
`ALTER TABLE ADD COLUMN`-Checks.

### Kern-Tabellen

```
agents
  agent_id      PK        -- Tactical Agent-ID
  hostname
  registered_at
  last_seen
  token_version             -- JWT-Revocation
  ring          INTEGER    -- 1=Canary, 2=Pilot, 3=Produktion (Default)

agent_blocklist
  agent_id      PK
  banned_at, reason

packages
  name          PK
  display_name
  category
  type          TEXT       -- 'choco' | 'winget' | 'custom'
  filename, sha256, size_bytes
  install_args, uninstall_cmd, detection_name
  current_version_id         -- FK package_versions (nur custom)
  archive_type, entry_point
  winget_version              -- Version-Pin (NULL = latest)
  winget_publisher
  winget_scope                -- 'auto'|'machine'|'user'
  required      INT           -- Compliance-Flag
  staged_rollout INT          -- Phased-Rollout-Pflicht-Flag
  auto_advance  INT           -- Auto-Mode pro Paket (v2.0)
  hidden_in_kiosk INT         -- Kiosk-Grid ausblenden (v2.0)
  notes         TEXT          -- Admin-Notizen

package_versions
  id            PK
  package_name, version_label, sha256, uploaded_at, ...

agent_installations       -- Custom-Paket-Tracking
  agent_id, package_name PK
  version_id, installed_at

agent_winget_state        -- Winget-Inventur
  agent_id, winget_id PK
  installed_version, available_version, scanned_at

agent_choco_state         -- Analog zu winget
  agent_id, choco_name PK
  ...

agent_scan_meta           -- Per-Agent Scan/Action-Metadaten
  agent_id               PK
  last_scan_at
  last_action_at, _package, _action
  last_action_error, _full_output
  last_action_error_acked_at
```

### Profile & Compliance

```
profiles                  -- Paket-Bundles
  id, name, description, color
  auto_update INT            -- nightly Auto-Update

profile_packages
  profile_id, package_name FK
  sort_order, version_pin

agent_profiles
  agent_id, profile_id FK
  assigned_at
```

### Rollouts & Scheduling

```
rollouts                  -- Phased-Rollout State-Machine
  id                 PK
  package_name       FK
  display_name, action
  current_phase      -- 1 | 2 | 3 | >3=done
  status             -- active | done | cancelled
  created_at, created_by
  last_advanced_at
  phase_history      JSON  -- [{phase, at, auto?}]

scheduled_jobs            -- Wartungsfenster
  id, run_at, action_type
  action_params      JSON
  description, status
  executed_at, result
```

### Admin-RBAC

```
admin_users
  id, username UNIQUE
  display_name, email, password_hash
  sso_provider, sso_subject
  role        -- 'admin' | 'operator' | 'viewer'
  is_active, created_at, last_login

admin_sessions
  token PK, user_id, expires_at, last_active
```

---

## Authentifizierung & RBAC

### Machine-Tokens (Kiosk-Client)

JWT HS256, Claim `{agent_id, hostname, token_version}`. Revoke via
`bump_token_version` oder `agent_blocklist`.

### Admin-Sessions

`POST /admin/login` (local oder Entra-OIDC) → HttpOnly-Cookie,
`SameSite=Lax`, `Secure` bei X-Forwarded-Proto=https. Expiry nach
`token_ttl_days`.

### RBAC-Matrix (v2.0)

| Rolle | Darf | Darf nicht |
|---|---|---|
| `admin` | alles | — |
| `operator` | Dispatch (Install/Uninstall/Update-All/Push-Update/Bulk), Profile anwenden, Rollouts starten/weiterschalten/pausieren/abbrechen, Fehler bestätigen | Whitelist-Edit, Benutzer, Einstellungen, Builds, Paket-Flags (required/staged/hidden/auto_advance), Ring-Mutation, Wartungsfenster |
| `viewer` | alle GETs + CSV-Export | jegliche state-changing Operations |

**Implementierung**: Zentraler Check in `_require_admin` (routes/admin.py):
Path-Prefix-Match gegen `_ADMIN_ONLY_PATHS` + Exception-Suffix-Liste für
operator-erlaubte Dispatch-Aktionen.

### Rate-Limiting (v1.7.2 getrennte Buckets)

| Bucket | Limit/min | Zweck |
|---|---|---|
| `/api/v1/register` | 5 | Registration-Brute-Force |
| `/admin/login` | 10 | Login-Brute-Force |
| `/admin/api/*` | 600 | SPA mit parallelen Calls |
| `/admin/*` | 120 | Admin-Portal HTML + Assets |

---

## Paket-Pipelines

Alle drei Pipelines (winget/choco/custom) nutzen das gleiche Dispatch-
Pattern: PowerShell-Wrapper über Tactical `run_command`, Output-Capture
via `===SOFTSHELF_EXIT===`-Marker, Soft-Error-Detection, Persist in
`agent_scan_meta.last_action_error`.

### Winget (Layer-2 Scope-Fallback)

`packages.winget_scope`:
- `auto` (Default): erst SYSTEM + `--scope machine`, bei
  `-1978335216` (NO_APPLICABLE_INSTALLER) retry ohne Scope mit
  `run_as_user=True`
- `machine`: nur SYSTEM
- `user`: direkt User-Kontext — für LastPass, Bitwarden, Firefox-per-user

Layer-1 Success-Hints: `"no newer package versions"` zählt als Erfolg.

### Choco (Ghost-Repair)

Uninstall mit `--force --skip-autouninstaller --remove-dependencies` —
repariert Fälle wo `lib/<pkg>/` vorhanden aber App weg.

Success-Codes: `0`, `1641` (reboot initiated), `3010` (reboot required).

### Custom

PowerShell-Template je archive_type (MSI/EXE/ZIP). Download via signed
JWT-URL (`/api/v1/file/{sha256}?token=...`), Agent exekutiert, ExitCode
propagiert.

### Phased-Rollout-Gate (Kiosk-API, v2.0)

Wenn `packages.staged_rollout=1`:
- Kein aktiver Rollout → `update_available=false` im Kiosk-Response
- Aktiver Rollout → `update_available` nur wenn `rollout.current_phase >= agent.ring`

Damit sehen Agents updates erst wenn ihr Ring an der Reihe ist.

---

## Phased Rollouts

### State-Machine

```
Admin markiert Paket als staged
       │
       ▼
┌── Mode M (manuell) ──────────┐  ┌── Mode A (auto_advance=1) ──┐
│ Admin klickt „Rollout starten"│  │ Auto-Start-Tick alle 15 Min:  │
│ → Rollout anlegen             │  │ prüft staged+auto Pakete      │
│ → Phase 1 ausgelöst           │  │ ohne aktiven Rollout + mit    │
│                               │  │ has_updates → Rollout anlegen │
└───────────────┬───────────────┘  └───────────────┬───────────────┘
                │                                  │
                ▼                                  ▼
          Phase 1 active                     Phase 1 active
                │                                  │
  Admin „Weiter"                         Auto-Advance-Tick alle 15 Min:
                │                        │ - Wartezeit hours_1_to_2 um?
                ▼                        │ - Fehler unter max_error_pct?
          Phase 2 active                 │ - Paket hat auto_advance=1?
                │                        │ → advance zu Phase 2
  Admin „Weiter"                         │
                ▼                        ▼
          Phase 3 (Produktion)
                │
                ▼
            status=done
            (Mode A: wartet auf nächste Version → Loop)
```

### Cancel-Semantik

- Mode M: Cancel → rollout.status=cancelled
- Mode A: Cancel → rollout.status=cancelled **+** `auto_advance=0` auf Paket
  (verhindert sofortigen Neustart durch Auto-Start-Tick)

### Pause-auto

Mode A Running hat zusätzlich `[Pause auto]`-Button:
`auto_advance=0` auf Paket, Rollout bleibt active → wird zu Mode M
(Admin advanced manuell weiter).

### Phase → Ring-Mapping

| Phase | Dispatcht an Ring | Stage-Name |
|---|---|---|
| 1 | ring=1 | ring1 (Canary) |
| 2 | ring=2 | ring2 (Pilot) |
| 3 | ring=3 | ring3 / prod (Produktion) |

### Wartezeiten

`rollout_auto_advance_hours_1_to_2` (Default 24h) und
`rollout_auto_advance_hours_2_to_3` (Default 168h = 7d) getrennt
konfigurierbar.

### Fehler-Rate-Gate

`rollout_max_error_pct` (Default 0):
- `0` = jeder einzelne Fehler blockt Auto-Advance
- `>0` = Auto-Advance blockt wenn `offene_Fehler/Agents-in-Phase > Schwelle`

---

## Background-Jobs (APScheduler)

| Job-ID | Trigger | Zweck |
|---|---|---|
| `winget_catalog_refresh` | Cron 01:30 | Download `source.msix` |
| `winget_nightly_scan` | Cron 02:00 | Flotten-winget-Inventur |
| `choco_nightly_scan` | Cron 02:15 | Flotten-choco-Inventur |
| `winget_enrichment` | Cron 02:30 | Tactical-Software ↔ Catalog |
| `profile_autoupdate` | Cron 03:00 | Profile mit `auto_update=1` |
| `scheduled_jobs_tick` | Intervall 1 Min | Wartungsfenster |
| `rollout_auto_advance` | Intervall 15 Min | Phasen-Advancement (per-Paket) |
| `rollout_auto_start` | Intervall 15 Min | Auto-Rollout-Start (v2.0) |

Alle mit `max_instances=1, coalesce=True`.

---

## API-Referenz

### Kiosk-Client (`/api/v1/*`, Machine-JWT)

- `POST /register` — Onboarding
- `GET /packages` — Whitelist mit pro-Agent-State, respektiert Phased-Rollout-Gate + Hide-in-Kiosk
- `POST /install` / `POST /uninstall`
- `GET /health`, `GET /client-config`
- `GET /download/{filename}`, `GET /file/{sha256}?token=`

### Admin-API (`/admin/api/*`, Session-Cookie, RBAC-gegatet)

**Home/Monitoring:**
- `GET /dashboard`, `/fleet-errors`, `/ack-error`, `/fleet-errors/ack-all`
- `GET /agents/{id}/last-action-output`, `POST /agents/{id}/ack-error`

**Pakete:**
- `GET /enabled`, `POST /enable`, `PATCH /enable/{name}`, `POST /disable/{name}`
- `POST /upload`, `POST /upload-folder`, Versions-Endpoints
- `PATCH /packages/{name}/required` · `/staged` · `/notes` · `/hidden` · `/auto-advance`
- `PATCH /winget/{name}/scope` · `/version-pin`
- `POST /winget/activate`, `/winget/bulk-activate`
- `POST /packages/{name}/push-update?stage=` *(operator OK)*
- `POST /packages/{name}/update-all?stage=` *(operator OK)*

**Verteilung & Compliance:**
- `GET /distributions?q=&type=&outdated_only=&sort=&offset=&limit=`
- `GET /packages/{name}/agents?q=&outdated_only=`
- `POST /distributions/bulk` *(operator OK)*
- `GET /compliance`, `POST /compliance/fix?stage=` *(operator OK)*

**Rollouts:**
- `GET /rollouts/staged-overview` — Hauptendpoint für Rollouts-Tab (v2.0)
- `GET /rollouts?status=`
- `GET /rollouts/ring-overview`, `/rollouts/settings`
- `POST /packages/{name}/rollouts` — startet Rollout *(operator OK)*
- `GET /packages/{name}/rollouts` — Rollout-Historie für Paket (v2.0)
- `POST /rollouts/{id}/advance` — CAS-safe
- `POST /rollouts/{id}/pause-auto` (v2.0) *(operator OK)*
- `POST /rollouts/{id}/cancel` — auch setzt `auto_advance=0` bei Mode A

**Scheduled (admin-only):**
- `POST /scheduled`, `GET /scheduled`, `DELETE /scheduled/{id}`

**Profile:**
- CRUD, `POST /profiles/{id}/apply` *(operator OK)*

**Agents (admin-only außer Dispatch):**
- `GET /agents`, `/agents/{id}/software`, `/installs`, `/profiles`
- `POST /agents/{id}/install/{pkg}` *(operator OK)*
- `POST /agents/{id}/uninstall/{pkg}` *(operator OK)*
- `POST /agents/{id}/update-all` *(operator OK)*
- `POST /agents/{id}/install-bulk` *(operator OK)*
- `PATCH /agents/{id}/ring`, `POST /agents/{id}/revoke`, `/ban`, `/unban`, `DELETE /agents/{id}` — admin-only

**System (admin-only):**
- Users-CRUD, `GET/PATCH /settings`, `POST /settings/rotate-registration-secret`
- Build-Trigger, Branding, Icon-Upload, Audit-Log

---

## Security-Modell

### Grundprinzipien

1. **Separation of concerns**: Kiosk-JWT vs Admin-Session getrennte Pfade
2. **Defense in depth**: mehrfach-Validierung (Pydantic + Regex + Whitelist-Sets)
3. **Least privilege**: RBAC verhindert Dispatch→Policy-Eskalation

### Parameterized Queries

Alle SQL über aiosqlite `?`-Placeholders. Keine f-string-Interpolation.

### XSS-Schutz

- Backend: HTML-Escape in Template-Substitutionen
- Frontend: `esc()` für Strings, `jsStr()` für JS-in-HTML

### CSRF

Middleware prüft POST/PATCH/DELETE:
- `Origin`-Header matched Hostname **oder**
- `X-Requested-With: XMLHttpRequest`

### Session-Härtung

- HttpOnly-Cookie, SameSite=Lax
- Secure-Flag auto bei X-Forwarded-Proto=https
- `delete_user_sessions` bei User-Deaktivierung

### Phased-Rollout Kiosk-Gate

Update-Version-Info nur sichtbar wenn Agent-Ring ≤ Rollout-Phase. Verhindert Version-Leaks an „noch nicht dran"-Agents.

### Upload-Härtung

- SHA256-Verifizierung
- Path-Traversal-Check bei ZIP-Extract
- MSI-Metadata via msiinfo-Subprocess (kein Python-Parser)
- Icon: Pillow mit DecompressionBombError-Schutz

### Rate-Limiting

Siehe RBAC-Sektion.

### Audit

Zwei Log-Schienen:
- `audit_log` (HTTP-Requests)
- `event_log` (typed Admin-Events)

Auto-Pruning nach `log_retention_days`.

---

## Deployment

### Produktiv

1. `.env` setzen (SECRET_KEY, ADMIN_*, REGISTRATION_SECRET, TACTICAL_*, PROXY_PUBLIC_URL)
2. `docker-compose up -d`
3. Admin-Portal → Settings ausfüllen → „EXEs bauen"
4. Reverse-Proxy (Caddy/Traefik) mit TLS
5. Kiosk-Deployment via Tactical

### Development

Beispiel-Loop für Entwicklung direkt auf dem Host:

```bash
scp proxy/...py user@host:/opt/softshelf/proxy/...
ssh user@host "cd /opt/softshelf && \
  docker-compose build softshelf-proxy && \
  docker-compose up -d softshelf-proxy && \
  docker logs --tail 20 softshelf-proxy"
```

### Backup (minimal)

- `/app/data/softshelf.db`
- `/app/data/uploads/`

Regenerierbar via Tools: `winget_index.db`, `downloads/*.exe`.

---

## Siehe auch

- **`CHANGELOG.md`** — Version-by-Version-Historie
- **`proxy/templates/admin_help.html`** — User-facing Admin-Doku (lazy-geladen im Hilfe-Tab)
