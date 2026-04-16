# Changelog

Version-by-Version-Historie. Für architekturelle Details siehe `ARCHITEKTUR.md`.

Format: inspired by Keep-a-Changelog. Jede Version hat Gruppen
*Added / Changed / Fixed / Security*.

---

## [2.0.0] – 2026-04-16

Großer Sprung seit 1.6.0. Repositioning von „Self-Service-Portal" zu einer
vollwertigen **Windows-Software-Verteilungs-Plattform** auf Tactical-RMM-Basis.
Self-Service ist jetzt nur einer von vier Deployment-Wegen — neben
Profil-Anwendung, Phased Rollouts und Compliance-Enforcement.

### Added — Profile-System

- **Profile** als benannte Paket-Sets. Ein Profil bündelt 1–N Pakete,
  wird einem Client (oder mehreren) zugewiesen und propagiert Änderungen
  automatisch: neues Paket im Profil → alle bereits zugewiesenen Clients
  bekommen es. Client entfernen → optional gleichzeitig deinstallieren.
- **Version-Pinning pro Profil-Paket** (`profile_packages.version_pin`).
- **Auto-Update-Flag pro Profil.** Nächtlicher Scheduler-Lauf (03:00 UTC)
  aktualisiert alle Profil-Pakete auf allen zugewiesenen Clients.
- **Profile-Tab** in der Admin-UI, Counter-First-Darstellung der
  zugewiesenen Clients (Ring-Split-Chips, skaliert auf 200+ Clients
  per Modal mit Ring-Filter + Suche).
- **Agent-Detail: Profile-Pills** mit Schnellzuweisung und Entfernen.

### Added — Phased Rollouts (Mode M + Mode A)

- **Ring-basiertes Rollout-System.** Drei Ringe (Default-Labels
  Canary / Pilot / Produktion, pro Umgebung editierbar). Neue Agents
  landen in Ring 3 (Produktion).
- **State-Machine** mit `rollouts`-Tabelle, `current_phase`, `status`,
  `phase_history`. Endpoints: `POST /packages/{name}/rollouts` (Start),
  `POST /rollouts/{id}/advance`, `POST /rollouts/{id}/cancel`.
- **Mode M (manuell)**: Admin klickt „Weiter" zwischen Phasen.
- **Mode A (kontinuierlich)**: `packages.auto_advance` kombiniert mit
  `staged_rollout` → System startet Rollouts automatisch wenn Updates
  verfügbar werden, phased durch die Ringe, startet bei jeder neuen
  Version neu. `_rollout_auto_start_tick` läuft alle 15 Min.
- **Per-Paket `auto_advance`-Toggle** (⚡-Icon in Pakete-Zeile).
- **Pause-auto-Button** in aktiven Mode-A-Rollouts.
- **Auto-Off beim Cancel** verhindert Neustart durch Auto-Start-Tick.
- **Per-Transition-Wartezeiten**: `rollout_auto_advance_hours_1_to_2`
  (Default 24h) und `_2_to_3` (Default 168h = 7d) separat.
- **Rollouts-Tab**: eine Liste, Zeilen-Höhe richtet sich nach Status
  (running / ready / done / idle / auto-armed). Version-Diff-Hero,
  3-Dot-Phase-Timeline mit Ring-Labels, per-Paket Rollout-Historie im
  Expand-Panel.
- **Dynamische Ring-Labels** überall in der UI.
- **Kiosk Phased-Rollout-Gate**: Update-Button **nur** wenn
  `agent.ring ≤ rollout.current_phase`. Updates erscheinen erst wenn der
  eigene Ring dran ist.
- **`packages.staged_rollout`-Flag.** ▶-Icon pro Paket. Phased-Pakete
  zwingen Ring-Auswahl beim Dispatch.

### Added — Monitoring & Incidents

- **Home-Dashboard** (`Übersicht`-Tab) mit KPI-Cards:
  Clients online/heute-aktiv, Pakete-Count, Updates verfügbar
  (flotten-weit), Fehler letzte 7 Tage, Installationen heute. Plus
  Panels: Offene Fehler, Meiste-outdated-Pakete, Letzte Installationen.
- **Fehler-Tab** flotten-weit mit Erneut + Bestätigen pro Fehler,
  „Alle bestätigen"-Bulk, „Bestätigte anzeigen"-Toggle. Bestätigen-Button
  auch im Agent-Detail-Banner.
- **Update-Banner im Agent-Detail** zeigt die Paket-Liste
  („9 Updates: Firefox, 7-Zip, …").
- **`agent_scan_meta.last_action_error_acked_at`** für ack-ohne-löschen.

### Added — Compliance & Policy

- **`packages.required`-Flag** → `Compliance`-Tab zeigt Required-Pakete
  mit Abdeckung pro Agent. „Alles nachinstallieren" triggert Install
  auf allen noch nicht-compliant Clients.
- **`packages.hidden_in_kiosk`-Flag.** Paket erscheint im Kiosk NUR
  wenn bereits installiert. Use-case: Admin-only Remote-Deploy-Software.

### Added — Wartungsfenster

- `scheduled_jobs`-Tabelle + APScheduler-Minuten-Tick. Unterstützte
  Aktionen: push_update, update_all, bulk_distribution, compliance_fix.
- **Geplant-Tab** mit „+ Neuer Job" Modal.

### Added — Admin-Tooling

- **Admin-Assign-Picker**: `[+ Agent zuweisen]`-Button im Paket-
  Installations-Panel. Hostname-Filter, Ring-Badge, 1-Klick-Install
  pro Agent.
- **Bulk-Import** für winget-IDs (Paste-Textarea, Catalog-Lookup,
  Skipping bereits-whitelisted Pakete).
- **Version-Pin UI** für winget-Pakete.
- **Notes-Feld** pro Paket (📝-Icon, Modal mit Textarea).

### Added — RBAC

- Drei Rollen: `admin` (alles), `operator` (Dispatch + Fehler bestätigen,
  kein Edit), `viewer` (read-only).
- `admin_users.role`-Spalte, Rollen-Dropdown im Benutzer-Panel,
  Role-Badge in Benutzer-Tab und User-Menu-Header.
- Zentraler `_require_admin`-Gate mit path+method-basierter Policy,
  `_ADMIN_ONLY_EXCEPTIONS`-Suffix-Liste für Dispatch-Endpoints.

### Added — UX

- **Sidebar-Navigation** (220px links) mit Gruppen: Software / Flotte /
  Operations / System. Ersetzt horizontale Tab-Bar.
- **Dark-Mode** via `data-theme`-Attribute. Toggle im Header,
  localStorage-persistiert, FOUC-safe inline-Init-Script.
- **Cmd+K / ⌘K Quick-Jump** — Suchmodal mit Tab/Paket/Agent/Profil-
  Treffern.
- **URL-Hash-Tab-Persistenz** — Reload/Back landet auf dem richtigen Tab.
- **CSV-Export** in allen sechs Tabellen-Tabs, Excel-kompatibel mit BOM.
- **Verteilung-Tabelle** statt Cards, skaliert auf 2000+ Pakete:
  Server-side Filter/Sort/Pagination, Row-Klick öffnet Slide-Over mit
  Agent-Details, Multiselect + Bulk-Aktionen.
- **Pakete-Tab als Tabelle** mit Type-Pills (monochrom + farbiger Dot:
  winget=amber, choco=blau, custom=violett).
- **Admin-Hilfe** komplett neu geschrieben (2-spaltiges TOC,
  2.0-Konzepte, Troubleshooting).

### Added — Winget Scope-Fallback & Choco-Ghost-Repair

- **`packages.winget_scope`** (auto|machine|user). Bei `auto` + Exit
  `-1978335216` (NO_APPLICABLE_INSTALLER): automatischer Retry ohne
  `--scope machine` im User-Kontext via `run_as_user=True`. Löst
  LastPass, Bitwarden, 1Password-via-Store etc.
- **Choco-Ghost-Repair.** `choco uninstall` mit `--force` +
  `--skip-autouninstaller` repariert Pakete deren `lib/`-Ordner
  vorhanden ist aber App weg.
- **Layer 1 Winget**: „no newer package versions are available" wird
  nicht mehr als Fehler gewertet.
- `agent_installations` wird auch bei winget-Success beschrieben.

### Changed — Ring-Semantik

- **Default ist jetzt Ring 3 (Produktion)** statt Ring 0. Legacy
  `ring=0`-Agents werden bei Migration auf `ring=3` gesetzt.
- `stage=prod` heißt `ring==3`, `stage=rings` heißt `ring IN (1,2)`.

### Changed — Rate-Limit-Buckets getrennt

- `/admin/login` (10/min) separiert von `/admin/api/*` (600/min) —
  SPA-parallele-Calls machen nicht mehr `429`-Probleme.

### Changed — Durchgehend deutsch

- Admin-UI + Hilfe durchgehend auf deutsche Terminologie: Ringe (statt
  Rings), Wartungsfenster (Maintenance-Windows), ausgelöst (dispatched),
  Flotten-* (Fleet-*), Erneut (Retry), Phased markieren (Staged markieren),
  nächtlich (nightly), Klick (Click).

### Security

- **Race-Condition `advance_rollout`:** Compare-and-swap-Guard
  (`WHERE id=? AND current_phase=?`). Endpoint gibt `409` bei Conflict
  zurück.
- **Ring-Mutation-Endpoint admin-only** — verhindert dass Operator
  Phased-Rollout-Targeting manipuliert.
- **Phased-Rollout-Gate im Kiosk-API** leakt keine Target-Versions an
  zu früh-gewählte Agents.
- **`/admin/api/scheduled` admin-only.** Operator kann keine
  Wartungsfenster mehr anlegen/löschen.
- **Scheduled-Job Input-Caps:** `package_names` max 500, `package_name`
  max 200 chars, `stage`/`action` Whitelist-Validierung.
- **CSV-Export defensive.** `Array.isArray(r?.entries) ? ... : []`
  statt fragile `||`-Kette.

### Removed

- **`docs/superpowers/`** aus git-Tracking entfernt (internes
  Planungs-Material).
- Globaler `rollout_auto_advance_enabled` Setting entfernt — per-Paket-
  Flag ersetzt das vollständig.

### Notes für Upgrade

- **Einmalige Migration**: Agents mit `ring=0` werden automatisch auf
  `ring=3` gesetzt beim ersten Start.
- **Bestehende Rollouts bleiben aktiv**. `auto_advance`-Flag ist 0 per
  Default — alte Rollouts laufen in Mode M weiter bis Admin umschaltet.

---

## [1.6.0] – 2026-04-15

Tray-Visibility, Installer, Branding.

### Added

- **Session-aware Launch.** Installer erzeugt Task-Scheduler-Task mit
  `Principal=active user` + `WorkingDirectory=$env:SystemRoot`. Damit
  kann Tactical (SYSTEM) den Tray-Client in User-Session starten.
- **Apps-&-Features-Integration.** Uninstall-Key in
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Softshelf`.
  Self-Relaunch beim Uninstall.
- **Editierbarer Publisher** (Settings → Publisher). Wird ins Apps-&-
  Features eingebacken.
- **Icon-Upload** (Settings → Icon). Pillow multi-resolution ICO-
  Konvertierung mit DecompressionBombError-Schutz, Bake beim Build.

---

## [1.5.0] – 2026-03-XX

Drei-Pipelines-Unification.

### Changed

- Choco läuft jetzt durch dasselbe `run_command` + Output-Capture +
  Soft-Error-Detection wie winget. Fire-and-forget `/software/{id}/`
  Tactical-Endpoint entfällt — Fehler werden sichtbar.
- `agent_scan_meta.last_action_error` für alle drei Typen.
- Per-Agent choco-Inventur (`choco_scanner.py` + `agent_choco_state`),
  parallel zu winget.

### Added

- Nightly choco-Scan (02:15).

---

## [1.4.0] – 2026-02-XX

Winget-Support.

### Added

- Lokaler Microsoft-winget-Catalog-Mirror (täglicher Download
  `cdn.winget.microsoft.com/cache/source.msix`, SQLite-Index,
  semver-aware Search).
- Nightly Per-Agent winget-Inventur via Tactical `winget export` +
  `winget upgrade`.
- `agent_winget_state`-Tabelle.
- Winget-Discovery und -Aktivierungs-Flow im Admin-UI.
- `winget.exe`-Resolver für SYSTEM-Kontext (per-user Shim nicht im PATH).
- APScheduler mit drei Jobs.
- **Agent-Detail-Page** (Vollbild statt Slide-in) mit zusammengeführter
  Software-Liste (Tactical + winget_state, dedupt mit Token-Score).
- Winget-Enrichment-Job (Tactical-Software-Scan ↔ Catalog-Matching).

---

## [1.3.0] – 2025-12-XX

Versionierung + Distribution-Tab.

### Added

- Custom-Paket-Versionierung (`package_versions`) + Agent-Installations-
  Tracking + Push-Update.
- Programm-Ordner-Upload (multi-file → server-side ZIP) mit Entry-Point.
- Verteilung-Tab mit per-Agent Update-/Entfernen-Aktionen.
- Storage-Indicator im Upload-Panel.
- Tray-Health-Monitor (Offline-Notification, rotes Icon).
- „Update verfügbar"-Badge + Updaten-Button im Kiosk.
- Agent-Lifecycle im Admin-UI (Revoke / Löschen / Sperren).

### Security

- Security-Review-Fixes (CRIT+HIGH+MEDIUM): build.sh-Injection,
  PRAGMA foreign_keys, delete_version TOCTOU, XSS via jsStr()-Refactor,
  SSO email_verified-Check, Session-Secure-Flag, Rate-Limit-Trust,
  Field-Validators, Exception-Leak-Fixes.

---

## Ältere Versionen

Siehe Git-History. v1.0-v1.2 waren interne MVP-Iterationen ohne
publizierten Changelog.
