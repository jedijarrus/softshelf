# Changelog

Version-by-Version-Historie. Für architekturelle Details siehe `ARCHITEKTUR.md`.

Format: inspired by Keep-a-Changelog. Jede Version hat Gruppen
*Added / Changed / Fixed / Security*.

---

## [2.4.2] – 2026-05-20

ARP-Fallback fuer winget-Uninstalls: behebt False-Success bei NSIS-Uninstallern
unter SYSTEM (Firefox helper.exe), greift generisch fuer alle winget-uninstalls.

### Fixed

- **winget uninstall: ARP-Fallback fuer NSIS/MSI/Inno Uninstaller.** winget
  meldet bei NSIS-Uninstallern (z.B. Mozilla Firefox `helper.exe`) unter
  SYSTEM oft `success` ohne dass tatsaechlich deinstalliert wird — der
  vendor-default Silent-Switch wird nicht durchgereicht, `helper.exe`
  ohne Desktop-Session exitet mit 0 ohne Aktion. Nach dem winget-Lauf
  durchsucht der Dispatcher jetzt Add/Remove-Programs nach `DisplayName`;
  bleibt ein Eintrag uebrig, wird `UninstallString` (bzw.
  `QuietUninstallString` wenn vorhanden) geparst, Installer-Typ erkannt
  (`MsiExec /I|/X` â MSI, `unins\d+\.exe` â Inno,
  sonst NSIS) und mit korrektem Silent-Switch (`/quiet /norestart`,
  `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`, `/S`) direkt ausgefuehrt.
  Greift fuer alle winget-uninstalls, no-op wenn winget sauber durchkommt.
- **Admin-UI `winget-uninstall`-Endpoint** (`/admin/api/agents/{id}/winget-uninstall`)
  reicht `display_name` jetzt an `_build_winget_command` weiter â
  ohne diesen Fix lief der ARP-Fallback-Block nur beim Client-Uninstall,
  nicht bei Admin-Uninstall + Profil-Unassign-Uninstall.

---

## [2.4.1] – 2026-05-11

Phased-Rollout-Harden: target_version Frozen-on-Start, semver-aware Compare,
Per-Ring-Detail-UI, Race-Guard.

### Added

- **`rollouts.target_version`** (Schema-Migration): Ziel-Version wird beim
  Start des Rollouts eingefroren. Catalog-`latest_version` kann sich danach
  aendern — Historie zeigt trotzdem was damals rolled out wurde.
- **Helper `resolve_target_version(pkg)`** in `routes/admin.py` als Single
  Source of Truth fuer `version_pin > catalog-latest (winget) > current_version
  (custom/plugin) > Fleet-Max`. Genutzt von `staged-overview`,
  `list_package_agents`, `start_rollout`, `_rollout_auto_start_tick`.
- **Semver-aware Version-Compare** in `winget_catalog`:
  `versions_equivalent(a, b)` (`"1.2"` == `"1.2.0"`, locale-Suffix-tolerant),
  `is_outdated(installed, target)` (semver-lt), `latest_version(list)`
  (semver-max). Loest lexikographische Bugs wie `"1.10" > "1.9"` = False.
- **Per-Ring Agent-Detailansicht** im Rollouts-Tab: Agents pro Paket nach
  Ring 1/2/3 gruppiert mit Header + Counts, Status-Pill pro Agent
  (`✓ aktuell` / `outdated` / `⟳ läuft` / `⚠ Fehler` / `nicht installiert`),
  klickbarer Hostname springt zur Agent-Detailansicht. Details-Button auch
  bei `ready`/`done`/`idle`-Status (vorher nur `running`).
- **History-Versions-Badge**: Rollout-History zeigt `→ <version>` pro
  Eintrag. Bei `action='push_uninstall'` ausgeblendet.
- **`get_latest_action_per_agent(package_name)`**: Bulk-Query map
  `agent_id → letzter action_log-Eintrag` fuer Per-Agent-Status-Pill.
- **`ring`-Spalte** in `get_agents_with_winget_package`,
  `get_agents_with_choco_package`, `get_installations_for_package` Results
  fuer die Per-Ring-Detailansicht.

### Changed

- **Auto-Start ist ring-agnostic** (`_rollout_auto_start_tick`): startet
  Phase 1 sobald irgendwo im Fleet outdated Agents existieren — egal welcher
  Ring. Phase ist Zeit-Konzept, kein Agent-Konzept. Leere Phasen laufen
  no-op durch und werden vom Advance-Tick nach Wartezeit weitergeschaltet.
  Admin sieht Phasen-Fortschritt durchgehend im UI auch bei leeren Ringen.
- **Phase-3-Auto-Completion-Policy**: System-gestartete Rollouts
  (`created_by IS NULL`) werden auch ohne `pkg.auto_advance` zu `done`
  weitergeschaltet (Bookkeeping, kein neuer Dispatch) — sonst blockiert ein
  stuck Phase-3-Rollout fuer immer neue Versionen. Manuell gestartete
  Rollouts behalten Admin-Kontrolle und muessen explizit abgeschlossen
  werden.
- **`outdated`-Flag in `list_package_agents`** nutzt jetzt zusaetzlich zu
  `available_version` auch den semver-Vergleich gegen `target_version` —
  faengt Faelle ab wo per-agent winget-scan kein Update meldet
  (per-user-Install, scope-Filter) das Paket aber tatsaechlich alt ist.
- **`get_package_agents_version_split`** nutzt `versions_equivalent` statt
  `==` — Format-Drift `"1.2"` vs `"1.2.0"` wird korrekt als `on_target`
  gebucket.

### Fixed

- **Lexikographischer Versionsvergleich**: `max(avs)` und `installed != target`
  haben False-Positive-Outdated-Flags und falsche Targets produziert. Jetzt
  ueberall semver-aware. (siehe Added oben.)
- **Stuck-Phase-3-Rollouts blockieren neue Versionen**: Vor 2.4.1 ist ein
  Rollout mit `auto_advance=0` in Phase 3 active geblieben und hat alle
  zukuenftigen Auto-Start-Versuche fuer das Paket geblockt. Phase-3-
  Auto-Completion behebt das fuer system-gestartete Rollouts.
- **target_version-Resolution war 4x dupliziert** mit unterschiedlichen
  Branches (`custom` nur in `start_rollout`, `version_pin` nicht in
  staged-overview-Choco). Jetzt zentralisiert in `resolve_target_version`.

### Security

- **Partial UNIQUE Index `idx_rollouts_one_active`** auf
  `rollouts(package_name) WHERE status='active'` verhindert Race zwischen
  API-Start und Auto-Start-Tick. Neue Exception `database.ActiveRolloutExists`
  wird vom API-Endpoint als `409 Conflict` zurueckgegeben und vom Tick
  geskipped.

---

## [2.4.0] – 2026-05-06

Agent-Management-Modul: zentrale Sicht und Push-Update fuer Tray-Clients.

### Added — Agent-Management

- **Tray-Client-Telemetrie**: Tray-App sendet bei jedem Health-Poll
  `X-Softshelf-Client-Version`, `X-Softshelf-Os-Version` und
  `X-Softshelf-Tray-Uptime` als HTTP-Header. Server persistiert in
  `agents.client_version`, `client_version_at`, `os_version`,
  `tray_uptime_s`, `last_telemetry_at`.
- **Build-Source-of-Truth**: `build_log.is_current` (genau 1 Build
  als current markiert), `setup_sha` und `tray_sha` werden bei
  erfolgreichem Build automatisch berechnet und persistiert.
  `database.get_current_build()` ist die Quelle fuer
  „welche Tray-Version sollen Agents haben".
- **Version-Distribution-Banner** im Clients-Tab: zeigt
  `<aktuell> / <veraltet> / <unbekannt>` mit Soll-Version + Button
  „Alle veralteten updaten".
- **Filter-Chips Alle / Veraltet / Unbekannt** im Clients-Tab.
- **Bulk-Select + Update-Button** pro Agent + global.
- **`POST /admin/api/agents/{id}/update-client`**: Server schickt
  PowerShell via Tactical run_command — Setup.exe runterladen,
  sha256-verifizieren, silent installieren. Setup.exe ersetzt
  Tray-Files in-place.
- **`POST /admin/api/agents/bulk-update-client`** mit
  `only_outdated` und optional `agent_ids[]`. Wenn keine IDs:
  ganze Flotte (gefiltert nach `only_outdated`).
- **`GET /admin/api/clients/version-distribution`**: Aggregat-
  Endpoint fuer das Banner.
- **`GET /api/v1/client-version-check`**: Public-Endpoint
  (Tray-JWT) — liefert `{latest, setup_url, setup_sha,
  min_required, deferred_until}`. Foundation fuer spaeteren
  Self-Update-Loop, MVP nutzt nur Push.
- **Settings-Key `client_min_required_version`**: optionaler
  Force-Update-Floor. Wenn gesetzt + Tray-Version darunter,
  zeigt Tray einen Force-Modal (Phase 3, aktuell nicht
  implementiert; Endpoint liefert den Wert bereits).

### Changed

- `get_agents()` liefert jetzt zusaetzlich client_version,
  os_version, tray_uptime_s, last_telemetry_at.

---

## [2.3.0] – 2026-05-06

Plugin-Pakettyp, MS-Store-Support, Workflow-Übersicht-Redesign,
umfangreiche Hardening-Runde.

### Added — Plugin-Pakettyp

- **Generischer `plugin`-Pakettyp** (`packages.type='plugin'`) für
  Drop-in-DLL/PLGX-Plugins von Host-Anwendungen wie Notepad++ und
  KeePass 2. Admin lädt eine Plugin-Datei hoch (`.dll`, `.zip`,
  `.plgx` je nach Host), Backend baut host-spezifischen
  PowerShell-Wrapper, der die Datei in den richtigen Plugin-Ordner
  der Host-App kopiert.
- **`plugin_hosts.py` Registry** mit pro-Host PowerShell-Snippets
  für `resolve_root` / `install` / `uninstall` / `detect`. Erweiterung
  um neue Hosts (Foobar2000, IrfanView, …) = neuer Eintrag im Dict.
- **`packages.plugin_host`** + `packages.plugin_folder` Spalten,
  Migration idempotent.
- **`POST /admin/api/upload-plugin`** + **`GET /admin/api/plugin-hosts`**.
- **Plugin-Update-Detection via sha256**: neue
  `agent_installations.installed_sha`-Spalte. Bei Re-Upload eines
  Plugins (neuer Hash) gelten alle Agents mit altem Hash als
  outdated → Push-Update-Button im Edit-Panel.
- **Plugin-Auto-Process-Check**: NPP/KeePass laufende Prozesse
  werden vor Install detektiert (Soft-Error 9020), DLL-Lock
  vermeidet sich.
- **Soft-Error 9030**: Host-Anwendung fehlt → User-Toast „Notepad++
  ist nicht installiert. Bitte zuerst installieren."
- **NPP-Plugin-ZIP-Flatten**: ZIPs mit nested folder-structure
  (z.B. URLPlugin liefert `URLPlugin/URLPlugin.dll`) werden in
  Stage-Dir extrahiert, alle `.dll/.xml/.txt/.ini` flach in den
  Plugin-Ordner kopiert.

### Added — MS-Store (msstore) Support

- **MS-Store-IDs** (Pattern `^9[A-Z0-9]{11}$`, z.B. `9NBLGGH6BZL3`)
  werden automatisch erkannt und mit `--source msstore` statt
  `--source winget` installiert. Admin gibt ID + Display-Name +
  Publisher manuell ein (kein Catalog-Mirror).
- **Auto-`run_as_user=True`** für msstore-Pakete weil UWP/Appx
  fast immer per-user installiert.
- **Modal „MS-Store-App per ID hinzufuegen"** im Winget-Tab des
  Add-Panels.
- **Soft-Error-Patterns** für `you must accept the license
  agreements` und `no application is installed matching`.

### Changed — Admin-UI Reorganization

- **Add-Panel umstrukturiert**: 5 Tabs in 2 Gruppen — „Katalog"
  (Winget, Chocolatey) + „Hochladen" (EXE/MSI, Programm-Ordner,
  Plugin). Tabs nicht mehr in einer Reihe und gruppiert nach
  Modus.
- **Default-Mode beim Öffnen ist jetzt Winget** statt Chocolatey
  (Winget hat das größere Catalog).
- **Subtitle** erwähnt Plugin-Type.
- **Filter-Chip `plugin`** in Pakete-Tab, Verteilung-Tab,
  Add-Staged-Profile-Picker und Profile-Editor.
- **Workflow-Übersicht redesigned**: statt nichtssagendem
  „install → install → install" zeigt die Karte jetzt Counter
  („19 Steps · 18 Installs · 1 Reboot") und eine alphabetisch
  sortierte Step-Liste mit Type-Color-Dots (grün=install,
  rot=uninstall, amber=reboot, blau=script). Execution-Order
  bleibt im Editor unverändert.
- **3-State-Sichtbarkeit `hidden_in_kiosk`**: 0=sichtbar,
  1=nur-wenn-installiert (Admin-Dispatch-Use-Case),
  2=komplett-ausgeblendet. Dropdown im Edit-Panel statt
  binary Toggle.
- **Plugin-Pill** (grün) in der Pakete-Tabelle mit Host-Label +
  Plugin-Folder als Sub-Text.

### Fixed — Workflow-Engine

- **Workflow-Retry-Advance-Bug**: per-user-Retry und choco
  `.install`-Retry hingen früher nicht am `workflow_run_id` ihres
  Original-action_logs → Retry-Erfolg wurde dem Workflow nicht
  gemeldet, Run blieb auf `failed`. Retries hängen jetzt am
  gleichen run, und der erste Callback advanced den Workflow
  NICHT mehr wenn ein Retry gerade dispatched wurde.
- **Catch-Block-Bug im Bootstrap-Wrapper**: `$_sfSuccess -ne
  'skipped'` coerced den String zu Bool → `$true -ne $true` war
  immer `$false`, der Reset-Pfad lief NIE und Server bekam
  Erfolg gemeldet obwohl die Inner-Script-Aktion ge-throw't
  hatte. Fix: Cast nach `[string]$_sfSuccess` erzwungen.

### Fixed — UI

- **Off-Screen-Panel-Shadow-Leak**: 7 `.panel`-Elemente sind als
  `position:fixed` knapp jenseits Viewport (transform:
  `translateX(100%)`), ihre `box-shadow:-8px 0 32px` blutete aber
  rund 32 Pixel in den sichtbaren Viewport-Rand und sah aus wie
  ein dunkler Verlauf rechts der Scrollbar. Fix: Schatten nur
  noch an `.panel.open`.

### Security — Hardening

- **Magic-Byte-Validation beim Plugin-Upload** (`.zip`=`PK`,
  `.dll`=`MZ`, `.msi`=OLE, `.plgx`=`19 07 D9 65`). Spoofing der
  Datei-Endung wird beim ersten Chunk abgewiesen.
- **ZIP-Slip-Defense im Notepad++-Install**: vor `Expand-Archive`
  alle ZIP-Entries via `System.IO.Compression.ZipFile` validieren
  — reject bei `..\\`, absoluten Pfaden oder Drive-Letter-Prefix.
  PS 5.1 default-load das Assembly nicht — `Add-Type` mit
  Fallback auf Expand-Archive's eigene Sicherung.
- **PowerShell single-quote-Escape** für `host.label` + andere
  PS-string-Interpolationen. Kein bekanntes Exploit aktuell, aber
  Defense-in-Depth gegen zukünftige Hosts mit `'` im Label.
- **Explicit `cmd /c "exit 0"`** am Ende von Plugin-Install und
  -Uninstall, damit `$LASTEXITCODE` deterministisch ist.
- **Cleanup-on-Validation-Fail** beim Plugin-Upload: wenn
  `plugin_folder`-Regex nach Upload scheitert, wird die
  Orphan-Datei aus `uploads/` entfernt sofern niemand sonst den
  sha referenziert.

---

## [2.2.0] – 2026-04-25

Workflows + generische Version-Pinning. Größtes Feature: das
Workflow-System für mehrstufige Setup-Sequenzen.

### Added — Workflows

- **Workflows als wiederverwendbare Step-Sequenzen** auf
  Single-Agent-Basis. Schritte: `install`, `script`, `reboot`.
- **`workflow_engine.py`** State-Machine: `start_workflow`,
  `dispatch_current_step`, `advance` (aus receive_callback),
  `cancel`, `check_timeouts` (APScheduler), `recover_after_restart`.
- **Failure-Policies pro Step**: `abort` (Default), `skip`, `retry:N`.
- **Reboot-Step**: AtStartup-Task auf Agent + `shutdown /r`,
  Client zeigt RebootDialog (pywebview Countdown), User kann
  sofort neu starten oder per `force_after_hours` aufschieben.
- **Workflow-Editor** (Drag&Drop-Step-Editor) im Admin-UI,
  Sidebar-Gruppe „VERWALTUNG" (Profile, Workflows, Rollouts).
- **Agent-Detail-Workflow-Sektion**: Run starten, aktive Runs,
  Cancel, Run-Historie.
- **REST-Endpoints**: `GET/POST /admin/api/workflows`,
  `PATCH/DELETE /admin/api/workflows/{wid}`,
  `POST /admin/api/agents/{id}/start-workflow`,
  `GET /admin/api/agents/{id}/workflow-runs`,
  `DELETE /admin/api/workflow-runs/{run_id}`,
  `POST /api/v1/workflow/reboot-now/{run_id}`,
  `POST /api/v1/workflow/defer/{run_id}`.
- **APScheduler-Job `_workflow_timeout_check`** (jede Minute,
  prueft step_deadline_at).
- **Restart-Recovery**: `recover_after_restart` re-dispatcht
  laufende Runs nach Container-Restart (oder markiert sie als
  `timed_out`).
- **Unique-Constraint**: max. 1 aktiver Run pro Agent.

### Added — Generic Version Pinning

- **`packages.version_pin`** (TEXT NULL) ersetzt
  `packages.winget_version` — generisch für winget UND choco.
  Migration kopiert alte Werte rüber, alte Spalte bleibt für
  Backward-Compat aber wird nicht mehr befüllt.
- **`PATCH /admin/api/packages/{name}/version-pin`** —
  generischer Endpoint, alter `/winget/.../version-pin` als
  Legacy-Alias erhalten.
- **`GET /admin/api/packages/{name}/available-versions`** —
  Versions-Picker, winget aus lokalem Catalog, choco aus
  Fleet-Scan-Aggregat.
- **Version-Picker im Edit-Panel** mit Suche.

### Added — Process-Check (Pre-Install)

- **`packages.process_check`** TEXT — komma-separierte
  Prozessnamen die VOR Install-Dispatch geprüft werden.
- **Server-Side Check** in `_build_winget_command`
  (Soft-Error 9020 → SOFTSHELF_PROCESS_RUNNING marker).
- **Client-Side Check im Kiosk** (PackageApi.check_running_processes
  via `tasklist`), zeigt einen Modal „Bitte X schliessen" bevor
  der Install dispatched wird.
- **Whitelist-validierte `install_args`** für winget (z.B.
  `--skip-dependencies` für NoSpamProxy mit Office-Dependency).
- **Edit-Panel-Felder** für `process_check` und `install_args`.

### Changed — Errors-Tab

- **Filter, Bulk-Select, Acknowledge, Delete** für Fehler-Liste.
- Strukturierter Output bei Soft-Errors mit Severity-Mapping.

### Fixed

- Comprehensive Error-Handling-Review (C1-C8, I1-I20, M1-M10):
  Race-Conditions in Cooldown (asyncio.Lock), CSRF-Edge-Cases,
  Whitelist-Bypasses, Trusted-Proxies-Caching, mehr.

---

## [2.1.0] – 2026-04-22

Choco läuft jetzt durch denselben Dispatch-Pfad wie winget/custom.

### Changed — Choco-Dispatch-Vereinheitlichung

- **Choco wird nicht mehr** über Tactical's
  `/software/{id}/`-Endpoint installiert (fire-and-forget mit
  Null Output-Capture). Stattdessen via `_build_choco_command`
  + `_build_script_and_bootstrap` + `_deliver_command_bg`.
- **Soft-Error-Detection** für Choco im `receive_callback`:
  `is not installed`, `please also run the command`,
  `likely broken for foss users`, `404`-Patterns,
  Partial-Success-Detection.
- **Choco `.install`-Retry**: wenn Uninstall mit `is not
  installed` failt UND Paketname nicht auf `.install` endet,
  wird automatisch ein Retry mit `<pkg>.install` gestartet.

### Fixed

- **Office-Choco-Uninstall** entfernt jetzt wirklich (das
  `--skip-autouninstaller`-Flag verhinderte das).
- **Choco-Case-Insensitive-Whitelist-Lookup** (war
  CamelCase-vs-lowercase-Mismatch).

---

## [2.0.3] – 2026-04-24

Unified Delivery: alle Pakettypen (winget/choco/custom) laufen
jetzt durch denselben fire-and-forget Bootstrap + Callback Pattern.
Größter Architektur-Cleanup seit Choco-Dispatch-Trennung.

### Changed — Unified Dispatch

- **`_deliver_command_bg`** als zentraler Dispatch-Helper.
  Pre-Flight (Agent-Status) → Bootstrap (60s Tactical-Timeout) →
  return. Result kommt asynchron via Callback.
- **`_build_script_and_bootstrap`**: speichert PS-Script als
  Datei (HTTP-Pull durch Agent), liefert Bootstrap-Command
  (~250 Bytes) zurück. Eliminiert NATS-Timeout-Issues bei
  langen Installs.
- **`POST /api/v1/callback/{job_id}`** + **`GET /api/v1/script/{job_id}`**
  endpoints. job_id (256 bit random) ist die Auth.
- **`action_log`-Tabelle** trackt pending → running →
  success/error/skipped statt eigener install_log/uninstall_log.

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
