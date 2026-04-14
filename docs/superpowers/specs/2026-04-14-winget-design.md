# Spec: Winget-Paketverwaltung für Softshelf

**Datum:** 2026-04-14
**Status:** Design abgestimmt, Implementierung offen
**Zielbranch:** `feature/winget`

## 1. Kontext & Motivation

Softshelf verwaltet aktuell zwei Paketquellen: **Chocolatey** und **Eigene Pakete**
(MSI/EXE/Ordner). Die Nutzer-Basis fragt zunehmend nach Software, die nicht
über Chocolatey verfügbar ist, aber in Microsofts offiziellem **winget**-Katalog
gepflegt wird (z. B. Entwickler-Tools, Browser-Varianten, Nischen-Software).

Ziel dieses Features: winget als **dritte gleichwertige Paketquelle** integrieren.
Admins können winget-Pakete im Backend aktivieren, Endnutzer sehen sie im
Kiosk-Client gleichwertig mit Choco- und Custom-Paketen und können installieren,
aktualisieren und deinstallieren.

Winget hat eine fundamentale Besonderheit gegenüber den bisherigen Quellen:
- **Katalog-Lookup** (Welche Pakete existieren?) geht server-seitig gegen
  Microsofts öffentliches REST-Endpoint ohne Agent-Beteiligung.
- **Installations-Zustand** (Was ist auf Rechner X drauf? Welche Updates
  gibt es?) muss zwingend per winget-CLI **auf dem Agent selbst** abgefragt
  werden — das lässt sich nicht aus Tacticals bestehender software-scan-Liste
  herleiten, weil die Display-Namen nicht eindeutig auf winget-PackageIdentifier
  zurückzurechnen sind.

Diese Asymmetrie ist der zentrale Design-Treiber.

## 2. Ziele

1. Admin kann im Backend nach winget-Paketen **suchen** (gegen Microsofts
   öffentlichen Katalog) und mit einem Klick whitelisten.
2. Admin sieht eine **Fleet-Discovery-Liste**: „Welche Software ist auf
   Rechnern in meiner Flotte installiert, aber noch nicht in Softshelf
   whitelisted?" — mit einem Klick aktivierbar.
3. Endnutzer sehen im Kiosk-Client die whitelisteten winget-Pakete gleichwertig
   zu Choco-/Custom-Paketen. Pakete mit verfügbarem Update werden prominent
   oben angezeigt.
4. Install, Upgrade und Uninstall laufen silent als SYSTEM über den bestehenden
   Tactical-`run_command`-Dispatch.
5. Nach jeder User-Aktion ist der angezeigte Zustand innerhalb von Sekunden
   aktuell (targeted Re-Scan).

## 3. Nicht-Ziele (MVP)

- User-Scope-Installationen (UWP-only / Microsoft-Store-exklusive Apps, die
  nicht via `--scope machine` installierbar sind) werden nicht unterstützt.
  Fehler wird klar geloggt, Admin sieht's und kann das Paket als Nicht-Kandidat
  markieren.
- Version-Pinning (Admin legt eine spezifische Version fest): DB-Spalte wird
  vorbereitet, UI-Picker und Dispatch-Logik kommen in einer späteren Phase.
- Community-Winget-Sources außerhalb des offiziellen `winget`-Repositories.
- Collision-Detection zwischen choco- und winget-Varianten desselben Pakets
  (z. B. Firefox via Choco *und* via winget gleichzeitig whitelisted): wird
  nicht enforced, bleibt Admin-Verantwortung.
- User-Wunschliste im Kiosk-Client: Software-Wünsche werden weiterhin als
  Ticket außerhalb des Systems erfasst.
- Automatische Rollbacks nach fehlgeschlagenen Upgrades.

## 4. Architektur-Überblick

```
┌───────────┐        ┌──────────────────────┐        ┌──────────────┐        ┌────────────┐
│ Admin UI  │        │     Softshelf Proxy   │        │ Tactical RMM │        │ Win-Agent  │
└─────┬─────┘        └──────────┬────────────┘        └──────┬───────┘        └─────┬──────┘
      │                         │                            │                      │
      │ Search „firefox"        │                            │                      │
      ├───────────────────────> │ manifestSearch REST        │                      │
      │                         ├─────────────── HTTPS ───────────── Microsoft CDN   │
      │                         │                            │                      │
      │                         │ APScheduler nightly job    │                      │
      │                         │ (Pre-Filter via eigener    │                      │
      │                         │  kiosk-client last_seen)   │                      │
      │                         │ Semaphore(20), 120s/Agent  │                      │
      │                         ├─ run_command ────────────> │ ─ NATS ────────────> │ winget list
      │                         │                            │                      │ winget upgrade
      │                         │ <── stdout (Text) ──────── │ <─ NATS ──────────── │
      │                         │ parse → upsert state       │                      │
      │                         │                            │                      │
      │ GET /admin/api/winget/  │                            │                      │
      │     discovery           │                            │                      │
      │ <───────────────────────┤ Query state + enrichment   │                      │
      │                         │                            │                      │
┌─────┴─────┐                   │                            │                      │
│  Kiosk    │                   │                            │                      │
└─────┬─────┘                   │                            │                      │
      │ GET /api/v1/packages    │                            │                      │
      ├───────────────────────> │ Join packages × state      │                      │
      │                         │ für diesen Agent           │                      │
      │ <───────────────────────┤                            │                      │
      │                         │                            │                      │
      │ POST install/upgrade    │                            │                      │
      ├───────────────────────> │ ─ run_command (winget) ──> │ ──────────────────── │ winget install
      │                         │ <── result ─────────────── │ <─────────────────── │
      │                         │ scan_agent(id) chained ──> │ ──────────────────── │ winget list/upgrade
      │                         │ upsert state               │                      │
      │                         │                            │                      │
```

## 5. Datenmodell

Nur additive Änderungen am bestehenden Schema. Keine Migrationen bestehender
Tabellen.

```sql
-- Per-Agent Software-Zustand (Ergebnis von winget list + winget upgrade)
CREATE TABLE agent_winget_state (
    agent_id          TEXT NOT NULL,
    winget_id         TEXT NOT NULL,              -- z.B. 'Mozilla.Firefox'
    installed_version TEXT,
    available_version TEXT,                        -- NULL = up-to-date
    source            TEXT,                        -- 'winget' | 'msstore'
    scanned_at        TIMESTAMP NOT NULL,
    PRIMARY KEY (agent_id, winget_id)
);
CREATE INDEX idx_agent_winget_id ON agent_winget_state(winget_id);

-- Meta: Pro-Agent Scan-Zustand für Fleet-Health und Retry-Logik
CREATE TABLE agent_scan_meta (
    agent_id              TEXT PRIMARY KEY,
    last_scan_at          TIMESTAMP,
    last_status           TEXT,                    -- 'ok'|'offline'|'error'|'timeout'
    last_error            TEXT,                    -- human-readable
    consecutive_failures  INTEGER NOT NULL DEFAULT 0
);

-- Discovery-Enrichment Cache:
-- Tactical-software-scan display_name → winget-ID (Bonus-Feature)
CREATE TABLE discovery_enrichment (
    display_name  TEXT PRIMARY KEY,
    winget_id     TEXT,                            -- NULL wenn kein Match
    confidence    TEXT,                            -- 'high'|'medium'|'low'|'none'
    checked_at    TIMESTAMP NOT NULL
);

-- Vorbereitung für Version-Pinning (UI-Integration ist Phase 2)
ALTER TABLE packages ADD COLUMN winget_version TEXT;  -- NULL = latest
```

Winget-Pakete nutzen die bestehende `packages`-Tabelle mit `type='winget'` und
`name` als winget-PackageIdentifier (z. B. `Mozilla.Firefox`). Die Spalten
`display_name`, `category`, `uninstall_cmd` werden wiederverwendet. Die Spalten
`filename`, `sha256`, `current_version_id` bleiben für winget-Rows `NULL`.

## 6. Backend-Komponenten

### Neue Module

| Datei | Verantwortung |
|---|---|
| `proxy/winget_catalog.py` | httpx-Wrapper für Microsofts öffentliches REST-Endpoint `manifestSearch`. Exponiert `async def search(query: str)` und `async def get_details(package_id: str)`. Normalisiert Response in ein internes Format: `{id, name, publisher, latest_version, description, source}`. |
| `proxy/winget_scanner.py` | Scan-Logik. Funktionen: `scan_agent(agent_id)` für targeted Re-Scans nach User-Aktionen, `run_nightly_scan()` für den Fleet-wide Batch. Beinhaltet den PowerShell-Text-Parser (siehe Abschnitt 9). Upserts in `agent_winget_state` und `agent_scan_meta`. |
| `proxy/winget_enrichment.py` | Täglicher Enrichment-Job: geht unmatched Tactical-software-scan Display-Namen durch, ruft `winget_catalog.search()` auf, berechnet Confidence (Abschnitt 10), cached in `discovery_enrichment` mit TTL 7 Tage. |

### Geänderte Module

| Datei | Änderung |
|---|---|
| `proxy/main.py` | Im `lifespan`-Context wird ein APScheduler gestartet. Zwei Jobs: `run_nightly_winget_scan` (z. B. 03:00 lokal) und `run_enrichment_job` (z. B. 03:30). Neue Dependency: `apscheduler` in `requirements.txt`. |
| `proxy/database.py` | Schema-Migration (CREATE TABLE + ALTER TABLE idempotent beim Start). Neue Helper: `upsert_agent_winget_state`, `get_agent_winget_state`, `query_fleet_discovery`, `upsert_scan_meta`, `get_discovery_count`. Alle aiosqlite-Calls gehen über den bestehenden `_db()`-Helper, damit `PRAGMA foreign_keys` gesetzt bleibt. |
| `proxy/tactical_client.py` | Kein neuer Endpoint notwendig. Der bestehende `run_command(agent_id, cmd, shell, timeout)` wird für den Scan wiederverwendet. |
| `proxy/routes/admin.py` | Neue Endpoints: `GET /admin/api/winget/search?q=` proxied die manifestSearch-REST-Abfrage und liefert normalisierte Ergebnisse. `POST /admin/api/winget/activate` erstellt eine neue `packages`-Row mit `type='winget'`. `GET /admin/api/winget/discovery` liefert die Fleet-Discovery-Liste mit Enrichment-Informationen. `GET /admin/api/winget/discovery-count` liefert nur die Zahl für das Header-Banner. `POST /admin/api/winget/rescan/{agent_id}` triggert einen sofortigen targeted Re-Scan. |
| `proxy/routes/packages.py` | Für winget-Pakete wird ein Left-Join mit `agent_winget_state` des anfragenden Agents gemacht. Response-Felder pro Paket: `status` (einer von `not_installed`, `installed`, `update_available`), `installed_version`, `available_version`. |
| `proxy/routes/install.py` | Neuer Dispatch-Branch für `type='winget'`. Baut PowerShell-Befehle der Form `winget install --id '<ID>' --scope machine --silent --accept-package-agreements --accept-source-agreements --disable-interactivity -h` (analog für `upgrade` und `uninstall`). Exit-Codes `0`, `-1978335212` (bereits installiert) und `-1978335189` (no upgrade available) werden als Erfolg behandelt. Nach erfolgreicher Ausführung wird `scan_agent(agent_id)` als chained Background-Task abgesetzt. |

### Scheduler-Details

- Nightly-Scan fan-out: Semaphore mit 20 gleichzeitigen `run_command`-Calls.
- Pre-Filter: Der Scheduler fragt zuerst die eigene `agents`-Tabelle nach
  Kiosk-Client-`last_seen`. Agents mit `last_seen` älter als 5 Minuten werden
  als „offline" klassifiziert und im Scan geskipped (landen mit
  `last_status='offline'` in `agent_scan_meta`). Das ist billig und vermeidet
  Timeouts durch offline-Agents, ohne einen extra Tactical-API-Call.
- Timeout pro Agent: 120 s (Scan ist schnell).
- Retry: `consecutive_failures >= 7` → Agent wird aus dem nightly-Batch
  ausgeschlossen, bis er wieder online ist. Ein manueller Re-Scan via
  Admin-UI setzt den Counter zurück.

## 7. Admin-UI

### Erweiterung des Paket-Aktivieren-Panels

Das bestehende „Paket aktivieren"-Panel bekommt einen dritten Tab neben
„Chocolatey" und „Eigenes Paket": **„Winget"**.

```
┌─ Paket aktivieren ────────────────────────────────────┐
│  [Chocolatey]  [Eigenes Paket]  [Winget ●]            │
├───────────────────────────────────────────────────────┤
│  🔍 [ firefox                                       ] │
│                                                        │
│  Mozilla Firefox            Mozilla    v125.0   [+]   │
│  Firefox Developer Edition  Mozilla    v126.0b1 [+]   │
│  Firefox ESR                Mozilla    v115.9   [+]   │
│                                                        │
│  ▼ In der Flotte gefunden (12)                        │
│  ┌─────────────────────────────────────────────────┐  │
│  │ Notepad++         23/200  → NotepadPP.NotepadPP [+] │
│  │ 7-Zip             18/200  → 7zip.7zip           [+] │
│  │ VLC media player  15/200  → VideoLAN.VLC        [+] │
│  │ Legacy Tool 2018   3/200  → kein Match       manuell│
│  │ ...                                                  │
│  └─────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────┘
```

**Oberer Block:** Suchfeld ruft `GET /admin/api/winget/search?q=` auf. Ergebnisse
werden als Liste gerendert, jede Zeile hat einen Aktivieren-Button der
`POST /admin/api/winget/activate` triggert.

**Unterer Block:** Aufklappbar. Ruft `GET /admin/api/winget/discovery` auf. Zeigt
pro Zeile: Display-Name, Installations-Zahl über die Flotte, aufgelöste
winget-ID (falls Enrichment ein Match gefunden hat), Confidence-Badge und einen
Aktivieren-Button. Bei Confidence `none` statt Aktivieren ein Hinweis „manuell",
der einen Link ins Choco-/Custom-Tab öffnet.

### Discovery-Badge im Admin-Header

Im Admin-Header erscheint ein dezentes Badge, wenn
`GET /admin/api/winget/discovery-count` eine Zahl > 0 liefert:

```
Softshelf Admin            🔔 12 Pakete in der Flotte unverwaltet →
```

Ein Klick öffnet das Aktivieren-Panel direkt auf dem Winget-Tab mit
expandiertem Discovery-Block.

## 8. Kiosk-Client

Keine strukturellen Änderungen am `package_window.py`. Das bestehende Grid
nimmt winget-Pakete gleichwertig aus der `/api/v1/packages`-Response entgegen.

Zwei minimale Ergänzungen:

1. **Sortierung:** Pakete mit `available_version != NULL` werden an den
   Grid-Anfang gepinnt (Update-Kandidaten zuerst). Rest bleibt alphabetisch.
2. **Source-Badge:** Klein und dezent unten in der Card — „winget", „choco",
   „eigen". Kein Farbsignal, nur Labeling.

Die bestehende Button-Logik (Installieren / Aktualisieren / Deinstallieren)
funktioniert unverändert, weil sie auf das `status`-Feld der Paket-Response
reagiert, nicht auf den Paket-Typ.

## 9. Scan-PowerShell und Text-Parser

### Kommando, das auf dem Agent ausgeführt wird

```powershell
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8

# Buffer-Breite aufreißen, damit winget lange Namen/IDs nicht mit '…' abschneidet
try {
    $raw = $Host.UI.RawUI
    $sz = $raw.BufferSize
    $sz.Width = 512
    $raw.BufferSize = $sz
} catch {}
$env:COLUMNS = 512

$installed = winget list --source winget --accept-source-agreements --disable-interactivity | Out-String
$upgradable = winget upgrade --source winget --accept-source-agreements --disable-interactivity | Out-String

@{installed=$installed; upgradable=$upgradable} | ConvertTo-Json -Compress
```

Das läuft unter `powershell.exe` (Windows PowerShell 5.1), was auf allen
Windows-11-Installationen out of the box verfügbar ist. Keine Abhängigkeit
auf PowerShell 7 oder das `Microsoft.WinGet.Client`-Modul.

### Parser-Strategie

Winget hat seit v1.0 ein stabiles tabellarisches Output-Format mit den Spalten
`Name | Id | Version | Available | Source`. Das Format ist nicht offiziell
dokumentiert, aber in fünf Jahren nicht gebrochen worden.

**Algorithmus:**
1. Die Header-Zeile finden: winget gibt direkt nach dem Header eine Trennzeile
   aus, die überwiegend aus `-`-Zeichen (U+002D) besteht. Der Parser sucht die
   erste Zeile die zu mindestens 80 % aus `-`-Zeichen und Leerzeichen besteht
   — die Zeile direkt darüber ist der Header. Diese Erkennung ist
   sprachunabhängig und überlebt sowohl englische (`Available`) als auch
   deutsche Windows-Installationen (`Verfügbar`).
2. Aus der Header-Zeile werden die Byte-Offsets der Spaltenanfänge bestimmt:
   jede Spalte beginnt dort wo ein Wort-Zeichen auf ein vorangegangenes
   Leerzeichen folgt. Das ergibt eine Liste von Offsets `[0, 24, 48, 60, 75]`
   für die fünf Spalten.
3. Jede Datenzeile wird anhand dieser Offsets per Substring-Slice in Felder
   zerlegt und pro Feld getrimmt.
4. **Truncation-Erkennung:** Wenn ein ID-Feld auf `…` (U+2026) endet, wird
   die Zeile verworfen und als Scan-Warnung in `agent_scan_meta.last_error`
   geloggt. Die Buffer-Breite von 512 im Scan-Skript sollte das unwahrscheinlich
   machen, aber die Prüfung ist defensiv.
5. Zeilen mit unvollständigen Feldern werden verworfen (z. B. Trenner-Zeilen
   aus Unicode-Box-Drawing-Chars).

**Phase-2-Option:** Falls sich im Betrieb zeigt dass der Text-Parser zu
unzuverlässig ist (viele Truncation-Warnings oder Lokalisierungs-Edge-Cases),
wird als Phase 2 das `Microsoft.WinGet.Client` PowerShell-Modul via Tactical auf
allen Agents nachinstalliert. Das Modul liefert strukturierte Objekte und
eliminiert das Text-Parsing komplett. Diese Phase ist nur optional und wird
ausgelöst durch echte Failure-Daten aus dem Betrieb, nicht präventiv.

## 10. Confidence-Heuristik für Discovery-Enrichment

Die Enrichment-Funktion matcht einen Tactical-software-scan Display-Namen
(z. B. „Mozilla Firefox (x64 de)") gegen ein manifestSearch-Ergebnis. Das
Ergebnis bekommt eine Confidence-Label:

| Label | Kriterium |
|---|---|
| `high` | Exakter Match zwischen dem Display-Namen (nach Normalisierung: lowercase, Whitespace kollabiert, Klammer-Suffixe entfernt) und dem `PackageName`-Feld des manifestSearch-Treffers. |
| `medium` | Publisher-Name kommt im Display-Namen vor UND Substring-Match auf einem der manifestSearch-Treffer-Namen. |
| `low` | Fuzzy-Match (Levenshtein-Distanz ≤ 3 oder Jaccard-Similarity ≥ 0.7) auf dem Top-Treffer, ohne klaren Publisher-Hinweis. |
| `none` | Kein manifestSearch-Treffer oder keine der obigen Heuristiken greifen. Der Display-Name landet trotzdem in der Discovery-Liste, aber ohne Aktivieren-Option. |

Im Admin-UI wird die Confidence als farbiger Badge dargestellt:
- `high` → grün, direkter Aktivieren-Button
- `medium` → gelb, Aktivieren-Button mit Bestätigungs-Dialog („Mozilla Firefox
  → Mozilla.Firefox richtig?")
- `low` → orange, Bestätigungs-Dialog mit deutlichem Warnhinweis
- `none` → grau, kein Aktivieren-Button, Hinweis auf manuelle Handhabung

Das Enrichment läuft nicht im nightly-Scan, sondern als separater täglicher
Job, damit der Scan selbst schnell bleibt. Ergebnisse werden in
`discovery_enrichment` mit 7 Tagen TTL gecached — wiederholte Scans derselben
Display-Namen treffen den Cache, kein erneuter REST-Call.

## 11. Bekannte Einschränkungen

| # | Einschränkung | Grund / Mitigation |
|---|---|---|
| 1 | Nur `--scope machine` | winget als SYSTEM kann keine User-Scope-Apps installieren. MVP: immer machine versuchen, bei User-only-Apps klarer Fehler-Log. Phase 2 optional: scheduled-task-Fallback als logged-in User. |
| 2 | Nur offizielle `winget`-Source | Community-Repos oder Custom-Sources nicht unterstützt. Hardcoded `--source winget` im Scan und Dispatch. |
| 3 | Version-Pinning verschoben | `winget_version`-Spalte wird migriert, aber MVP-UI hat keinen Picker. Immer „latest" beim Dispatch. |
| 4 | Keine Collision-Detection | Admin kann dasselbe Paket doppelt whitelisten (z. B. Firefox via Choco UND Winget). Kiosk zeigt dann zwei Rows. Admin-Verantwortung. |
| 5 | Text-Parser statt strukturierte Objekte | Buffer-Breite auf 512 setzen, Truncation-Detection, positional Parsing. Siehe Abschnitt 9 für Phase-2-Plan. |
| 6 | Fleet-Discovery ist best-effort | Display-Name-Varianten können Enrichment-Match verfehlen. Admin sieht Confidence-Label und kann unsichere Treffer überspringen. |
| 7 | Kein Rollback nach failed Upgrade | Verhalten identisch zum bestehenden Choco-Dispatch. User sieht Fehler im Kiosk, Admin prüft Logs. |
| 8 | Nightly-Scan umgeht offline-Agents | Pre-Filter via eigener kiosk-client last_seen (5 min), offline-Agents landen in `agent_scan_meta.last_status='offline'`, blockieren den Batch nicht. |
| 9 | User-Wunschliste nicht integriert | Software-Wünsche kommen außerhalb von Softshelf als Ticket rein, Admin whitelisted manuell. |

## 12. Rollout-Plan

1. **Branch:** `feature/winget` vom aktuellen `main` auf der Test-Instanz.
2. **Schema + Backend:**
   - `database.py` Migrationen und Helper
   - `winget_catalog.py`, `winget_scanner.py`, `winget_enrichment.py`
   - `main.py` APScheduler-Wiring
   - `requirements.txt` um `apscheduler` erweitern
3. **Routes:** `admin.py`, `packages.py`, `install.py` erweitern.
4. **Admin-UI:** `templates/admin.html` Winget-Tab, Discovery-Block, Header-Badge.
5. **Build + Hot-Reload im Container:**
   `docker-compose build softshelf-proxy && docker-compose up -d softshelf-proxy`
6. **End-to-End-Test** gegen die angebundene Tactical-Instanz:
   - Winget-Katalog-Suche
   - Fleet-Discovery mit Enrichment
   - Install → Scan → Upgrade → Scan → Uninstall Zyklus auf einem Test-Agent
7. **Commit + Push** nach Sign-off, Merge von `feature/winget` nach `main`.

## 13. Offene Implementierungsfragen

Diese Fragen werden während der Implementierung entschieden, nicht jetzt:

- **Scheduler-Interval konfigurierbar?** Aktuell hardcoded auf 24 h nightly.
  Admin-Setting dazu bauen oder erstmal hardcoded? → Tendenz: hardcoded,
  Setting ist leicht nachzurüsten.
- **Retry-Policy bei `consecutive_failures >= 7`:** komplett stoppen bis
  manueller Re-Scan, oder Backoff (alle 3 Tage einen Versuch)? → Tendenz:
  komplett stoppen, Re-Scan-Button im UI.
- **Discovery-Enrichment Normalisierung:** welche Klammer-Suffixe werden
  entfernt? („x64 de", „x86", „2020", Versionsnummern am Ende…) Wird iterativ
  beim Test-Durchlauf getunt.
- **Rate-Limiting gegen manifestSearch:** das öffentliche Endpoint hat
  undokumentierte Rate-Limits. MVP fügt ein weiches Limit von 10 Requests/s
  im Enrichment-Job ein. Falls das in der Praxis zu wenig ist, wird's erhöht.
