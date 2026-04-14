# Softshelf

A self-service software portal for managed Windows fleets, built on top of
[Tactical RMM](https://tacticalrmm.com). End users open a tray icon, see a
curated whitelist of software, click *Install* — and Tactical runs the silent
install as SYSTEM in the background. No admin rights on the endpoint, no ticket
queue for the IT team, and no direct exposure of the RMM API to end users.

Softshelf is designed for internal deployment: you run it on a Linux host in
your own network, point your Tactical agents at it, and manage the whitelist
from a browser.

---

## What you get

- **Curated whitelist** combining three package sources side-by-side:
  - **Chocolatey** packages (browse and enable from `community.chocolatey.org`),
  - **Self-hosted MSI/EXE installers** and multi-file program folders
    (uploaded as ZIP), and
  - **Microsoft winget** packages — search the official catalog locally from
    a daily-refreshed mirror of `cdn.winget.microsoft.com/cache/source.msix`,
    enable a package with one click, and have the agent install/upgrade
    silently as SYSTEM via `winget install --scope machine`.
- **Per-agent inventory for winget AND choco** built nightly. Two schedulers
  run on every online agent: the winget scanner triggers `winget export` +
  `winget upgrade` and the choco scanner triggers `choco list` +
  `choco outdated`. Both feed structured per-agent state tables. The agent
  detail view in the admin UI deduplicates the result with the Tactical
  software-scan and surfaces a single combined per-agent software list —
  including which packages are managed by Softshelf, which source they
  come from (winget / choco / custom), which are installed but unmanaged,
  and which have upgrades waiting.
- **Fleet discovery** that turns the nightly scan into actionable suggestions:
  any winget package installed on at least one agent but not yet whitelisted
  shows up in a one-click *Activate* list. A bonus enrichment pass takes
  Tactical software-scan display names and fuzzy-matches them against the
  winget catalog with a confidence label.
- **Silent install + uninstall** via Tactical RMM's agent command channel.
  The end user never sees a UAC prompt, never types credentials, never waits
  for a ticket. Choco, custom and winget all share the same dispatch path
  (Tactical `run_command` with PowerShell wrapper, captured stdout, exit
  code checking, and known-failure-pattern detection — so a broken upstream
  package like `choco install 3cx` whose installer 404s lands as a
  human-readable error banner in the admin UI instead of disappearing into
  Tactical fire-and-forget land).
- **Version tracking** per uploaded package. Softshelf knows which agent runs
  which version, and lets an admin push updates to every outdated endpoint
  with a single click. For winget packages the upgrade state comes straight
  from `winget upgrade`, no manual tracking needed.
- **Admin UI** in the browser: search Chocolatey + winget, enable/disable
  packages, upload custom installers, browse a per-agent software detail page
  with install/upgrade/uninstall buttons, watch the distribution tab, browse
  the audit log.
- **Self-contained clients** — a Windows tray app and a tkinter-based
  installer, built inside the repo via a Wine + PyInstaller container.
- **CI branding** — three independent settings let you brand each surface
  on its own terms:
  - `admin_portal_title` (free text, e.g. `Acme IT Self-Service`) — browser
    tab and admin UI header. Reload to apply.
  - `client_app_name` (free text, e.g. `Acme Software Center`) — window
    title, tray tooltip and dialogs of the Windows tray client. Picked up
    at every kiosk launch, no rebuild needed.
  - `product_slug` (strict, e.g. `AcmeSoft`) — filesystem-safe identifier
    used for the EXE filename, install directory, registry key, autostart
    entry and proxy URL environment variable. Change requires a rebuild
    plus reinstall on the endpoints.
- **Multi-admin** with local passwords (scrypt-hashed) and optional Microsoft
  Entra ID SSO.

---

## Architecture at a glance

Three components, all running on a single Linux host via `docker compose`:

| Service | What it does | Exposed? |
|---|---|---|
| **softshelf-proxy** | FastAPI + SQLite. Admin UI, API, state, download endpoints. | Yes — HTTP on 8765 |
| **softshelf-builder** | Cross-compiles `softshelf.exe` / `softshelf-setup.exe` under Wine + PyInstaller. | Internal only |
| *Windows clients* | Compiled tray app deployed to managed PCs via Tactical. | — |

```
┌───────────────────────────────────────────────────────────┐
│  Linux host (docker compose)                              │
│                                                           │
│   softshelf-proxy  ───── internal HTTP ─────▶ softshelf-   │
│   (FastAPI, 8765)                             builder     │
│       │                                       (Wine,      │
│       │                                        PyInstaller)│
│       ▼                                                    │
│   shared  ./downloads  volume ─── built EXEs ──▶           │
└───────────────────────────────────────────────────────────┘
            │                                 │
     HTTP + JWT Bearer                  HTTPS + API key
            │                                 │
            ▼                                 ▼
   ┌────────────────┐                ┌────────────────┐
   │ softshelf.exe  │                │  Tactical RMM  │
   │ on Windows PC  │                │   (external)   │
   └────────────────┘                └────────────────┘
```

The full architecture — database schema, API surface, auth flows, install
data flow, security model — is documented in [`ARCHITEKTUR.md`](ARCHITEKTUR.md).
The in-app help tab (`proxy/templates/admin_help.html`) covers day-to-day
admin workflows.

---

## How installs actually work

1. End user clicks *Install Firefox* in the tray app.
2. The client `POST`s to `/api/v1/install` with its machine token.
3. The proxy looks the package up in its whitelist and dispatches by type:
4. **Chocolatey package?** The proxy tells Tactical to run `choco install`
   on the agent — done.
5. **Winget package?** The proxy resolves the bundled `winget.exe` from the
   per-machine WindowsApps directory (the user-shim isn't on SYSTEM PATH),
   builds a PowerShell wrapper around
   `winget install --id <ID> --scope machine --silent --accept-package-agreements --accept-source-agreements --disable-interactivity -h`,
   and dispatches it via Tactical's command channel. After the command
   returns, the proxy chains a targeted re-scan so the kiosk shows fresh
   state within seconds. If the agent already has the package, the same
   button transparently runs `winget upgrade` instead.
6. **Custom MSI/EXE?** The proxy mints a short-lived signed download URL
   (5-minute JWT, bound to package hash + agent ID), builds a PowerShell
   command, and dispatches it via Tactical's command channel. The agent
   downloads the file from the proxy, runs the installer, and reports back.
7. **Failures from any of the three sources** land in
   `agent_scan_meta.last_action_error` and surface as a yellow warning
   banner on the agent detail page. Known failure modes get a human
   message (`Likely broken for FOSS users` for choco packages with paid
   downloads, `install technology is different` for winget OS-managed
   packages like Edge, etc.) — anything unknown surfaces with the raw
   choco/winget exit code and the trailing output.
8. The proxy records the installed version against that agent for later
   outdated-detection and push updates. For winget the upgrade state comes
   from `winget export` + `winget upgrade`. For choco it comes from
   `choco list --limit-output` + `choco outdated --limit-output`. Both run
   nightly via APScheduler and after every targeted action.

There is no persistent reverse-tunnel, no open port on the endpoint, and
no shared credential on the client side — just a signed JWT issued once
at deployment time.

---

## Quickstart

**Prerequisites:** a Linux host with Docker + `docker compose`, and an
existing Tactical RMM instance with an API key.

```bash
git clone https://github.com/jedijarrus/softshelf /opt/softshelf
cd /opt/softshelf

cp .env.example .env
$EDITOR .env
#   SECRET_KEY=<openssl rand -hex 32>
#   ADMIN_PASSWORD=<something strong>

docker compose up -d --build
# first build: proxy ~1 min, builder ~5–8 min
```

Open `http://<host>:8765/admin`, log in with the credentials from `.env`,
and fill in *Settings*:

- Tactical URL + API key
- Registration secret (used to enroll new clients)
- Public proxy URL (this is the URL burned into the built installer)

Click **Build EXEs** to produce `softshelf-setup.exe`, then deploy it to your
fleet via Tactical (there's a ready-to-use PowerShell script under
`installer/deploy_via_trmm.ps1`).

> **TLS.** The proxy speaks plain HTTP on purpose — put Caddy, Traefik, or
> nginx in front of it for TLS termination. The session cookie automatically
> flips to `Secure` when the proxy sees `X-Forwarded-Proto: https` from a
> trusted loopback reverse proxy.

---

## Security model

Softshelf effectively grants its admins SYSTEM-level code execution on every
enrolled endpoint — any custom package with a custom PowerShell command can
run arbitrary code via Tactical. Treat the admin role accordingly.

What the project does to keep that blast radius contained:

- **Machine tokens** — HS256 JWT, bound to agent ID + hostname, with
  per-agent revocation (`token_version` bump) and an explicit ban list that
  survives agent deletion.
- **Signed download URLs** — custom installers are served under a 5-minute
  JWT bound to both the file hash and the target agent ID.
- **Session cookies** — `HttpOnly` + `SameSite=Strict` + `Secure`
  (conditional on detected HTTPS), path-scoped to `/admin`.
- **CSRF** — double-submit check on every state-changing admin call
  (`Origin`/`Referer` match or `X-Requested-With`).
- **Rate limits** — 5/min on `/api/v1/register`, 60/min on `/admin/*`,
  with `X-Forwarded-For` trust limited to loopback-origin proxies.
- **Input validation** — tight regex allow-lists for package names, agent
  IDs, version labels, usernames, file paths. No `..`, no shell metacharacters
  that reach a subprocess.
- **XSS hardening** — the admin UI uses a distinct `jsStr()` helper for
  JS-string-in-HTML-attribute contexts (plain `esc()` is not enough; the
  HTML parser decodes `&#39;` back to `'` and breaks out of the string).
- **Build pipeline** — values injected into `_build_config.py` go through
  `repr()` in a Python subprocess with an allow-list of characters, so an
  attacker-controlled proxy URL cannot inject Python code into the built
  EXE.
- **SQLite integrity** — every connection sets `PRAGMA foreign_keys = ON`
  via a shared helper, so `ON DELETE CASCADE` clauses actually fire.
- **Non-root container** — the proxy runs as UID 1001 after `gosu`-dropping
  from root in the entrypoint.

See [`ARCHITEKTUR.md`](ARCHITEKTUR.md) §Authentifizierung & Sicherheit for
the long version, including what is *intentionally* out of scope (local
MFA, one-time registration tokens, code-signing verification on uploads,
4-eyes on package push — the admin is trusted).

---

## Repository layout

```
softshelf/
├── proxy/                # FastAPI backend + admin UI
│   ├── main.py           # app setup, lifespan, APScheduler wiring,
│   │                     # public endpoints
│   ├── routes/           # register, packages, install, admin
│   ├── middleware/       # CSRF, rate limit, audit logger
│   ├── templates/        # admin.html, admin_login.html, admin_help.html
│   ├── database.py       # schema + migrations + helpers
│   ├── auth.py           # machine tokens, download tokens
│   ├── admin_auth.py     # scrypt, sessions, Entra OIDC
│   ├── tactical_client.py # Tactical RMM API wrapper
│   ├── winget_catalog.py # local mirror of the Microsoft winget source
│   ├── winget_scanner.py # nightly + targeted per-agent winget scan
│   ├── winget_enrichment.py # daily Tactical-scan → winget-id matcher
│   ├── choco_scanner.py  # nightly + targeted per-agent choco scan
│   │                     # (choco list + choco outdated)
│   └── Dockerfile
├── builder/              # Wine + PyInstaller cross-compile service
│   ├── server.py
│   └── build.sh
├── client/               # Windows tray app + installer (PyQt5 + tkinter)
│   ├── main.py
│   ├── ui/               # tray.py, package_window.py
│   ├── api_client.py
│   └── setup.py
├── installer/            # manual build script + Tactical deploy template
├── docs/superpowers/specs/ # design specs (e.g. winget feature)
├── ARCHITEKTUR.md        # full architecture doc (German)
├── docker-compose.yml
└── .env.example
```

---

## Contributing & status

Softshelf ships roughly what the author needed to run a small internal
software portal: the UI is in German, the docs are in German, the audit-log
timestamps are in Europe/Berlin. It is published here in case any of that is
useful to someone else running a Tactical RMM fleet. Pull requests are
welcome; issues less so — this is a small side project with no SLA.

---

## License

MIT — see [`LICENSE`](LICENSE).
