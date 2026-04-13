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

- **Curated whitelist** of Chocolatey packages plus self-hosted MSI/EXE
  installers and multi-file program folders (uploaded as ZIP).
- **Silent install + uninstall** via Tactical RMM's agent command channel.
  The end user never sees a UAC prompt, never types credentials, never waits
  for a ticket.
- **Version tracking** per uploaded package. Softshelf knows which agent runs
  which version, and lets an admin push updates to every outdated endpoint
  with a single click.
- **Admin UI** in the browser: search Chocolatey, enable/disable packages,
  upload custom installers, watch the distribution tab, browse the audit log.
- **Self-contained clients** — a Windows tray app and a tkinter-based
  installer, built inside the repo via a Wine + PyInstaller container.
- **CI branding** — set a `product_slug` in the admin UI and the next build
  produces `<slug>.exe` / `<slug>-setup.exe`, installs into
  `C:\Program Files\<slug>\`, writes its registry under
  `HKLM\SOFTWARE\<slug>\`, and uses `<SLUG>_PROXY_URL` as its environment
  variable. The default slug is `Softshelf`; change it once before the
  first rollout.
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
3. The proxy looks the package up in its whitelist.
4. **Chocolatey package?** The proxy tells Tactical to run `choco install`
   on the agent — done.
5. **Custom MSI/EXE?** The proxy mints a short-lived signed download URL
   (5-minute JWT, bound to package hash + agent ID), builds a PowerShell
   command, and dispatches it via Tactical's command channel. The agent
   downloads the file from the proxy, runs the installer, and reports back.
6. The proxy records the installed version against that agent for later
   outdated-detection and push updates.

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
│   ├── main.py           # app setup, public endpoints
│   ├── routes/           # register, packages, install, admin
│   ├── middleware/       # CSRF, rate limit, audit logger
│   ├── templates/        # admin.html, admin_login.html, admin_help.html
│   ├── database.py       # schema + migrations + helpers
│   ├── auth.py           # machine tokens, download tokens
│   ├── admin_auth.py     # scrypt, sessions, Entra OIDC
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
