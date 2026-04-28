"""
Reboot Dialog - pywebview implementation.

Design: Centered card on dark overlay (Option A from brainstorm).
Always-on-top, not resizable. Countdown with auto-reboot.
"""
import threading

import webview

from api_client import KioskApiClient
from _version import __version__


_REBOOT_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Neustart erforderlich</title>
<style>
*, *::before, *::after {{
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}}

:root {{
  --bg: #ffffff;
  --bg-soft: #fafafa;
  --border: #e4e4e7;
  --fg: #18181b;
  --fg-2: #27272a;
  --fg-3: #52525b;
  --fg-4: #71717a;
  --fg-5: #a1a1aa;
  --red: #ef4444;
  --radius: 14px;
  --transition: 150ms cubic-bezier(0.4, 0, 0.2, 1);
}}

html, body {{
  height: 100%;
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  color: var(--fg);
  background: rgba(0, 0, 0, 0.6);
  -webkit-font-smoothing: antialiased;
  overflow: hidden;
  user-select: none;
  display: flex;
  align-items: center;
  justify-content: center;
}}

/* ─── Card ─── */
.card {{
  background: var(--bg);
  border-radius: var(--radius);
  width: 380px;
  box-shadow:
    0 25px 50px -12px rgba(0, 0, 0, 0.25),
    0 0 0 1px rgba(255, 255, 255, 0.05);
  animation: cardIn 300ms cubic-bezier(0.16, 1, 0.3, 1);
  overflow: hidden;
}}
@keyframes cardIn {{
  from {{
    opacity: 0;
    transform: scale(0.95) translateY(10px);
  }}
  to {{
    opacity: 1;
    transform: scale(1) translateY(0);
  }}
}}

/* ─── Header ─── */
.card-header {{
  padding: 24px 28px 0;
}}
.header-row {{
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}}
.header-icon {{
  width: 38px;
  height: 38px;
  background: var(--fg);
  border-radius: 9px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}}
.header-icon svg {{
  width: 20px;
  height: 20px;
}}
.header-titles {{
  flex: 1;
}}
.header-title {{
  font-size: 15px;
  font-weight: 600;
  color: var(--fg);
  letter-spacing: -0.3px;
}}
.header-subtitle {{
  font-size: 11px;
  color: var(--fg-4);
  margin-top: 1px;
}}

/* ─── Separator ─── */
.separator {{
  height: 1px;
  background: var(--border);
  margin: 0 28px;
}}

/* ─── Body ─── */
.card-body {{
  padding: 20px 28px;
}}
.message {{
  font-size: 13px;
  color: var(--fg-3);
  line-height: 1.6;
  margin-bottom: 24px;
}}

/* ─── Countdown ─── */
.countdown-container {{
  text-align: center;
  margin-bottom: 12px;
}}
.countdown {{
  font-size: 48px;
  font-weight: 700;
  color: var(--fg);
  font-family: 'Cascadia Mono', 'Consolas', 'SF Mono', ui-monospace, monospace;
  letter-spacing: -2px;
  line-height: 1;
  transition: color 500ms ease;
}}
.countdown.urgent {{
  color: var(--red);
}}

/* ─── Progress ─── */
.progress-container {{
  margin-bottom: 8px;
}}
.progress-bar {{
  height: 4px;
  background: var(--border);
  border-radius: 2px;
  overflow: hidden;
}}
.progress-fill {{
  height: 100%;
  background: var(--red);
  border-radius: 2px;
  transition: width 1s linear;
}}
.progress-hint {{
  font-size: 10px;
  color: var(--fg-5);
  text-align: center;
  margin-top: 8px;
}}

/* ─── Buttons ─── */
.card-footer {{
  border-top: 1px solid var(--border);
  padding: 16px 28px;
  display: flex;
  gap: 10px;
}}
.btn {{
  flex: 1;
  padding: 11px 20px;
  font-size: 13px;
  font-weight: 500;
  border: none;
  border-radius: 9px;
  cursor: pointer;
  transition: all var(--transition);
  outline: none;
}}
.btn-defer {{
  background: var(--bg);
  color: var(--fg-3);
  border: 1px solid var(--border);
}}
.btn-defer:hover {{
  background: var(--bg-soft);
  border-color: #d4d4d8;
}}
.btn-defer:active {{
  background: #f4f4f5;
}}
.btn-now {{
  background: var(--fg);
  color: white;
  font-weight: 600;
}}
.btn-now:hover {{
  background: var(--fg-2);
}}
.btn-now:active {{
  background: #000;
}}
.btn:disabled {{
  opacity: 0.5;
  cursor: not-allowed;
}}
</style>
</head>
<body>
<div class="card">
  <div class="card-header">
    <div class="header-row">
      <div class="header-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <polyline points="12 6 12 12 16 14"/>
        </svg>
      </div>
      <div class="header-titles">
        <div class="header-title">Neustart erforderlich</div>
        <div class="header-subtitle" id="subtitle">{app_name}</div>
      </div>
    </div>
  </div>

  <div class="separator"></div>

  <div class="card-body">
    <div class="message" id="message">{message}</div>

    <div class="countdown-container">
      <div class="countdown" id="countdown">00:00</div>
    </div>

    <div class="progress-container">
      <div class="progress-bar">
        <div class="progress-fill" id="progressFill" style="width:100%"></div>
      </div>
      <div class="progress-hint">Automatischer Neustart nach Ablauf</div>
    </div>
  </div>

  <div class="card-footer">
    <button class="btn btn-defer" id="btnDefer" onclick="deferReboot()" {defer_display}>Verschieben</button>
    <button class="btn btn-now" id="btnNow" onclick="rebootNow()">Jetzt neustarten</button>
  </div>
</div>

<script>
'use strict';

const TOTAL = {total_seconds};
let remaining = TOTAL;
let interval = null;

function updateDisplay() {{
  const m = Math.floor(remaining / 60);
  const s = remaining % 60;
  const el = document.getElementById('countdown');
  el.textContent = String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');

  // Urgent state when <60s
  if (remaining <= 60) {{
    el.classList.add('urgent');
  }}

  // Progress bar
  const pct = (remaining / TOTAL) * 100;
  document.getElementById('progressFill').style.width = pct + '%';
}}

function tick() {{
  remaining--;
  if (remaining <= 0) {{
    remaining = 0;
    updateDisplay();
    clearInterval(interval);
    // Auto-reboot
    pywebview.api.on_auto_reboot();
    disableButtons();
    return;
  }}
  updateDisplay();
}}

function rebootNow() {{
  disableButtons();
  pywebview.api.on_reboot_now();
}}

function deferReboot() {{
  disableButtons();
  pywebview.api.on_defer();
}}

function disableButtons() {{
  document.getElementById('btnNow').disabled = true;
  const defer = document.getElementById('btnDefer');
  if (defer) defer.disabled = true;
}}

// Start
updateDisplay();
interval = setInterval(tick, 1000);
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────── Python API Bridge ────

class RebootApi:
    """JS-to-Python bridge for the reboot dialog."""

    def __init__(self, api_client: KioskApiClient, run_id: int | None,
                 on_done: callable):
        self._api = api_client
        self._run_id = run_id
        self._on_done = on_done
        self._handled = False

    def on_reboot_now(self):
        if self._handled:
            return
        self._handled = True
        if self._run_id:
            self._api.workflow_reboot_now(self._run_id)
        self._on_done("now")

    def on_auto_reboot(self):
        if self._handled:
            return
        self._handled = True
        if self._run_id:
            self._api.workflow_reboot_now(self._run_id)
        self._on_done("auto")

    def on_defer(self):
        if self._handled:
            return
        self._handled = True
        if self._run_id:
            self._api.workflow_defer(self._run_id)
        self._on_done("defer")


# ────────────────────────────────────────────────────── Window Management ─────

_reboot_window: webview.Window | None = None
_reboot_lock = threading.Lock()


def show_reboot_dialog(
    api_client: KioskApiClient,
    run_id: int | None,
    message: str = "Es wurden Updates installiert die einen Neustart erfordern.",
    countdown: int = 300,
    can_defer: bool = True,
    app_name: str = "Softshelf",
    on_done: callable = None,
):
    """Show the reboot dialog window. Thread-safe, creates a new window."""
    global _reboot_window

    def _handle_done(result: str):
        """Callback when user makes a choice."""
        global _reboot_window
        with _reboot_lock:
            if _reboot_window is not None:
                try:
                    _reboot_window.destroy()
                except Exception:
                    pass
                _reboot_window = None
        if on_done:
            on_done(result)

    with _reboot_lock:
        # Destroy existing if any
        if _reboot_window is not None:
            try:
                _reboot_window.destroy()
            except Exception:
                pass
            _reboot_window = None

        js_api = RebootApi(api_client, run_id, _handle_done)

        from html import escape as _h
        html = _REBOOT_HTML.format(
            app_name=_h(app_name),
            message=_h(message),
            total_seconds=max(countdown, 10),
            defer_display='' if can_defer else 'style="display:none"',
        )

        _reboot_window = webview.create_window(
            f"{app_name} \u2014 Neustart",
            html=html,
            js_api=js_api,
            width=440,
            height=380,
            resizable=False,
            on_top=True,
            text_select=False,
        )
        _reboot_window.events.closed += lambda: _on_reboot_closed(js_api)


def _on_reboot_closed(js_api: RebootApi):
    """Handle window closed via X button - treat as defer if not handled."""
    global _reboot_window
    with _reboot_lock:
        _reboot_window = None
    # If user closed without choosing, don't call API - just reset state
    if not js_api._handled:
        js_api._handled = True


def destroy_reboot_window():
    """Force close the reboot dialog."""
    global _reboot_window
    with _reboot_lock:
        if _reboot_window is not None:
            try:
                _reboot_window.destroy()
            except Exception:
                pass
            _reboot_window = None
