"""
Mitteilungs-Fenster (v2.10) — pywebview.

Zwei Darstellungen:
- "wichtig":  rahmenloses Hinweisfenster unten rechts ueber der Taskleiste.
              Schliesst per Klick oder nach 60 s (Timer pausiert bei Hover).
- "kritisch": Fenster in der Bildschirmmitte, immer im Vordergrund, ohne
              Schliessen-Kreuz — geht nur mit "Verstanden" weg.

Mehrere Mitteilungen werden nacheinander gezeigt (Warteschlange). Inhalte
kommen ueber die JS-Bridge (get_payload) und werden per textContent gesetzt —
kein HTML aus Serverdaten im Template.
"""
import collections
import ctypes
import logging
import threading
import webbrowser
from ctypes import wintypes

import webview

logger = logging.getLogger("softshelf.message")

_AUTO_CLOSE_S = 60

_HTML = r"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>Mitteilung</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #ffffff;
  --bg-soft: #fafafa;
  --border: #e4e4e7;
  --fg: #18181b;
  --fg-3: #52525b;
  --fg-4: #71717a;
  --fg-5: #a1a1aa;
  --accent: #2563eb;
  --accent-bg: #eff6ff;
  --ease: cubic-bezier(0.16, 1, 0.3, 1);
}
.sev-wichtig  { --accent: #b45309; --accent-bg: #fffbeb; }
.sev-kritisch { --accent: #dc2626; --accent-bg: #fef2f2; }
html, body {
  height: 100%;
  font-family: 'Segoe UI Variable Text', 'Segoe UI', system-ui, sans-serif;
  color: var(--fg);
  background: var(--bg);
  -webkit-font-smoothing: antialiased;
  overflow: hidden;
}
body { display: flex; flex-direction: column; border: 1px solid var(--border); }
.bar { height: 3px; background: var(--accent); flex-shrink: 0; }
.head { display: flex; align-items: flex-start; gap: 12px; padding: 16px 18px 0; }
.icon {
  width: 32px; height: 32px; border-radius: 8px; flex-shrink: 0;
  background: var(--accent-bg); color: var(--accent);
  display: flex; align-items: center; justify-content: center;
}
.icon svg { width: 18px; height: 18px; }
.titles { flex: 1; min-width: 0; }
.kicker { font-size: 11.5px; font-weight: 600; color: var(--fg-4); letter-spacing: .01em; }
.title { font-size: 15px; font-weight: 600; line-height: 1.35; margin-top: 2px; overflow-wrap: anywhere; }
.close {
  width: 28px; height: 28px; border: 0; border-radius: 6px; background: transparent;
  color: var(--fg-4); cursor: pointer; display: flex; align-items: center; justify-content: center;
  margin: -4px -6px 0 0; flex-shrink: 0;
}
.close:hover { background: var(--bg-soft); color: var(--fg); }
.close:focus-visible, .btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.close svg { width: 16px; height: 16px; }
.body {
  flex: 1; min-height: 0; overflow-y: auto;
  padding: 10px 18px 4px 62px;
  font-size: 13px; line-height: 1.55; color: var(--fg-3);
  white-space: pre-wrap; overflow-wrap: anywhere; user-select: text;
}
.foot { display: flex; gap: 8px; justify-content: flex-end; align-items: center; padding: 12px 18px 16px; }
.hint { flex: 1; font-size: 11.5px; color: var(--fg-5); }
.btn {
  font: inherit; font-size: 13px; font-weight: 500; padding: 8px 14px; border-radius: 8px;
  border: 1px solid var(--border); background: var(--bg); color: var(--fg); cursor: pointer;
  transition: background 120ms ease, border-color 120ms ease;
}
.btn:hover { background: var(--bg-soft); border-color: #d4d4d8; }
.btn.primary { background: var(--fg); border-color: var(--fg); color: #fff; font-weight: 600; }
.btn.primary:hover { background: #27272a; }
.timer { height: 2px; background: var(--border); flex-shrink: 0; }
.timer i { display: block; height: 100%; width: 100%; background: var(--accent); opacity: .55; transform-origin: left; }
.card { flex: 1; display: flex; flex-direction: column; min-height: 0; animation: in 260ms var(--ease); }
@keyframes in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
.mode-kritisch .head { padding: 22px 24px 0; }
.mode-kritisch .title { font-size: 17px; }
.mode-kritisch .body { padding: 12px 24px 4px 68px; font-size: 13.5px; }
.mode-kritisch .foot { padding: 16px 24px 20px; }
@media (prefers-reduced-motion: reduce) { .card { animation: none; } }
</style>
</head>
<body class="__CLASSES__">
<div class="bar"></div>
<div class="card">
  <div class="head">
    <div class="icon" aria-hidden="true">__ICON__</div>
    <div class="titles">
      <div class="kicker" id="kicker"></div>
      <div class="title" id="title"></div>
    </div>
    __CLOSE__
  </div>
  <div class="body" id="body"></div>
  <div class="foot">
    <div class="hint" id="hint"></div>
    <button class="btn" id="link" style="display:none" onclick="openLink()"></button>
    <button class="btn primary" id="ok" onclick="done()"></button>
  </div>
</div>
__TIMER__
<script>
'use strict';
const MODE = '__MODE__';
const AUTO_MS = __AUTO_MS__;
let closed = false, left = AUTO_MS, last = Date.now(), paused = false;

function done() {
  if (closed) return;
  closed = true;
  pywebview.api.close(MODE === 'kritisch' ? 'acked' : 'closed');
}
function openLink() { pywebview.api.open_link(); }

window.addEventListener('pywebviewready', async () => {
  const p = await pywebview.api.get_payload();
  document.getElementById('kicker').textContent = p.header || '';
  document.getElementById('title').textContent = p.title || '';
  document.getElementById('body').textContent = p.body || '';
  if (!p.body) document.getElementById('body').style.display = 'none';
  const link = document.getElementById('link');
  if (p.link_url) { link.textContent = p.link_label || 'Öffnen'; link.style.display = ''; }
  document.getElementById('ok').textContent = MODE === 'kritisch' ? 'Verstanden' : 'Schließen';
  if (MODE === 'kritisch') document.getElementById('hint').textContent = 'Bitte bestätigen, um fortzufahren.';
  document.getElementById('ok').focus();
  pywebview.api.shown();
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && MODE !== 'kritisch') done();
});

if (AUTO_MS > 0) {
  document.addEventListener('mouseenter', () => { paused = true; });
  document.addEventListener('mouseleave', () => { paused = false; last = Date.now(); });
  const bar = document.querySelector('.timer i');
  setInterval(() => {
    if (closed || paused) return;
    const now = Date.now();
    left -= now - last; last = now;
    if (bar) bar.style.transform = 'scaleX(' + Math.max(0, left / AUTO_MS) + ')';
    if (left <= 0) { closed = true; pywebview.api.close('timeout'); }
  }, 200);
}
</script>
</body>
</html>"""

_ICONS = {
    "wichtig": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
               'stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/>'
               '<path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>',
    "kritisch": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
                'stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>'
                '<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
}
_CLOSE_BTN = ('<button class="close" aria-label="Schließen" onclick="done()">'
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">'
              '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>')


def _render(mode: str) -> str:
    return (_HTML
            .replace("__CLASSES__", f"sev-{mode} mode-{mode}")
            .replace("__ICON__", _ICONS[mode])
            .replace("__CLOSE__", _CLOSE_BTN if mode == "wichtig" else "")
            .replace("__TIMER__", '<div class="timer"><i></i></div>' if mode == "wichtig" else "")
            .replace("__MODE__", mode)
            .replace("__AUTO_MS__", str(_AUTO_CLOSE_S * 1000 if mode == "wichtig" else 0)))


def _estimate_height(msg: dict, mode: str) -> int:
    """Fensterhoehe grob aus der Textlaenge — Rest scrollt im Body."""
    per_line = 50 if mode == "wichtig" else 64
    lines = 0
    for para in (msg.get("body") or "").split("\n"):
        lines += max(1, -(-len(para) // per_line))
    if not (msg.get("body") or "").strip():
        lines = 0
    title_lines = max(1, -(-len(msg.get("title") or "") // (per_line - 8)))
    base = 124 if mode == "wichtig" else 136
    h = base + title_lines * 21 + lines * 21
    return max(170, min(h, 420 if mode == "wichtig" else 540))


def _work_area() -> tuple[int, int, int, int] | None:
    """Arbeitsbereich (ohne Taskleiste) in logischen Pixeln."""
    try:
        rect = wintypes.RECT()
        ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0)  # SPI_GETWORKAREA
        try:
            scale = ctypes.windll.user32.GetDpiForSystem() / 96.0
        except Exception:
            scale = 1.0
        scale = scale or 1.0
        return (int(rect.left / scale), int(rect.top / scale),
                int(rect.right / scale), int(rect.bottom / scale))
    except Exception:
        return None


class MessageApi:
    """JS-Bridge eines Mitteilungsfensters."""

    def __init__(self, msg: dict, mode: str, on_shown, on_close):
        self._msg = msg
        self._mode = mode
        self._on_shown = on_shown
        self._on_close = on_close
        self._shown = False
        self.handled = False

    def get_payload(self) -> dict:
        m = self._msg
        return {k: str(m.get(k) or "") for k in ("header", "title", "body", "link_url", "link_label")}

    def shown(self):
        if not self._shown:
            self._shown = True
            if self._on_shown:
                self._on_shown()

    def open_link(self):
        url = str(self._msg.get("link_url") or "")
        if url.lower().startswith("https://"):
            try:
                webbrowser.open(url)
            except Exception:
                logger.exception("Link konnte nicht geoeffnet werden")

    def close(self, result: str):
        if self.handled:
            return
        self.handled = True
        self._on_close(result)


# ── Warteschlange + Fensterverwaltung ─────────────────────────────────────────

_queue: collections.deque = collections.deque()
_lock = threading.Lock()
_window: "webview.Window | None" = None


def enqueue_message(msg: dict, app_name: str = "Softshelf", on_shown=None, on_done=None):
    """Mitteilung anzeigen, sobald kein anderes Mitteilungsfenster offen ist.
    Kritische Mitteilungen ruecken in der Warteschlange nach vorn."""
    item = (msg, app_name, on_shown, on_done)
    with _lock:
        if (msg.get("severity") or "") == "kritisch":
            _queue.appendleft(item)
        else:
            _queue.append(item)
        busy = _window is not None
    if not busy:
        _show_next()


def _show_next():
    global _window
    with _lock:
        if _window is not None or not _queue:
            return
        msg, app_name, on_shown, on_done = _queue.popleft()
        mode = "kritisch" if msg.get("severity") == "kritisch" else "wichtig"
        width = 380 if mode == "wichtig" else 480
        height = _estimate_height(msg, mode)
        x = y = None
        if mode == "wichtig":
            wa = _work_area()
            if wa:
                x, y = wa[2] - width - 16, wa[3] - height - 16

        def on_close(result: str):
            _finish(result, on_done)

        api = MessageApi(msg, mode, on_shown, on_close)
        title = f"{app_name} — {msg.get('header') or 'Mitteilung'}"
        try:
            _window = webview.create_window(
                title, html=_render(mode), js_api=api,
                width=width, height=height, x=x, y=y,
                resizable=False, frameless=True, easy_drag=(mode == "wichtig"),
                on_top=True, focus=True, text_select=True,
            )
        except Exception:
            _window = None
            logger.exception("Mitteilungsfenster konnte nicht erstellt werden")
            if on_done:
                on_done("closed_unacked" if mode == "kritisch" else "closed")
            return
        _window.events.closed += lambda: _on_window_closed(api, mode, on_done)


def _finish(result: str, on_done):
    global _window
    with _lock:
        win, _window = _window, None
    if win is not None:
        try:
            win.destroy()
        except Exception:
            pass
    if on_done:
        try:
            on_done(result)
        except Exception:
            logger.exception("Mitteilung: on_done fehlgeschlagen")
    _show_next()


def _on_window_closed(api: MessageApi, mode: str, on_done):
    """Fenster ohne Button-Klick zu (z. B. Alt+F4 oder Tray beendet)."""
    global _window
    if api.handled:
        return
    api.handled = True
    with _lock:
        _window = None
    if on_done:
        on_done("closed_unacked" if mode == "kritisch" else "closed")
    _show_next()


def destroy_message_window():
    """Beim Beenden: offenes Fenster schliessen, Warteschlange leeren."""
    global _window
    with _lock:
        _queue.clear()
        win, _window = _window, None
    if win is not None:
        try:
            win.destroy()
        except Exception:
            pass
