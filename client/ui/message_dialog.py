"""
Mitteilungs-Fenster (v2.10) — pywebview.

Drei Stufen:
- "info":     kompaktes Fenster unten rechts, schliesst nach 10 s.
- "wichtig":  Fenster unten rechts mit Buttons, schliesst nach 60 s.
              Bei beiden pausiert der Timer, solange Maus oder Tastaturfokus
              im Fenster sind; sie nehmen der laufenden Arbeit den Fokus nicht weg.
- "kritisch": Fenster in der Bildschirmmitte, immer im Vordergrund, ohne
              Schliessen-Kreuz — geht nur mit "Verstanden" weg.

Groesse: Das Fenster entsteht ausserhalb des sichtbaren Bereichs, misst nach
dem Rendern seinen Inhalt (JS → fit) und wird dann per SetWindowPos auf die
passende Groesse gebracht und platziert — in physischen Pixeln, also passend
zur Windows-Skalierung. ctypes statt pywebview-resize/move: deren Invoke aus
einem Fremd-Thread kann am GIL verklemmen (siehe diag.bring_to_front).

Mehrere Mitteilungen werden nacheinander gezeigt; kritische ziehen vor.
Inhalte kommen ueber die JS-Bridge (get_payload) und werden per textContent
gesetzt — kein HTML aus Serverdaten im Template.
"""
import collections
import ctypes
import logging
import os
import threading
import webbrowser
from ctypes import wintypes

import webview

logger = logging.getLogger("softshelf.message")

_AUTO_CLOSE_S = {"info": 10, "wichtig": 60, "kritisch": 0}
_WIDTH = {"info": 360, "wichtig": 380, "kritisch": 480}  # CSS-Pixel
_MARGIN = 16                                              # Abstand zum Bildschirmrand (CSS-Pixel)
_OFFSCREEN = -32000

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
.card { flex: 1; display: flex; flex-direction: column; min-height: 0; opacity: 0; }
body.ready .card { opacity: 1; animation: in 260ms var(--ease); }
@keyframes in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
.head { display: flex; align-items: flex-start; gap: 12px; padding: 16px 18px 0; flex-shrink: 0; }
.icon {
  width: 32px; height: 32px; border-radius: 8px; flex-shrink: 0;
  background: var(--accent-bg); color: var(--accent);
  display: flex; align-items: center; justify-content: center;
}
.icon svg { width: 18px; height: 18px; }
.titles { flex: 1; min-width: 0; }
.kicker { font-size: 12px; font-weight: 600; color: var(--fg-4); }
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
  padding: 8px 18px 2px 62px;
  font-size: 13px; line-height: 1.55; color: var(--fg-3);
  white-space: pre-wrap; overflow-wrap: anywhere; user-select: text;
}
.foot { display: flex; gap: 8px; justify-content: flex-end; align-items: center; padding: 12px 18px 16px; flex-shrink: 0; }
.hint { flex: 1; font-size: 12px; color: var(--fg-4); }
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
.mode-info .head { padding: 14px 16px 0; }
.mode-info .title { font-size: 14px; }
.mode-info .body { padding: 6px 16px 14px 60px; font-size: 12.5px; }
.mode-info .foot { padding: 0 16px 14px; }
.mode-kritisch .head { padding: 22px 24px 0; }
.mode-kritisch .title { font-size: 17px; }
.mode-kritisch .body { padding: 12px 24px 4px 68px; font-size: 13.5px; }
.mode-kritisch .foot { padding: 16px 24px 20px; }
/* Messen: alles auf natuerliche Hoehe, nichts gestreckt */
html.measuring, html.measuring body { height: auto; }
html.measuring .card, html.measuring .body { flex: none; }
html.measuring .body { overflow: visible; }
@media (prefers-reduced-motion: reduce) { body.ready .card { animation: none; } }
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
  <div class="foot" id="foot">
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
let closed = false, started = false, left = AUTO_MS, last = Date.now(), paused = false;

function done() {
  if (closed) return;
  closed = true;
  pywebview.api.close(MODE === 'kritisch' ? 'acked' : 'closed');
}
function openLink() { pywebview.api.open_link(); }

// Natuerliche Hoehe des Inhalts in CSS-Pixeln: kurz ohne flex-Streckung
// messen — sonst fuellt der Textbereich die vorlaeufige Fensterhoehe aus
function neededHeight() {
  const root = document.documentElement;
  root.classList.add('measuring');
  const h = document.body.getBoundingClientRect().height;
  root.classList.remove('measuring');
  return Math.ceil(h);
}

window.addEventListener('pywebviewready', async () => {
  const p = await pywebview.api.get_payload();
  document.getElementById('kicker').textContent = p.header || '';
  document.getElementById('title').textContent = p.title || '';
  const body = document.getElementById('body');
  body.textContent = p.body || '';
  if (!p.body) body.style.display = 'none';
  const link = document.getElementById('link');
  if (p.link_url) { link.textContent = p.link_label || 'Öffnen'; link.style.display = ''; }
  const ok = document.getElementById('ok');
  if (MODE === 'info') {
    ok.style.display = 'none';
    if (!p.link_url) document.getElementById('foot').style.display = 'none';
  } else {
    ok.textContent = MODE === 'kritisch' ? 'Verstanden' : 'Schließen';
  }
  if (MODE === 'kritisch') document.getElementById('hint').textContent = 'Bitte bestätigen, um fortzufahren.';
  try { await pywebview.api.fit(neededHeight()); } catch (e) {}
  document.body.classList.add('ready');
  if (MODE === 'kritisch') ok.focus();
  started = true; last = Date.now();
  pywebview.api.shown();
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && MODE !== 'kritisch') done();
});

if (AUTO_MS > 0) {
  // Timer pausiert, solange Maus oder Tastaturfokus im Fenster sind
  let hover = false, focus = false;
  const sync = () => { const p = hover || focus; if (paused && !p) last = Date.now(); paused = p; };
  document.addEventListener('mouseenter', () => { hover = true; sync(); });
  document.addEventListener('mouseleave', () => { hover = false; sync(); });
  document.addEventListener('focusin', e => { focus = !!(e.target && e.target.matches(':focus-visible')); sync(); });
  document.addEventListener('focusout', () => { focus = false; sync(); });
  const bar = document.querySelector('.timer i');
  setInterval(() => {
    if (closed || paused || !started) return;
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
    "info": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/>'
            '<line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
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
    auto = _AUTO_CLOSE_S[mode] * 1000
    return (_HTML
            .replace("__CLASSES__", f"sev-{mode} mode-{mode}")
            .replace("__ICON__", _ICONS[mode])
            .replace("__CLOSE__", _CLOSE_BTN if mode != "kritisch" else "")
            .replace("__TIMER__", '<div class="timer"><i></i></div>' if auto else "")
            .replace("__MODE__", mode)
            .replace("__AUTO_MS__", str(auto)))


# ── Fenster platzieren (physische Pixel, per ctypes) ─────────────────────────

_user32 = ctypes.windll.user32
_SWP_NOZORDER, _SWP_NOACTIVATE = 0x0004, 0x0010


def _work_area() -> wintypes.RECT | None:
    """Arbeitsbereich ohne Taskleiste. Der Prozess ist DPI-aware (pywebview
    ruft SetProcessDPIAware) → physische Pixel."""
    rect = wintypes.RECT()
    try:
        if _user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0):  # SPI_GETWORKAREA
            return rect
    except Exception:
        pass
    return None


def _find_hwnd(title: str) -> int | None:
    """Sichtbares oder unsichtbares Top-Level-Fenster dieses Prozesses mit genau diesem Titel."""
    pid = os.getpid()
    found: list[int] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _lparam):
        wpid = wintypes.DWORD()
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value == pid:
            # InternalGetWindowText schickt keine Nachricht ans Fenster
            buf = ctypes.create_unicode_buffer(512)
            _user32.InternalGetWindowText(hwnd, buf, 512)
            if buf.value == title:
                found.append(hwnd)
                return False
        return True

    _user32.EnumWindows(cb, 0)
    return found[0] if found else None


def _scale(hwnd: int) -> float:
    try:
        dpi = _user32.GetDpiForWindow(hwnd) or _user32.GetDpiForSystem()
    except Exception:
        dpi = 96
    return (dpi or 96) / 96.0


def _place(hwnd: int, mode: str, css_height: int):
    s = _scale(hwnd)
    wa = _work_area()
    w = round(_WIDTH[mode] * s)
    h = round(max(120, css_height) * s)
    if wa is not None:
        h = min(h, int((wa.bottom - wa.top) * 0.85))
        m = round(_MARGIN * s)
        if mode == "kritisch":
            x = wa.left + (wa.right - wa.left - w) // 2
            y = wa.top + (wa.bottom - wa.top - h) // 2
        else:
            x, y = wa.right - w - m, wa.bottom - h - m
    else:
        x = y = 100
    _user32.SetWindowPos(hwnd, 0, int(x), int(y), int(w), int(h), _SWP_NOZORDER | _SWP_NOACTIVATE)


class MessageApi:
    """JS-Bridge eines Mitteilungsfensters."""

    def __init__(self, msg: dict, mode: str, title: str, on_shown, on_close):
        self._msg = msg
        self._mode = mode
        self._title = title
        self._on_shown = on_shown
        self._on_close = on_close
        self._shown = False
        self.placed = False
        self.handled = False

    def get_payload(self) -> dict:
        m = self._msg
        return {k: str(m.get(k) or "") for k in ("header", "title", "body", "link_url", "link_label")}

    def fit(self, css_height):
        """Vom Fenster nach dem Rendern: Groesse + Position setzen."""
        try:
            hwnd = _find_hwnd(self._title)
            if hwnd:
                _place(hwnd, self._mode, int(css_height))
                self.placed = True
        except Exception:
            logger.exception("Mitteilungsfenster: Platzieren fehlgeschlagen")

    def ensure_visible(self):
        """Sicherheitsnetz: ruft das Fenster fit() nicht auf (JS-Fehler),
        nach ein paar Sekunden mit Standardhoehe sichtbar machen."""
        if not self.placed and not self.handled:
            logger.warning("Mitteilungsfenster: kein fit() — Standardgroesse")
            self.fit(260 if self._mode == "kritisch" else 200)

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
_counter = 0


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
    global _window, _counter
    with _lock:
        if _window is not None or not _queue:
            return
        msg, app_name, on_shown, on_done = _queue.popleft()
        sev = msg.get("severity")
        mode = sev if sev in ("info", "wichtig", "kritisch") else "info"
        _counter += 1
        # Eindeutiger Titel: daran findet fit() das Fenster per EnumWindows
        title = f"{app_name} — {msg.get('header') or 'Mitteilung'} ({_counter})"

        def on_close(result: str):
            _finish(result, on_done)

        api = MessageApi(msg, mode, title, on_shown, on_close)
        try:
            # Entsteht ausserhalb des Bildschirms; fit() holt es an die richtige Stelle
            _window = webview.create_window(
                title, html=_render(mode), js_api=api,
                width=_WIDTH[mode], height=240, x=_OFFSCREEN, y=_OFFSCREEN,
                resizable=False, frameless=True, easy_drag=(mode != "kritisch"),
                on_top=True, focus=(mode == "kritisch"), text_select=True,
            )
        except Exception:
            _window = None
            logger.exception("Mitteilungsfenster konnte nicht erstellt werden")
            if on_done:
                on_done("closed_unacked" if mode == "kritisch" else "closed")
            return
        _window.events.closed += lambda: _on_window_closed(api, mode, on_done)
    threading.Timer(6.0, api.ensure_visible).start()


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
