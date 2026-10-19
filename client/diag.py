"""
Client-Diagnose: Log-Datei und Haenger-Erkennung.

Log:   %LOCALAPPDATA%\\<Slug>\\logs\\tray.log        (rotierend, 4 x 1 MB)
Dumps: %LOCALAPPDATA%\\<Slug>\\logs\\hang-dumps.log  (Thread-Stacks bei Haengern)

Zwei Arten von Haengern werden erkannt:

1. GIL-Deadlock — ein Thread haelt Pythons globale Sperre und blockiert in
   einem .NET-/Win32-Aufruf, alle anderen Python-Threads stehen. Normaler
   Python-Code kann das nicht mehr melden. Deshalb arbeitet hier der
   C-Watchdog von faulthandler: der Heartbeat-Thread zieht ihn alle
   _HEARTBEAT_S Sekunden auf; kommt der Heartbeat _GIL_HANG_S lang nicht
   durch, schreibt faulthandler (ohne GIL) die Stacks aller Threads.

2. Fenster-Haenger — die GUI-Thread-Nachrichtenschleife steht, der GIL ist
   aber frei. Der Heartbeat fragt IsHungAppWindow fuer registrierte Fenster
   ab und schreibt nach _GUI_HANG_S Sekunden einen Dump.
"""
import ctypes
import faulthandler
import logging
import logging.handlers
import os
import sys
import threading
import time
from ctypes import wintypes

logger = logging.getLogger("softshelf.diag")

_HEARTBEAT_S = 10
_GIL_HANG_S = 60
_GUI_HANG_S = 15
_DUMP_MAX_BYTES = 2_000_000

_log_dir: str | None = None
_dump_file = None
_hwnds: dict[int, str] = {}       # hwnd -> Name, fuer die Haenger-Pruefung
_hwnds_lock = threading.Lock()


def log_dir() -> str | None:
    return _log_dir


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def setup(slug: str, version: str) -> None:
    """Logging + Haenger-Watchdog einrichten. Fehler hier duerfen den Tray
    nie am Start hindern — im Zweifel laeuft er eben ohne Log."""
    global _log_dir, _dump_file
    try:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or "."
        _log_dir = os.path.join(base, slug, "logs")
        os.makedirs(_log_dir, exist_ok=True)

        handler = logging.handlers.RotatingFileHandler(
            os.path.join(_log_dir, "tray.log"),
            maxBytes=1_000_000, backupCount=3, encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s [%(threadName)s] %(name)s: %(message)s",
        ))
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        root.addHandler(handler)
        # Bibliotheken nur bei Problemen
        for noisy in ("httpx", "httpcore", "PIL"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

        sys.excepthook = _excepthook
        threading.excepthook = _thread_excepthook

        dump_path = os.path.join(_log_dir, "hang-dumps.log")
        mode = "w" if (os.path.exists(dump_path)
                       and os.path.getsize(dump_path) > _DUMP_MAX_BYTES) else "a"
        _dump_file = open(dump_path, mode, encoding="utf-8")
        _dump_file.write(f"\n=== {_ts()} Start pid={os.getpid()} version={version} ===\n")
        _dump_file.flush()
        # Auch harte Abstuerze (Access Violation in nativem Code) landen im Dump
        faulthandler.enable(file=_dump_file, all_threads=True)

        logger.info("Start: version=%s pid=%d log=%s", version, os.getpid(), _log_dir)
        threading.Thread(target=_watchdog, daemon=True, name="DiagWatchdog").start()
    except Exception:
        # Logging selbst kaputt — nicht weiter eskalieren
        pass


def _excepthook(exc_type, exc, tb):
    logger.critical("Unbehandelte Ausnahme", exc_info=(exc_type, exc, tb))


def _thread_excepthook(args):
    logger.error("Unbehandelte Ausnahme in Thread %s",
                 getattr(args.thread, "name", "?"),
                 exc_info=(args.exc_type, args.exc_value, args.exc_traceback))


def dump_threads(reason: str) -> None:
    """Stacks aller Python-Threads in hang-dumps.log schreiben."""
    if _dump_file is None:
        return
    try:
        _dump_file.write(f"\n=== {_ts()} {reason} ===\n")
        _dump_file.flush()
        faulthandler.dump_traceback(file=_dump_file, all_threads=True)
        _dump_file.flush()
    except Exception:
        pass


# ── Fenster ──────────────────────────────────────────────────────────────────

_user32 = ctypes.windll.user32
_EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
_user32.EnumWindows.argtypes = [_EnumWindowsProc, wintypes.LPARAM]
_user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
_user32.GetWindowThreadProcessId.restype = wintypes.DWORD
_user32.IsWindowVisible.argtypes = [wintypes.HWND]
_user32.IsWindow.argtypes = [wintypes.HWND]
_user32.IsHungAppWindow.argtypes = [wintypes.HWND]
_user32.InternalGetWindowText.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
_user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_int, ctypes.c_int, wintypes.UINT]
_user32.SetForegroundWindow.argtypes = [wintypes.HWND]


def find_window(title: str) -> int | None:
    """Sichtbares Fenster dieses Prozesses mit genau diesem Titel.
    InternalGetWindowText statt GetWindowText: schickt keine Nachricht an
    den (womoeglich haengenden) Besitzer-Thread."""
    pid = os.getpid()
    found: list[int] = []

    def cb(hwnd, _lparam):
        owner = wintypes.DWORD()
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and _user32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(512)
            _user32.InternalGetWindowText(hwnd, buf, 512)
            if buf.value == title:
                found.append(hwnd)
                return False
        return True

    try:
        _user32.EnumWindows(_EnumWindowsProc(cb), 0)
    except Exception:
        return None
    return found[0] if found else None


def bring_to_front(hwnd: int) -> None:
    """Fenster nach vorne holen. Per ctypes, NICHT ueber pywebview's on_top:
    das setzt TopMost aus dem aufrufenden Thread und haelt dabei den GIL —
    laedt das Fenster gerade (GUI-Thread braucht den GIL), verklemmt sich
    der ganze Prozess. ctypes gibt den GIL waehrend des Aufrufs frei."""
    HWND_TOPMOST, HWND_NOTOPMOST = wintypes.HWND(-1), wintypes.HWND(-2)
    flags = 0x0001 | 0x0002 | 0x0040  # SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW
    _user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, flags)
    _user32.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, flags)
    _user32.SetForegroundWindow(hwnd)


def watch_window(hwnd: int, name: str) -> None:
    """Fenster fuer die Haenger-Erkennung registrieren."""
    with _hwnds_lock:
        _hwnds[hwnd] = name


# ── Watchdog ─────────────────────────────────────────────────────────────────

def _watchdog() -> None:
    hung_since: dict[int, float] = {}
    dumped: set[int] = set()
    while True:
        try:
            if _dump_file is not None:
                # Neu aufziehen; bleibt das aus (GIL blockiert), feuert der C-Thread
                faulthandler.dump_traceback_later(
                    _GIL_HANG_S, repeat=False, file=_dump_file, exit=False,
                )
            time.sleep(_HEARTBEAT_S)
            with _hwnds_lock:
                watched = dict(_hwnds)
            now = time.monotonic()
            for hwnd, name in watched.items():
                if not _user32.IsWindow(hwnd):
                    with _hwnds_lock:
                        _hwnds.pop(hwnd, None)
                    hung_since.pop(hwnd, None)
                    dumped.discard(hwnd)
                    continue
                if _user32.IsHungAppWindow(hwnd):
                    t0 = hung_since.setdefault(hwnd, now)
                    if now - t0 >= _GUI_HANG_S and hwnd not in dumped:
                        logger.error("Fenster '%s' reagiert seit %ds nicht — Thread-Dump in hang-dumps.log",
                                     name, int(now - t0))
                        dump_threads(f"Fenster '{name}' reagiert nicht")
                        dumped.add(hwnd)
                elif hwnd in hung_since:
                    logger.warning("Fenster '%s' reagiert wieder (nach %ds)",
                                   name, int(now - hung_since.pop(hwnd)))
                    dumped.discard(hwnd)
        except Exception:
            logger.exception("Watchdog-Fehler")
            time.sleep(_HEARTBEAT_S)
