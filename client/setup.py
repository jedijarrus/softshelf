"""
Setup / Installer

Aufruf (still, z.B. via Tactical RMM):
    <slug>-setup.exe --proxy-url URL --reg-secret SECRET --agent-id ID

Aufruf (GUI-Wizard, Doppelklick):
    <slug>-setup.exe

Was dieser Installer macht:
  1. <slug>.exe nach C:\\Program Files\\<slug>\\ kopieren
  2. Diesen PC beim Proxy registrieren (Machine Token holen)
  3. Token + ProxyUrl in HKLM\\SOFTWARE\\<slug> speichern
  4. ProxyUrl als System-Umgebungsvariable setzen
  5. Autostart in HKLM eintragen (startet beim naechsten User-Login)

<slug> kommt aus _build_config.PRODUCT_SLUG (Default: Softshelf), wird
vom Builder aus dem Admin-Setting product_slug uebernommen.
"""
import argparse
import ctypes
import os
import re
import shutil
import subprocess
import sys
import time
import winreg
from ctypes import wintypes
from datetime import datetime
from urllib.parse import urlparse

import httpx

try:
    from _version import __version__
except Exception:
    __version__ = "?"

try:
    from _build_config import (
        DEFAULT_PROXY_URL, BUILD_VERSION, PRODUCT_SLUG, PUBLISHER,
    )
    if BUILD_VERSION and BUILD_VERSION != "?":
        __version__ = BUILD_VERSION
except Exception:
    DEFAULT_PROXY_URL = ""
    PRODUCT_SLUG = "Softshelf"
    BUILD_VERSION = "?"
    PUBLISHER = "Softshelf"

try:
    from _build_config import CLIENT_APP_NAME
except Exception:
    CLIENT_APP_NAME = ""

# Defense in depth: falsch injizierter Slug darf keine Pfad-Traversal oder
# Registry-Escapes ermoeglichen. Bei Mismatch fallen wir auf den Default zurueck.
if not re.match(r"^[A-Za-z][A-Za-z0-9_-]{0,30}$", PRODUCT_SLUG or ""):
    PRODUCT_SLUG = "Softshelf"

# Publisher: free-text bis 60, keine Steuer-/HTML-Sonderzeichen. Bei Mismatch
# fallen wir auf den Slug zurueck damit der Apps-&-Features-Eintrag wenigstens
# einen Wert hat statt den Build zu sprengen.
if not re.match(r'^[^\x00-\x1f\x7f<>"\'`]{1,60}$', PUBLISHER or ""):
    PUBLISHER = PRODUCT_SLUG


# ── Konstanten ─────────────────────────────────────────────────────────────────

INSTALL_DIR        = rf"C:\Program Files\{PRODUCT_SLUG}"
REG_PATH           = rf"SOFTWARE\{PRODUCT_SLUG}"
AUTOSTART_PATH     = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_NAME     = PRODUCT_SLUG
EXE_FILENAME       = f"{PRODUCT_SLUG}.exe"
SETUP_EXE_FILENAME = f"{PRODUCT_SLUG}-setup.exe"
# Apps-&-Features-Eintrag — Windows liest diesen Key zur Anzeige in
# Settings → Apps und in der klassischen "Programme und Features" Liste.
UNINSTALL_KEY_PATH = (
    rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{PRODUCT_SLUG}"
)
# System-Env-Var Name: Grossbuchstaben, Hyphens zu Underscores
PROXY_ENV_VAR      = PRODUCT_SLUG.upper().replace("-", "_") + "_PROXY_URL"


# ── Hilfsfunktionen ────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin():
    """Re-launcht sich selbst mit UAC-Elevation falls nicht bereits Admin."""
    if not is_admin():
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit(0)


def resource_path(filename: str) -> str:
    """Pfad zu eingebetteten Dateien (PyInstaller _MEIPASS oder Dev-Pfad)."""
    base = getattr(sys, "_MEIPASS", os.path.join(os.path.dirname(__file__), "..", "dist"))
    return os.path.join(base, filename)


def get_tactical_agent_id() -> str | None:
    """
    Liest die Tactical RMM Agent-ID aus der lokalen Registry.
    Tactical speichert sie unter HKLM\\SOFTWARE\\TacticalRMM\\agentid.
    """
    for key_path in (r"SOFTWARE\TacticalRMM", r"SOFTWARE\WOW6432Node\TacticalRMM"):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
                for value_name in ("agentid", "AgentID", "agent_id"):
                    try:
                        val, _ = winreg.QueryValueEx(k, value_name)
                        if val:
                            return str(val)
                    except FileNotFoundError:
                        continue
        except FileNotFoundError:
            continue
    return None


def validate_proxy_url(url: str) -> str:
    """Wirft ValueError wenn URL ungültig ist. Gibt normalisierte URL zurück."""
    url = url.strip()
    if not url:
        raise ValueError("Proxy-URL ist leer")
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ValueError("Proxy-URL muss mit http:// oder https:// beginnen")
    if not p.netloc:
        raise ValueError("Proxy-URL ist unvollständig (Host fehlt)")
    return url.rstrip("/")


def friendly_error(exc: BaseException) -> str:
    """Wandelt Exceptions in Endbenutzer-taugliche Meldungen um."""
    if isinstance(exc, ValueError):
        return str(exc)
    if isinstance(exc, httpx.ConnectError):
        return ("Proxy-Server nicht erreichbar.\n"
                "Bitte URL und Netzwerkverbindung prüfen.")
    if isinstance(exc, httpx.ConnectTimeout):
        return "Verbindung zum Proxy-Server hat zu lange gedauert (Timeout)."
    if isinstance(exc, httpx.HTTPStatusError):
        try:
            detail = exc.response.json().get("detail", "")
        except Exception:
            detail = (exc.response.text or "")[:200]
        code = exc.response.status_code
        if code == 403:
            return f"Registrierung abgelehnt: {detail}"
        if code == 404:
            return f"Agent nicht gefunden: {detail}"
        if code == 429:
            return "Zu viele Versuche. Bitte einen Moment warten und erneut probieren."
        return f"Server-Fehler ({code}): {detail}"
    return str(exc) or exc.__class__.__name__


# ── Installations-Schritte ─────────────────────────────────────────────────────

def step_copy_files() -> str:
    os.makedirs(INSTALL_DIR, exist_ok=True)
    src = resource_path(EXE_FILENAME)
    dst = os.path.join(INSTALL_DIR, EXE_FILENAME)
    shutil.copy2(src, dst)
    return dst


def step_register(proxy_url: str, reg_secret: str, agent_id: str) -> str:
    """Registriert beim Proxy. Gibt das Machine Token zurueck."""
    hostname = os.environ.get("COMPUTERNAME", "UNKNOWN")
    r = httpx.post(
        f"{proxy_url.rstrip('/')}/api/v1/register",
        json={
            "agent_id": agent_id,
            "hostname": hostname,
            "registration_secret": reg_secret,
        },
        timeout=30,
        verify=True,
    )
    r.raise_for_status()
    data = r.json()
    token = data.get("token")
    if not token:
        raise ValueError("Kein Token in Proxy-Antwort.")
    return token


def step_save_config(proxy_url: str, token: str):
    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE, REG_PATH, access=winreg.KEY_SET_VALUE
    ) as k:
        winreg.SetValueEx(k, "ProxyUrl",     0, winreg.REG_SZ, proxy_url)
        winreg.SetValueEx(k, "MachineToken", 0, winreg.REG_SZ, token)

    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        access=winreg.KEY_SET_VALUE,
    ) as k:
        winreg.SetValueEx(k, PROXY_ENV_VAR, 0, winreg.REG_EXPAND_SZ, proxy_url)

    HWND_BROADCAST = 0xFFFF
    WM_SETTINGCHANGE = 0x001A
    ctypes.windll.user32.SendMessageTimeoutW(
        HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", 2, 5000, None
    )


def step_autostart(exe_path: str):
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, AUTOSTART_PATH, access=winreg.KEY_SET_VALUE
    ) as k:
        winreg.SetValueEx(k, AUTOSTART_NAME, 0, winreg.REG_SZ, f'"{exe_path}"')


# ── Win32 Session-API Wrappers (ctypes) ────────────────────────────────────────
#
# Tactical RMM faehrt setup.exe als SYSTEM in Session 0 — dort ist kein Desktop,
# kein Explorer, keine Notification-Area. Ein dort gestarteter Tray-Prozess
# laeuft unsichtbar weiter. Den interaktiven Tray-Launch in der User-Session
# erledigen wir jetzt ueber den Task-Scheduler-Trick (siehe step_launch +
# launch_in_user_session_via_schtasks); die historisch hier gewesene
# CreateProcessAsUserW/CreateProcessWithTokenW-Variante hat sich im Tactical-
# SYSTEM-Service-Token-Kontext als unzuverlaessig erwiesen (default-disabled
# SeAssignPrimaryTokenPrivilege etc.) und ist entfernt. Wir brauchen hier nur
# noch ein paar kleine kernel32-Helper.

_INVALID_SESSION_ID                = 0xFFFFFFFF
_MOVEFILE_DELAY_UNTIL_REBOOT       = 0x4
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _load_session_apis():
    """Lazy-load der Win32-DLLs (kernel32 reicht aus)."""
    global _kernel32
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _kernel32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
    _kernel32.WTSGetActiveConsoleSessionId.argtypes = []

    _kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
    _kernel32.ProcessIdToSessionId.argtypes = [
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]

    _kernel32.GetCurrentProcessId.restype = wintypes.DWORD
    _kernel32.GetCurrentProcessId.argtypes = []

    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    _kernel32.MoveFileExW.restype = wintypes.BOOL
    _kernel32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]


_kernel32 = None
_load_session_apis()


def current_session_id() -> int:
    """Session-ID des laufenden Prozesses. 0 = SYSTEM/Service, >=1 = User."""
    pid = _kernel32.GetCurrentProcessId()
    sid = wintypes.DWORD()
    if not _kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
        return 0
    return sid.value


def active_console_session_id() -> int:
    """Session-ID des aktuell interaktiv eingeloggten Console-Users.

    Gibt 0xFFFFFFFF zurueck wenn niemand interaktiv eingeloggt ist (Lock-Screen
    direkt nach Boot, oder Server ohne aktive Console-Sitzung).
    """
    return _kernel32.WTSGetActiveConsoleSessionId()


def _pid_alive(pid: int) -> bool:
    """True wenn der gegebene PID noch laeuft."""
    if not pid:
        return False
    h = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    _kernel32.CloseHandle(h)
    return True


def _retry_rmtree(path: str, attempts: int = 20, delay: float = 0.5, status_cb=None):
    """rmtree mit Retry-Schleife.

    Windows haelt Datei-Handles oft 1-5 Sekunden nach Prozess-Exit. Wir
    versuchen ~10s lang in 0.5s-Intervallen. Zwischen den Versuchen bauen
    wir die Inhalte ab — wenn nur noch der Ordner selbst uebrig ist (handle
    auf den Verzeichnis-Eintrag selbst), greift os.rmdir der naechste Pass.
    Am Ende fallen wir auf MoveFileEx DELAY_UNTIL_REBOOT zurueck.
    """
    for i in range(attempts):
        try:
            if not os.path.exists(path):
                return
            # Wenn der Ordner leer ist, direkt rmdir — shutil.rmtree macht das
            # zwar auch, aber ein expliziter rmdir-Pfad gibt klarere Errors.
            if os.path.isdir(path) and not os.listdir(path):
                os.rmdir(path)
            else:
                shutil.rmtree(path, ignore_errors=False)
            return
        except Exception:
            time.sleep(delay)

    if status_cb:
        status_cb("Datei-Locks bestehen, plane Cleanup fuer naechsten Reboot...")

    # Fallback: was uebrig ist via MoveFileEx zur Reboot-Loeschung markieren.
    try:
        for root_dir, dirs, files in os.walk(path, topdown=False):
            for f in files:
                p = os.path.join(root_dir, f)
                try:
                    os.unlink(p)
                except Exception:
                    try:
                        _kernel32.MoveFileExW(p, None, _MOVEFILE_DELAY_UNTIL_REBOOT)
                    except Exception:
                        pass
            for d in dirs:
                p = os.path.join(root_dir, d)
                try:
                    os.rmdir(p)
                except Exception:
                    try:
                        _kernel32.MoveFileExW(p, None, _MOVEFILE_DELAY_UNTIL_REBOOT)
                    except Exception:
                        pass
        try:
            os.rmdir(path)
        except Exception:
            try:
                _kernel32.MoveFileExW(path, None, _MOVEFILE_DELAY_UNTIL_REBOOT)
            except Exception:
                pass
    except Exception:
        pass


def _dir_size_kb(path: str) -> int:
    """Total bytes/1024 fuer EstimatedSize im Uninstall-Key."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return max(1, total // 1024)


# ── Installations-Schritte (neu) ───────────────────────────────────────────────

def step_copy_setup_exe() -> str:
    """Kopiert die laufende setup.exe nach INSTALL_DIR.

    sys.executable ist bei PyInstaller --onefile der Pfad zur Bootstrap-EXE
    (also unsere setup.exe in %TEMP% oder wo Tactical sie hinterlegt hat).
    Wir brauchen die Kopie im INSTALL_DIR damit die UninstallString in der
    Apps-&-Features-Liste sie spaeter aufrufen kann.
    """
    src = sys.executable
    if not src or not os.path.isfile(src):
        raise RuntimeError("sys.executable zeigt nicht auf eine existierende Datei")
    dst = os.path.join(INSTALL_DIR, SETUP_EXE_FILENAME)
    shutil.copy2(src, dst)
    return dst


def step_copy_icon() -> str | None:
    """Kopiert das eingebackene app_icon.ico nach INSTALL_DIR (falls vorhanden).

    Builder bundelt das Icon ueber `--add-data app_icon.ico` in beide EXEs.
    Beim ersten Run extrahiert PyInstaller es nach _MEIPASS, von dort kopieren
    wir es nach INSTALL_DIR damit der Apps-&-Features DisplayIcon-Eintrag eine
    stabile, vom EXE unabhaengige Icon-Datei referenzieren kann.

    Wenn kein Icon mitgebaut wurde, geben wir None zurueck und der Caller
    faellt auf den Tray-EXE mit Index 0 zurueck.
    """
    src = resource_path("app_icon.ico")
    if not os.path.isfile(src):
        return None
    dst = os.path.join(INSTALL_DIR, "app_icon.ico")
    try:
        shutil.copy2(src, dst)
        return dst
    except Exception:
        return None


def step_register_uninstall_entry(
    tray_exe_path: str,
    setup_exe_path: str,
    icon_path: str | None,
) -> None:
    """Schreibt den HKLM-Eintrag fuer 'Apps & Features' / 'Programme und Features'.

    DisplayIcon zeigt bevorzugt auf die separat kopierte app_icon.ico, die im
    Builder via --add-data eingebacken wurde. Wenn keine vorhanden ist (kein
    Icon hochgeladen), fallen wir auf die Tray-EXE mit Resource-Index 0 zurueck
    — PyInstaller --icon embedded das Icon dort als Resource 0.

    UninstallString und Quiet-Variante rufen die kopierte setup.exe mit
    --uninstall auf.
    """
    display_name = CLIENT_APP_NAME or PRODUCT_SLUG
    uninstall_cmd = f'"{setup_exe_path}" --uninstall'
    estimated_size_kb = _dir_size_kb(INSTALL_DIR)
    install_date = datetime.now().strftime("%Y%m%d")
    display_icon = icon_path if icon_path else f"{tray_exe_path},0"

    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY_PATH,
        access=winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
    ) as k:
        winreg.SetValueEx(k, "DisplayName",     0, winreg.REG_SZ, display_name)
        winreg.SetValueEx(k, "DisplayVersion",  0, winreg.REG_SZ, BUILD_VERSION or "1.0.0")
        winreg.SetValueEx(k, "Publisher",       0, winreg.REG_SZ, PUBLISHER)
        winreg.SetValueEx(k, "InstallLocation", 0, winreg.REG_SZ, INSTALL_DIR)
        winreg.SetValueEx(k, "DisplayIcon",     0, winreg.REG_SZ, display_icon)
        winreg.SetValueEx(k, "UninstallString", 0, winreg.REG_SZ, uninstall_cmd)
        winreg.SetValueEx(k, "QuietUninstallString", 0, winreg.REG_SZ, uninstall_cmd)
        winreg.SetValueEx(k, "InstallDate",     0, winreg.REG_SZ, install_date)
        winreg.SetValueEx(k, "EstimatedSize",   0, winreg.REG_DWORD, estimated_size_kb)
        winreg.SetValueEx(k, "NoModify",        0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "NoRepair",        0, winreg.REG_DWORD, 1)


# ── Uninstall-Lock + Status-GUI ────────────────────────────────────────────────

def _uninstall_lock_path() -> str:
    """Lock-File in ProgramData (gleicher Pfad fuer SYSTEM und elevated User).

    %TEMP% waere fuer SYSTEM `C:\\Windows\\Temp` und fuer den UAC-User dessen
    %LOCALAPPDATA%\\Temp — verschiedene Pfade, dann schuetzt der Lock nicht
    zwischen den Kontexten. ProgramData ist dagegen system-weit gleich.
    """
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    d = os.path.join(base, PRODUCT_SLUG)
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return os.path.join(d, "uninstall.lock")


def _try_acquire_uninstall_lock() -> bool:
    """Versucht eine Lock-Datei exklusiv anzulegen.

    Falls bereits da: pruefen ob der haltende PID noch lebt. Wenn ja → False.
    Wenn der Halter tot ist → Lock uebernehmen.
    """
    path = _uninstall_lock_path()
    for _ in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, str(os.getpid()).encode("ascii"))
            finally:
                os.close(fd)
            return True
        except FileExistsError:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    pid = int((f.read().strip() or "0"))
            except Exception:
                pid = 0
            if pid and _pid_alive(pid):
                return False
            try:
                os.unlink(path)
            except Exception:
                pass
    return False


def _release_uninstall_lock():
    try:
        os.unlink(_uninstall_lock_path())
    except Exception:
        pass


def _show_uninstall_window_and_run(work_fn) -> tuple[bool, str]:
    """Zeigt ein kleines Status-Fenster und fuehrt work_fn(status_cb) im Worker.

    Returns (ok, error_message). Das Fenster schliesst automatisch ~1s
    nachdem der Worker fertig ist. Close-Button ist deaktiviert damit User
    nicht mid-uninstall abbricht.
    """
    import threading
    import tkinter as tk

    root = tk.Tk()
    root.title(PRODUCT_SLUG)
    root.geometry("440x150")
    root.resizable(False, False)
    root.attributes("-topmost", True)
    root.protocol("WM_DELETE_WINDOW", lambda: None)

    root.update_idletasks()
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    root.geometry(f"+{(sw - 440) // 2}+{(sh - 150) // 2}")

    tk.Label(
        root, text=f"{PRODUCT_SLUG} wird deinstalliert",
        font=("Segoe UI", 11, "bold"), pady=14,
    ).pack()
    status_lbl = tk.Label(
        root, text="Wird vorbereitet...", font=("Segoe UI", 9),
        wraplength=400, fg="#444",
    )
    status_lbl.pack(expand=True, fill="both", padx=20, pady=(0, 14))

    state = {"error": None, "done": False}

    def on_status(msg: str):
        if state["done"]:
            return
        try:
            root.after(0, lambda m=msg: status_lbl.config(text=m))
        except Exception:
            pass

    def worker():
        try:
            work_fn(on_status)
        except Exception as e:
            state["error"] = str(e)
        # Done-Flag VOR den finalen after-Calls setzen, damit ein gerade noch
        # laufendes on_status-Update keine zweite Modifikation einreicht.
        state["done"] = True
        try:
            if state["error"]:
                err_msg = f"Fehler: {state['error']}"
                root.after(0, lambda m=err_msg: status_lbl.config(text=m))
                root.after(2500, root.destroy)
            else:
                root.after(0, lambda: status_lbl.config(text="Fertig."))
                root.after(900, root.destroy)
        except Exception:
            pass

    threading.Thread(target=worker, daemon=True).start()
    root.mainloop()
    return (state["error"] is None, state["error"] or "")


def _show_already_running_toast():
    """Kleines Hinweis-Fenster (~2s), wenn schon ein Uninstall laeuft."""
    try:
        import tkinter as tk
        root = tk.Tk()
        root.title(PRODUCT_SLUG)
        root.geometry("400x120")
        root.resizable(False, False)
        root.attributes("-topmost", True)
        root.update_idletasks()
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"+{(sw - 400) // 2}+{(sh - 120) // 2}")
        tk.Label(
            root,
            text=f"{PRODUCT_SLUG}-Deinstallation laeuft bereits.\n"
                 f"Bitte einen Moment warten...",
            font=("Segoe UI", 10), padx=20, pady=24, justify="center",
        ).pack(expand=True)
        root.after(2200, root.destroy)
        root.mainloop()
    except Exception:
        pass


def do_uninstall(status_cb=None, finalize: bool = False, orig_pid: int = 0):
    """Tut die eigentliche Cleanup-Arbeit.

    Self-Relaunch und Lock-Handling passieren in run_cli_uninstall — diese
    Funktion erwartet, dass sie aus einer Position laeuft wo INSTALL_DIR
    rmtree-bar ist (entweder als Temp-Kopie mit finalize=True, oder von
    einer EXE die NICHT im INSTALL_DIR liegt).
    """
    def status(msg: str):
        if status_cb:
            status_cb(msg)
        else:
            print(msg)

    if finalize:
        # Safe CWD: wenn unsere CWD unter INSTALL_DIR liegt (Apps-&-Features
        # vererbt das vom UninstallString-Aufrufer), kann Windows den Ordner
        # nicht loeschen solange wir noch laufen. Wechseln in ein neutrales
        # System-Verzeichnis das garantiert nicht zu loeschen ist.
        try:
            os.chdir(os.environ.get("SystemRoot", r"C:\Windows"))
        except Exception:
            pass

    if finalize and orig_pid:
        status("Warte auf Original-Prozess...")
        for _ in range(50):  # max ~5s
            if not _pid_alive(orig_pid):
                break
            time.sleep(0.1)

    status("Beende laufende Instanzen...")
    subprocess.call(
        ["taskkill", "/f", "/im", EXE_FILENAME],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    # Auch andere setup.exe-Instanzen ausser uns selbst killen. /fi-Filter
    # werden AND-verknuepft, IMAGENAME engt auf den Slug ein damit wir keine
    # fremden setup.exe-Prozesse abrasieren.
    my_pid = os.getpid()
    subprocess.call(
        ["taskkill", "/f",
         "/fi", f"IMAGENAME eq {SETUP_EXE_FILENAME}",
         "/fi", f"PID ne {my_pid}"],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    # Windows braucht nach taskkill ein paar Sekunden bis File-Handles aus
    # den gekillten Prozessen freigegeben sind — sonst blockt rmtree.
    time.sleep(2.0)

    status("Entferne Autostart...")
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, AUTOSTART_PATH, access=winreg.KEY_SET_VALUE
        ) as k:
            winreg.DeleteValue(k, AUTOSTART_NAME)
    except FileNotFoundError:
        pass

    status("Entferne Konfiguration...")
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
    except FileNotFoundError:
        pass

    status("Entferne Apps-&-Features-Eintrag...")
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY_PATH)
    except FileNotFoundError:
        pass

    status("Entferne Umgebungsvariable...")
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            access=winreg.KEY_SET_VALUE,
        ) as k:
            winreg.DeleteValue(k, PROXY_ENV_VAR)
    except FileNotFoundError:
        pass
    HWND_BROADCAST = 0xFFFF
    WM_SETTINGCHANGE = 0x001A
    ctypes.windll.user32.SendMessageTimeoutW(
        HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", 2, 5000, None
    )

    status("Loesche Programmdateien...")
    _retry_rmtree(INSTALL_DIR, status_cb=status_cb)

    if finalize:
        # Eigene Temp-Kopie nach Reboot loeschen lassen — wir koennen uns
        # nicht selbst entlinken solange wir noch laufen.
        try:
            _kernel32.MoveFileExW(sys.executable or "", None, _MOVEFILE_DELAY_UNTIL_REBOOT)
        except Exception:
            pass

    status("Deinstallation abgeschlossen.")


def _launch_log(msg: str):
    """Diagnostisches Log fuer step_launch — landet in %TEMP%/softshelf_launch.log."""
    try:
        log_path = os.path.join(
            os.environ.get("TEMP", r"C:\Windows\Temp"),
            f"{PRODUCT_SLUG.lower()}_launch.log",
        )
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}\n")
    except Exception:
        pass


def launch_in_user_session_via_schtasks(exe_path: str) -> bool:
    """Startet exe_path in der Session des aktiven Console-Users via Task-Scheduler.

    Pattern wie SCCM / MDT / ServiceUI / Tactical-Tray: SYSTEM erzeugt eine
    Einmal-Task mit Principal=ActiveUser und feuert sie sofort. Windows
    Task-Scheduler kuemmert sich um Session-Boundary, Token-Impersonation und
    Desktop-ACL — wir muessen kein einziges Win32-Token-API selbst aufrufen.

    Funktioniert solange:
      - PowerShell verfuegbar (auf jedem modernen Windows der Fall)
      - ein interaktiver User in Win32_ComputerSystem.UserName auftaucht
      - der aktuelle Prozess Task-Scheduler-Schreibrechte hat (SYSTEM hat das)
    """
    task_name = f"{PRODUCT_SLUG}-LaunchOnce"
    # PowerShell-Heredoc: Single-Quotes in PS sind literal, kein Var-Expand,
    # deshalb landen die Slug- und Pfad-Werte sicher als Strings drin.
    # exe_path validieren wir nicht extra, weil er aus unserem eigenen
    # INSTALL_DIR + EXE_FILENAME zusammengesetzt wird (defense in depth: der
    # slug ist regex-validiert, der INSTALL_DIR ist hardcoded).
    ps = (
        "$ErrorActionPreference = 'Stop';"
        "$user = (Get-CimInstance Win32_ComputerSystem).UserName;"
        "if (-not $user) { Write-Output 'no_console_user'; exit 0 };"
        f"$task = '{task_name}';"
        "try { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue } catch {};"
        # Working-Directory explizit auf SystemRoot setzen damit die Tray-EXE
        # NICHT mit CWD im INSTALL_DIR landet — sonst blockt Windows den
        # Apps-&-Features-Uninstall den rmdir auf den Install-Ordner.
        f"$action = New-ScheduledTaskAction -Execute '{exe_path}' -WorkingDirectory $env:SystemRoot;"
        # AtStartup-Trigger ist nur ein Platzhalter — wir feuern die Task
        # gleich manuell mit Start-ScheduledTask. Ohne Trigger laesst sich die
        # Task aber nicht registrieren.
        "$trigger = New-ScheduledTaskTrigger -AtStartup;"
        "$principal = New-ScheduledTaskPrincipal -UserId $user -RunLevel Limited -LogonType Interactive;"
        "$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable;"
        "Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null;"
        "Start-ScheduledTask -TaskName $task;"
        "Start-Sleep -Seconds 2;"
        "$info = Get-ScheduledTaskInfo -TaskName $task;"
        "Write-Output (\"taskResult=\" + $info.LastTaskResult);"
        "Unregister-ScheduledTask -TaskName $task -Confirm:$false;"
        "Write-Output 'launched'"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, timeout=90,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        out = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        _launch_log(f"schtasks-launch rc={result.returncode} stdout={out!r} stderr={err!r}")
        return result.returncode == 0 and "launched" in out
    except Exception as e:
        _launch_log(f"schtasks-launch exception: {e}")
        return False


def step_launch(exe_path: str):
    """Startet den Tray-Client in der richtigen Session.

    Wenn wir in Session 0 (SYSTEM) laufen — typischer Tactical-Pfad — feuern
    wir den Tray ueber den Task-Scheduler-Trick (SCCM/MDT-Pattern): temporaere
    Scheduled-Task mit Principal = aktivem Console-User, sofort starten,
    wieder loeschen. Windows kuemmert sich um Session-Boundary, kein
    Token-API-Drama.

    Wenn das fehlschlaegt (PowerShell missing, Schtasks broken, ...), faengt
    der Autostart in HKLM\\Run den Tray beim naechsten Login.

    Im interaktiven Fall (User-Doppelklick) reicht ein normaler Popen.
    """
    cur = current_session_id()
    _launch_log(f"step_launch start, cur_session={cur}, exe={exe_path}")
    if cur == 0:
        # Erst etwaige Zombie-Tray-Instanzen aus Session 0 killen.
        try:
            subprocess.call(
                ["taskkill", "/f", "/im", EXE_FILENAME],
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass

        target = active_console_session_id()
        _launch_log(f"active_console_session_id={target}")
        if target in (0, _INVALID_SESSION_ID):
            _launch_log("no active console session, skipping (autostart will pick up)")
            return

        # Task-Scheduler-Trick (SCCM/MDT-Pattern). Erprobt: funktioniert im
        # Tactical-SYSTEM-Kontext zuverlaessig, kein Win32-Token-API-Drama.
        # Falls jemals broken: HKLM\Run-Autostart faengt's beim naechsten Login.
        ok = launch_in_user_session_via_schtasks(exe_path)
        _launch_log(f"schtasks-launch returned {ok}")
        return

    # Interaktiver User-Kontext (Doppelklick / Setup-Wizard).
    try:
        subprocess.Popen(
            [exe_path],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
            close_fds=True,
        )
    except Exception as e:
        _launch_log(f"interactive Popen fehlgeschlagen: {e}")


def do_install(proxy_url: str, reg_secret: str, agent_id: str, status_cb=None):
    def status(msg: str):
        if status_cb:
            status_cb(msg)
        else:
            print(msg)

    # URL hier einmal validieren – sowohl CLI als auch GUI laufen hier durch
    proxy_url = validate_proxy_url(proxy_url)

    status("Kopiere Programmdateien...")
    exe_path = step_copy_files()

    status("Kopiere Installer-EXE...")
    setup_path = step_copy_setup_exe()

    status("Kopiere App-Icon...")
    icon_path = step_copy_icon()

    status("Registriere beim Proxy...")
    token = step_register(proxy_url, reg_secret, agent_id)

    status("Speichere Konfiguration...")
    step_save_config(proxy_url, token)

    status("Richte Autostart ein...")
    step_autostart(exe_path)

    status("Registriere Apps-&-Features-Eintrag...")
    step_register_uninstall_entry(exe_path, setup_path, icon_path)

    status(f"Starte {PRODUCT_SLUG}...")
    step_launch(exe_path)

    status("Installation abgeschlossen.")
    return exe_path


# ── CLI-Modus ──────────────────────────────────────────────────────────────────

def _write_error_log(msg: str, secret: str | None = None):
    """Schreibt Fehlermeldung nach %TEMP% – Secret wird redacted."""
    if secret:
        msg = msg.replace(secret, "***REDACTED***")
    log_name = f"{PRODUCT_SLUG.lower()}_setup_error.txt"
    log = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), log_name)
    try:
        with open(log, "w", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass


def run_cli(proxy_url: str, reg_secret: str, agent_id: str):
    try:
        do_install(proxy_url, reg_secret, agent_id)
    except Exception as exc:
        _write_error_log(f"Kiosk Setup fehlgeschlagen:\n{friendly_error(exc)}", secret=reg_secret)
        sys.exit(1)


def run_cli_uninstall(finalize: bool = False, orig_pid: int = 0):
    """Apps-&-Features Uninstall-Pfad mit Self-Relaunch, Lock und Status-GUI.

    Phase 1: aufgerufen aus dem INSTALL_DIR (Apps-&-Features klickt die
    UninstallString an). Wir kopieren uns nach %TEMP%, spawnen die Kopie mit
    --finalize, exiten — sonst koennen wir den INSTALL_DIR nicht loeschen
    weil Windows die laufende EXE haelt.

    Phase 2: aufgerufen als Temp-Kopie (finalize=True) oder von einer EXE
    die nicht im INSTALL_DIR liegt. Wir holen das Lock-File (raceschutz fuer
    Doppel-Klicks), zeigen ein Status-Fenster und rufen do_uninstall auf.
    """
    exe_self = sys.executable or ""

    def _is_under(child: str, parent: str) -> bool:
        try:
            return os.path.commonpath(
                [os.path.normpath(child).lower(), os.path.normpath(parent).lower()]
            ) == os.path.normpath(parent).lower()
        except ValueError:
            return False

    is_in_install_dir = (
        exe_self
        and os.path.exists(INSTALL_DIR)
        and _is_under(exe_self, INSTALL_DIR)
    )

    if is_in_install_dir and not finalize:
        # Phase 1: Self-Relaunch
        import secrets as _secrets
        import tempfile as _tempfile
        tmp_dir = _tempfile.gettempdir()
        tmp_name = f"{PRODUCT_SLUG.lower()}-uninstall-{_secrets.token_hex(4)}.exe"
        tmp_path = os.path.join(tmp_dir, tmp_name)
        try:
            shutil.copy2(exe_self, tmp_path)
        except Exception as e:
            _write_error_log(f"Self-relaunch copy fehlgeschlagen: {e}")
            sys.exit(1)
        my_pid = os.getpid()
        try:
            subprocess.Popen(
                [tmp_path, "--uninstall", "--finalize", "--orig-pid", str(my_pid)],
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
                close_fds=True,
            )
        except Exception as e:
            _write_error_log(f"Self-relaunch spawn fehlgeschlagen: {e}")
            sys.exit(1)
        sys.exit(0)

    # Phase 2: Temp-Kopie oder externer Aufruf
    if not _try_acquire_uninstall_lock():
        _show_already_running_toast()
        sys.exit(0)

    try:
        ok, err = _show_uninstall_window_and_run(
            lambda cb: do_uninstall(status_cb=cb, finalize=finalize, orig_pid=orig_pid),
        )
        if not ok:
            _write_error_log(f"Kiosk Deinstallation fehlgeschlagen:\n{err}")
            sys.exit(1)
    finally:
        _release_uninstall_lock()


# ── GUI-Modus ──────────────────────────────────────────────────────────────────

def run_gui(prefill_agent_id: str | None = None, prefill_proxy_url: str = ""):
    import threading
    import tkinter as tk
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title(f"{PRODUCT_SLUG} – Setup  v{__version__}")
    root.geometry("500x420")
    root.resizable(False, False)
    try:
        root.eval("tk::PlaceWindow . center")
    except Exception:
        pass

    style = ttk.Style(root)
    try:
        style.theme_use("vista")
    except Exception:
        pass

    frame = ttk.Frame(root, padding=26)
    frame.pack(fill="both", expand=True)

    # Header
    tk.Label(
        frame,
        text=PRODUCT_SLUG,
        font=("Segoe UI", 15, "bold"),
        fg="#0f172a",
        bg=root.cget("bg"),
    ).pack(anchor="w")
    tk.Label(
        frame,
        text="Zugangsdaten vom IT-Administrator eingeben.",
        fg="#64748b",
        bg=root.cget("bg"),
    ).pack(anchor="w", pady=(2, 18))

    def labeled_entry(label_text: str, show: str = "") -> tuple[tk.StringVar, ttk.Entry]:
        ttk.Label(frame, text=label_text).pack(anchor="w")
        var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=var, width=58, show=show)
        entry.pack(fill="x", pady=(2, 10))
        return var, entry

    proxy_var, _ = labeled_entry("Proxy-URL  (z.B. https://server.intern:8765)")
    if prefill_proxy_url:
        proxy_var.set(prefill_proxy_url)

    secret_var, secret_entry = labeled_entry("Registration Secret", show="•")
    show_secret = tk.BooleanVar(value=False)
    def toggle_secret():
        secret_entry.config(show="" if show_secret.get() else "•")
    ttk.Checkbutton(
        frame, text="Anzeigen", variable=show_secret, command=toggle_secret
    ).pack(anchor="w", pady=(0, 6))

    agent_var, _ = labeled_entry("Agent ID  (Tactical RMM Agent-ID dieses PCs)")
    if prefill_agent_id:
        agent_var.set(prefill_agent_id)

    status_var = tk.StringVar()
    status_lbl = tk.Label(
        frame, textvariable=status_var, fg="#64748b", bg=root.cget("bg"),
        wraplength=440, justify="left", anchor="w"
    )
    status_lbl.pack(anchor="w", pady=(4, 0), fill="x")

    btn_frame = ttk.Frame(frame)
    btn_frame.pack(fill="x", side="bottom", pady=(14, 0))

    def set_status(msg: str, error: bool = False):
        status_var.set(msg)
        status_lbl.config(fg="#dc2626" if error else "#64748b")

    def on_install():
        proxy  = proxy_var.get().strip()
        secret = secret_var.get().strip()
        agent  = agent_var.get().strip()

        if not proxy or not secret or not agent:
            set_status("Bitte alle Felder ausfüllen.", error=True)
            return

        # URL clientseitig vorab prüfen → bessere Fehlermeldung
        try:
            proxy = validate_proxy_url(proxy)
            proxy_var.set(proxy)
        except ValueError as e:
            set_status(str(e), error=True)
            return

        install_btn.configure(state="disabled")
        uninstall_btn.configure(state="disabled")
        set_status("Starte Installation...")

        def run():
            try:
                do_install(
                    proxy, secret, agent,
                    status_cb=lambda m: root.after(0, lambda: set_status(m)),
                )
                root.after(
                    0,
                    lambda: (
                        messagebox.showinfo(
                            "Erfolg",
                            "Installation erfolgreich!\n\n"
                            f"{PRODUCT_SLUG} startet beim nächsten Windows-Login automatisch.",
                        ),
                        root.destroy(),
                    ),
                )
            except Exception as exc:
                msg = friendly_error(exc)
                root.after(
                    0,
                    lambda m=msg: (
                        set_status(m, error=True),
                        install_btn.configure(state="normal"),
                        uninstall_btn.configure(state="normal"),
                    ),
                )

        threading.Thread(target=run, daemon=True).start()

    def on_uninstall():
        if not messagebox.askyesno(
            "Deinstallieren",
            f"{PRODUCT_SLUG} wirklich von diesem PC entfernen?\n\n"
            "Autostart, Token und Programmdateien werden gelöscht.",
        ):
            return
        install_btn.configure(state="disabled")
        uninstall_btn.configure(state="disabled")

        def run():
            try:
                do_uninstall(
                    status_cb=lambda m: root.after(0, lambda: set_status(m))
                )
                root.after(
                    0,
                    lambda: (messagebox.showinfo("Fertig", "Deinstallation abgeschlossen."), root.destroy()),
                )
            except Exception as exc:
                msg = friendly_error(exc)
                root.after(
                    0,
                    lambda m=msg: (
                        set_status(m, error=True),
                        uninstall_btn.configure(state="normal"),
                        install_btn.configure(state="normal"),
                    ),
                )

        threading.Thread(target=run, daemon=True).start()

    install_btn = ttk.Button(btn_frame, text="Installieren", command=on_install)
    install_btn.pack(side="right")
    uninstall_btn = ttk.Button(btn_frame, text="Deinstallieren", command=on_uninstall)
    uninstall_btn.pack(side="right", padx=6)
    ttk.Button(btn_frame, text="Abbrechen", command=root.destroy).pack(
        side="right", padx=8
    )

    root.mainloop()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    require_admin()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--proxy-url",  dest="proxy_url",  default=DEFAULT_PROXY_URL)
    parser.add_argument("--reg-secret", dest="reg_secret")
    parser.add_argument("--agent-id",   dest="agent_id")
    parser.add_argument("--uninstall",  dest="uninstall",  action="store_true")
    # Self-relaunch fuer den Apps-&-Features-Uninstall-Pfad. Nicht von Hand
    # benutzen — der Original-Aufruf (--uninstall ohne --finalize) kopiert sich
    # nach %TEMP% und ruft sich selbst mit --finalize + --orig-pid <pid> auf.
    parser.add_argument("--finalize",   dest="finalize",   action="store_true")
    parser.add_argument("--orig-pid",   dest="orig_pid",   type=int, default=0)
    args, _ = parser.parse_known_args()

    if args.uninstall:
        run_cli_uninstall(finalize=args.finalize, orig_pid=args.orig_pid)
        return

    agent_id = args.agent_id or get_tactical_agent_id()

    if args.proxy_url and args.reg_secret and agent_id:
        run_cli(args.proxy_url, args.reg_secret, agent_id)
    else:
        run_gui(prefill_agent_id=agent_id, prefill_proxy_url=args.proxy_url or "")


if __name__ == "__main__":
    main()
