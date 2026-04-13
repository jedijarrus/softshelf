"""
Kiosk Setup / Installer

Aufruf (still, z.B. via Tactical RMM):
    softshelf-setup.exe --proxy-url URL --reg-secret SECRET --agent-id ID

Aufruf (GUI-Wizard, Doppelklick):
    softshelf-setup.exe

Was dieser Installer macht:
  1. softshelf.exe nach C:\\Program Files\\Softshelf\\ kopieren
  2. Diesen PC beim Proxy registrieren (Machine Token holen)
  3. Token + ProxyUrl in HKLM\\SOFTWARE\\Softshelf speichern
  4. ProxyUrl als System-Umgebungsvariable setzen
  5. Autostart in HKLM eintragen (startet beim naechsten User-Login)
"""
import argparse
import ctypes
import os
import shutil
import sys
import winreg
from urllib.parse import urlparse

import httpx

try:
    from _version import __version__
except Exception:
    __version__ = "?"

try:
    from _build_config import DEFAULT_PROXY_URL, BUILD_VERSION
    # Version aus build_config hat Vorrang wenn gesetzt
    if BUILD_VERSION and BUILD_VERSION != "?":
        __version__ = BUILD_VERSION
except Exception:
    DEFAULT_PROXY_URL = ""


# ── Konstanten ─────────────────────────────────────────────────────────────────

INSTALL_DIR    = r"C:\Program Files\Softshelf"
REG_PATH       = r"SOFTWARE\Softshelf"
AUTOSTART_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_NAME = "Softshelf"
PROXY_ENV_VAR  = "SOFTSHELF_PROXY_URL"


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
    src = resource_path("softshelf.exe")
    dst = os.path.join(INSTALL_DIR, "softshelf.exe")
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


def do_uninstall(status_cb=None):
    import subprocess

    def status(msg: str):
        if status_cb:
            status_cb(msg)
        else:
            print(msg)

    status("Beende laufende Instanz...")
    subprocess.call(
        ["taskkill", "/f", "/im", "softshelf.exe"],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

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

    status("Lösche Programmdateien...")
    import shutil as _shutil
    _shutil.rmtree(INSTALL_DIR, ignore_errors=True)

    status("Deinstallation abgeschlossen.")


def step_launch(exe_path: str):
    """Startet softshelf.exe im Hintergrund (Best-Effort)."""
    import subprocess
    try:
        subprocess.Popen(
            [exe_path],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
            close_fds=True,
        )
    except Exception:
        pass  # Beim naechsten Login startet es per Autostart


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

    status("Registriere beim Proxy...")
    token = step_register(proxy_url, reg_secret, agent_id)

    status("Speichere Konfiguration...")
    step_save_config(proxy_url, token)

    status("Richte Autostart ein...")
    step_autostart(exe_path)

    status("Starte Softshelf...")
    step_launch(exe_path)

    status("Installation abgeschlossen.")
    return exe_path


# ── CLI-Modus ──────────────────────────────────────────────────────────────────

def _write_error_log(msg: str, secret: str | None = None):
    """Schreibt Fehlermeldung nach %TEMP% – Secret wird redacted."""
    if secret:
        msg = msg.replace(secret, "***REDACTED***")
    log = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "softshelf_setup_error.txt")
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


def run_cli_uninstall():
    try:
        do_uninstall()
    except Exception as exc:
        _write_error_log(f"Kiosk Deinstallation fehlgeschlagen:\n{exc}")
        sys.exit(1)


# ── GUI-Modus ──────────────────────────────────────────────────────────────────

def run_gui(prefill_agent_id: str | None = None, prefill_proxy_url: str = ""):
    import threading
    import tkinter as tk
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title(f"Softshelf – Setup  v{__version__}")
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
        text="Softshelf",
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

    proxy_var, _ = labeled_entry("Proxy-URL  (z.B. https://softshelf.intern:8765)")
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
                            "Das Softshelf startet beim nächsten Windows-Login automatisch.",
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
            "Softshelf wirklich von diesem PC entfernen?\n\n"
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
    args, _ = parser.parse_known_args()

    if args.uninstall:
        run_cli_uninstall()
        return

    agent_id = args.agent_id or get_tactical_agent_id()

    if args.proxy_url and args.reg_secret and agent_id:
        run_cli(args.proxy_url, args.reg_secret, agent_id)
    else:
        run_gui(prefill_agent_id=agent_id, prefill_proxy_url=args.proxy_url or "")


if __name__ == "__main__":
    main()
