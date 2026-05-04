"""
Konfiguration in zwei Schichten:

  1. BOOTSTRAP  – aus .env, pydantic-geladen, static nach Start.
                  Enthält nur was nötig ist um den Proxy überhaupt hochzufahren:
                  SECRET_KEY (Krypto-Wurzel), Admin-Default-Credentials.

  2. RUNTIME    – in der SQLite-Tabelle `settings`, via Admin-UI editierbar.
                  Beispiele: tactical_url, tactical_api_key, registration_secret,
                  proxy_public_url, token_ttl_days, log_retention_days, max_upload_mb.

Bei einer neuen Installation kann der Admin optional INITIAL_*-Werte in die
.env schreiben; beim ersten Start werden diese in die settings-Tabelle übernommen.
Danach ist die .env nur noch für SECRET_KEY + Bootstrap-Admin relevant.
"""
import re
import warnings
from functools import lru_cache
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

# Product-Slug für CI-Branding: Buchstabe am Anfang, danach Buchstaben/Ziffern/_/-.
# Strikt fuer Dateinamen, Registry-Keys, Install-Pfade und PowerShell-Identifier —
# kein Leerzeichen, keine Path-Traversal-Chars. Fuer den frei waehlbaren Anzeige-
# titel des Admin-Portals gibt es separat das Setting `admin_portal_title`.
SLUG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,30}$")

# Frei waehlbarer Anzeigetitel: erlaubt Leerzeichen und Punkt, verbietet
# Steuerzeichen und HTML-relevante Sonderzeichen, die im Template per innerHTML
# bzw. <title> landen wuerden. Begrenzt auf 60 Zeichen damit das Layout passt.
DISPLAY_TITLE_RE = re.compile(r"^[^\x00-\x1f\x7f<>\"'`]{1,60}$")


class BootstrapSettings(BaseSettings):
    """Minimaler .env-Inhalt — nur was für den Start benötigt wird."""

    # Netzwerk
    host: str = "0.0.0.0"
    port: int = 8765

    # Crypto-Wurzel — niemals ändern nach Deploy, sonst JWTs invalidieren
    secret_key: str = Field(min_length=32)

    # Bootstrap-Admin — für erstes Login. Kann später im Admin-UI geändert werden
    # (wird dann in settings-Tabelle überschrieben)
    admin_username: str = "admin"
    admin_password: str = Field(min_length=8)

    # Optional: Initial-Werte für Runtime-Settings. Beim ersten Start werden
    # diese in die settings-Tabelle übernommen. Danach ignoriert.
    initial_tactical_url: str = ""
    initial_tactical_api_key: str = ""
    initial_registration_secret: str = ""
    initial_proxy_public_url: str = ""

    # Interne Builder-Adresse (docker-compose Service-Name)
    builder_url: str = "http://softshelf-builder:8766"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Legacy-.env-Variablen (TACTICAL_URL etc.) stören nicht


@lru_cache
def get_settings() -> BootstrapSettings:
    return BootstrapSettings()


# ── Runtime-Settings (aus DB) ─────────────────────────────────────────────────
# Definition + Defaults + Validierung pro Key

RUNTIME_KEYS: dict[str, dict] = {
    "tactical_url": {
        "label": "Tactical RMM URL",
        "help": "Basis-URL der Tactical-API, z. B. https://api.example.com",
        "type": "url",
        "secret": False,
        "required": True,
        "default": "",
    },
    "tactical_api_key": {
        "label": "Tactical API-Key",
        "help": "API-Key des Tactical-Users. Braucht 'can_manage_software' + 'can_send_cmd'.",
        "type": "string",
        "secret": True,
        "required": True,
        "default": "",
        "min_length": 10,
    },
    "registration_secret": {
        "label": "Registration Secret",
        "help": "Shared Secret für den Setup-Aufruf (--reg-secret). Rotieren via 'Neu erzeugen'.",
        "type": "string",
        "secret": True,
        "required": True,
        "default": "",
        "min_length": 16,
    },
    "proxy_public_url": {
        "label": "Proxy Public URL",
        "help": "Öffentlich erreichbare URL des Proxy für Tactical-Agent-Downloads. Wird in den Installer einkompiliert.",
        "type": "url",
        "secret": False,
        "required": True,
        "default": "",
    },
    "token_ttl_days": {
        "label": "Token-Lebensdauer (Tage)",
        "help": "Ablauf der Machine-Tokens. 0 = unbegrenzt.",
        "type": "int",
        "secret": False,
        "required": False,
        "default": "365",
    },
    "log_retention_days": {
        "label": "Log-Aufbewahrung (Tage)",
        "help": "Audit + Install-Log Einträge älter als N Tage werden beim Start gelöscht.",
        "type": "int",
        "secret": False,
        "required": False,
        "default": "90",
    },
    "max_upload_mb": {
        "label": "Max Upload (MB)",
        "help": "Größenlimit für custom MSI/EXE Dateien.",
        "type": "int",
        "secret": False,
        "required": False,
        "default": "500",
    },
    "client_app_name": {
        "label": "Client-Titel",
        "help": "Name der im Kiosk-Fenster, Tray-Tooltip und Dialogen angezeigt wird. Änderungen greifen sofort, kein Rebuild nötig.",
        "type": "string",
        "secret": False,
        "required": False,
        "default": "Softshelf",
    },
    "admin_portal_title": {
        "label": "Admin-Portal-Titel",
        "help": (
            "Anzeigename des Web-Portals (Browser-Tab und Header-Brand). "
            "Frei wählbar inkl. Leerzeichen — z. B. 'Acme IT Self-Service'. "
            "Greift sofort beim nächsten Page-Load, kein Rebuild nötig. "
            "Max. 60 Zeichen, keine HTML-Sonderzeichen."
        ),
        "type": "display_title",
        "secret": False,
        "required": False,
        "default": "Softshelf",
    },
    "product_slug": {
        "label": "Produkt-Slug (Client-Branding)",
        "help": (
            "Technischer Name für Dateiname, Install-Pfad, Registry-Key, "
            "Autostart-Eintrag und Umgebungsvariable des Tray-Clients. "
            "Strikt: Buchstabe am Anfang, danach Buchstaben/Ziffern/_/-, "
            "1-31 Zeichen, keine Leerzeichen (Windows-Filesystem-Vorgaben). "
            "Den frei wählbaren Anzeige-Titel des Tray-Clients steuerst "
            "du über 'Client-Titel' oben. Änderung des Slugs erfordert "
            "Rebuild und Neuinstallation auf den Endgeräten."
        ),
        "type": "slug",
        "secret": False,
        "required": False,
        "default": "Softshelf",
    },
    "support_email": {
        "label": "Support-E-Mail",
        "help": (
            "E-Mail-Adresse die auf der Landing-Page als 'IT kontaktieren' "
            "Link verwendet wird. Wenn leer, wird der Button ausgeblendet."
        ),
        "type": "string",
        "secret": False,
        "required": False,
        "default": "",
    },
    "publisher": {
        "label": "Publisher (Apps & Features)",
        "help": (
            "Herausgeber-Name, der unter Apps & Features als Publisher des "
            "installierten Clients erscheint. Frei wählbar, max. 60 Zeichen, "
            "keine HTML-Sonderzeichen. Wird beim nächsten EXE-Build in den "
            "Installer eingebacken — Endgeräte sehen die Änderung erst nach "
            "Rebuild + Neuinstallation."
        ),
        "type": "display_title",
        "secret": False,
        "required": False,
        "default": "Softshelf",
    },
    # ── SSO (Microsoft Entra ID / Azure AD) ──
    "sso_enabled": {
        "label": "SSO aktivieren",
        "help": "Wenn aktiv, erscheint auf der Login-Seite ein 'Mit Microsoft anmelden'-Button.",
        "type": "bool",
        "secret": False,
        "required": False,
        "default": "false",
    },
    "sso_tenant_id": {
        "label": "Entra Tenant-ID",
        "help": "Die Tenant-ID (GUID) eures Microsoft-365-Tenants. Zu finden im Azure-Portal unter Entra ID → Übersicht.",
        "type": "string",
        "secret": False,
        "required": False,
        "default": "",
    },
    "sso_client_id": {
        "label": "Entra App Client-ID",
        "help": "Die Application-(client)-ID einer App-Registrierung in Entra ID. Redirect-URI in der App muss <proxy_public_url>/admin/sso/callback sein.",
        "type": "string",
        "secret": False,
        "required": False,
        "default": "",
    },
    "sso_client_secret": {
        "label": "Entra App Client-Secret",
        "help": "Client-Secret der App-Registrierung (in Entra unter Zertifikate &amp; Geheimnisse generierbar).",
        "type": "string",
        "secret": True,
        "required": False,
        "default": "",
    },
    "sso_auto_create": {
        "label": "User automatisch anlegen",
        "help": "Wenn aktiv, wird beim ersten Microsoft-Login automatisch ein lokaler Admin-User angelegt. Sonst muss der Username vorher manuell mit derselben E-Mail in der Benutzer-Verwaltung angelegt sein.",
        "type": "bool",
        "secret": False,
        "required": False,
        "default": "false",
    },
    "rollout_ring1_label": {
        "label": "Ring 1 Name",
        "help": "Anzeigename fuer Ring 1 (Canary — kleinste Testgruppe, erste Phase).",
        "type": "string", "secret": False, "required": False,
        "default": "Canary",
    },
    "rollout_ring2_label": {
        "label": "Ring 2 Name",
        "help": "Anzeigename fuer Ring 2 (Pilot — zweite Phase).",
        "type": "string", "secret": False, "required": False,
        "default": "Pilot",
    },
    "rollout_ring3_label": {
        "label": "Ring 3 Name",
        "help": "Anzeigename fuer Ring 3 (Produktion — Default bei neuen Agents, letzte Phase).",
        "type": "string", "secret": False, "required": False,
        "default": "Produktion",
    },
    "rollout_default_staged": {
        "label": "Neue winget-Pakete automatisch als Staged",
        "help": "Wenn aktiv: alle neu aktivierten winget-Pakete werden als staged_rollout markiert.",
        "type": "bool", "secret": False, "required": False,
        "default": "false",
    },
    "rollout_auto_advance_enabled": {
        "label": "Auto-Advance aktivieren",
        "help": "Wenn aktiv: aktive Rollouts gehen automatisch zur naechsten Phase nach X Stunden ohne neue Fehler.",
        "type": "bool", "secret": False, "required": False,
        "default": "false",
    },
    "rollout_auto_advance_hours_1_to_2": {
        "label": "Auto-Advance: Ring 1 → Ring 2 (Std)",
        "help": "Wartezeit nach Dispatch auf Ring 1 bevor Auto-Advance zu Ring 2 geht. Default 24h.",
        "type": "int", "secret": False, "required": False,
        "default": "24",
    },
    "rollout_auto_advance_hours_2_to_3": {
        "label": "Auto-Advance: Ring 2 → Ring 3 (Std)",
        "help": "Wartezeit nach Dispatch auf Ring 2 bevor Auto-Advance zu Produktion (Ring 3) geht. Default 168h = 7 Tage.",
        "type": "int", "secret": False, "required": False,
        "default": "168",
    },
    "rollout_auto_advance_hours": {
        "label": "(deprecated) Auto-Advance Wartezeit (Stunden)",
        "help": "Legacy-Key. Wird bei Migration in hours_1_to_2 uebernommen. Nicht mehr benutzen.",
        "type": "int", "secret": False, "required": False,
        "default": "24",
    },
    "rollout_max_error_pct": {
        "label": "Max. Fehler-Rate (%)",
        "help": "Wenn in einer Phase mehr als N% der Dispatches scheitern: Rollout pausieren. 0 = Feature aus.",
        "type": "int", "secret": False, "required": False,
        "default": "0",
    },
}


def validate_runtime_value(key: str, value: str) -> str:
    """Validiert einen neuen Runtime-Setting-Wert. Wirft ValueError bei Fehler."""
    if key not in RUNTIME_KEYS:
        raise ValueError(f"Unbekannter Setting-Key: {key}")
    meta = RUNTIME_KEYS[key]

    # Leerer Wert nur wenn nicht required
    if not value:
        if meta.get("required"):
            raise ValueError(f"{meta['label']} darf nicht leer sein")
        return ""

    t = meta.get("type", "string")

    if t == "url":
        if not value.startswith(("http://", "https://")):
            raise ValueError(f"{meta['label']} muss mit http:// oder https:// beginnen")
        # Defensive: keine Steuerzeichen, Anführungszeichen oder Backslashes —
        # dieser Wert wird teilweise in shell/Python/JS Code eingebettet.
        for ch in value:
            if ord(ch) < 32 or ch in ('"', "'", "\\", "\x7f", "\n", "\r"):
                raise ValueError(
                    f"{meta['label']} enthält ungültige Zeichen ({ch!r})"
                )
        # URL-Parse zur Validierung des Aufbaus
        from urllib.parse import urlparse
        parsed = urlparse(value)
        if not parsed.netloc:
            raise ValueError(f"{meta['label']} ist keine gültige URL")
        if value.startswith("http://"):
            warnings.warn(f"{meta['label']} ist HTTP (unverschlüsselt)", stacklevel=2)
        return value.rstrip("/")

    if t == "int":
        try:
            n = int(value)
        except ValueError:
            raise ValueError(f"{meta['label']} muss eine Zahl sein")
        if n < 0:
            raise ValueError(f"{meta['label']} darf nicht negativ sein")
        return str(n)

    if t == "bool":
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return "true"
        if normalized in ("0", "false", "no", "off"):
            return "false"
        raise ValueError(f"{meta['label']} muss true oder false sein")

    if t == "slug":
        # Strikt fuer Dateinamen, Registry-Keys, PowerShell-Identifier.
        # Kein Leerzeichen, keine Path-Traversal-Chars, kein Beginn mit Ziffer.
        if not SLUG_RE.match(value):
            raise ValueError(
                f"{meta['label']} muss mit einem Buchstaben beginnen und darf "
                f"nur Buchstaben, Ziffern, Unterstrich und Bindestrich enthalten "
                f"(1-31 Zeichen, keine Leerzeichen)"
            )
        return value

    if t == "display_title":
        # Frei waehlbarer Anzeigetext: Leerzeichen erlaubt, HTML-Sonderzeichen
        # die in <title> oder als Brand-Text per innerHTML landen wuerden,
        # sind gesperrt. Whitespace wird trim/collapsed.
        normalized = " ".join(value.split())
        if not DISPLAY_TITLE_RE.match(normalized):
            raise ValueError(
                f"{meta['label']} darf max. 60 Zeichen lang sein und keine "
                f"Steuerzeichen oder HTML-Sonderzeichen (<, >, \", ', `) enthalten"
            )
        return normalized

    # string
    min_len = meta.get("min_length", 0)
    if len(value) < min_len:
        raise ValueError(f"{meta['label']} muss mind. {min_len} Zeichen haben")
    return value


# ── Helper um Runtime-Settings lesbar zu machen ───────────────────────────────

async def runtime_value(key: str) -> str:
    """Async-Accessor für Runtime-Settings mit Default-Fallback."""
    import database  # local import to avoid circular
    meta = RUNTIME_KEYS.get(key, {})
    default = meta.get("default", "")
    return await database.get_setting(key, default)


async def runtime_int(key: str) -> int:
    val = await runtime_value(key)
    try:
        return int(val)
    except (ValueError, TypeError):
        return int(RUNTIME_KEYS.get(key, {}).get("default", "0") or "0")
