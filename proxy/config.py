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
# Die Länge 1-31 ist durch die Erfahrung mit Windows-Filenames + Registry-Keys
# gesetzt — genug für sinnvolle Namen, wenig genug um in GUI-Labels zu passen.
SLUG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,30}$")


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
    "product_slug": {
        "label": "Produkt-Slug (CI-Branding)",
        "help": (
            "Technischer Name für Dateinamen, Install-Pfad, Registry-Key und "
            "Autostart. Wird beim EXE-Build in die Clients eingebacken. "
            "Erlaubt: Buchstabe am Anfang, dann Buchstaben/Ziffern/_/-, 1-31 "
            "Zeichen. Änderung erfordert Rebuild + Neuinstallation auf den "
            "Endgeräten."
        ),
        "type": "slug",
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
        # Safe für Windows-Filenames, Registry-Keys, Program-Files-Pfade,
        # URL-Segmente, PowerShell-Identifier. Kein Leerzeichen, keine
        # Path-Traversal-Chars, kein Beginn mit Ziffer/Sonderzeichen.
        if not SLUG_RE.match(value):
            raise ValueError(
                f"{meta['label']} muss mit einem Buchstaben beginnen und darf "
                f"nur Buchstaben, Ziffern, Unterstrich und Bindestrich enthalten "
                f"(1-31 Zeichen)"
            )
        return value

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
