"""
Builder-HTTP-API — triggert PyInstaller-Builds via Wine.

POST /build
  Body: {"proxy_url": "http://10.0.0.5:8765", "version": "1.6.0",
         "product_slug": "Softshelf", "publisher": "Softshelf",
         "icon_ico_b64": "<optional base64>"}
  Response: {"ok": true, "log": "...", "slug": "Softshelf",
             "artifacts": ["Softshelf.exe", "Softshelf-setup.exe"]}

GET /health
  Response: {"status": "ok"}

Läuft im Docker-Internal-Network auf Port 8766, nicht von außen erreichbar.
"""
import asyncio
import base64
import hashlib
import os
import re
import secrets
import tempfile
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="Softshelf Builder", docs_url=None, redoc_url=None)

_build_lock = asyncio.Lock()

# Shared-Secret-Auth: der Builder ist zwar nur im Docker-Netz erreichbar,
# aber jeder Prozess/Container in diesem Netz (oder eine kuenftige
# SSRF-Luecke im Proxy) konnte sonst beliebige Builds mit beliebiger
# proxy_url triggern — manipulierte Client-EXEs, die ueber den regulaeren
# Download-Pfad verteilt wuerden. Secret kommt via Compose aus SECRET_KEY.
_BUILD_SECRET = os.environ.get("BUILD_SHARED_SECRET", "")


def _check_build_auth(x_build_auth: str | None) -> None:
    if not _BUILD_SECRET:
        raise HTTPException(
            status_code=503,
            detail="BUILD_SHARED_SECRET nicht gesetzt — Builder-Service in "
                   "docker-compose.yml mit dem Secret versorgen.",
        )
    expected = hashlib.sha256(
        f"softshelf-build:{_BUILD_SECRET}".encode("utf-8")
    ).hexdigest()
    if not x_build_auth or not secrets.compare_digest(x_build_auth, expected):
        raise HTTPException(status_code=403, detail="Build-Auth ungueltig")

# Muss identisch zur Validierung im Proxy und in build.sh sein.
_SLUG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,30}$")
# Frei waehlbarer Publisher: dieselbe Regel wie der display_title-Validator
# im Proxy — keine Steuerzeichen, keine HTML-Sonderzeichen, max 60 Zeichen.
_PUBLISHER_RE = re.compile(r"^[^\x00-\x1f\x7f<>\"'`]{1,60}$")
# Selbe Regex wie der Proxy-Validator fuer client_app_name (display_title).
_DISPLAY_TITLE_RE = _PUBLISHER_RE
# Defensive Limits fuer den base64-bloeg: 8 MB Klartext = ~10.7 MB base64.
_MAX_ICON_B64_LEN = 11 * 1024 * 1024
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
# ICO-Magic-Bytes fuer Early-Reject von Non-ICO Uploads.
_ICO_MAGIC = b"\x00\x00\x01\x00"


class BuildRequest(BaseModel):
    proxy_url: str = Field(min_length=1)
    version: str = Field(default="1.6.0")
    product_slug: str = Field(default="Softshelf")
    publisher: str = Field(default="Softshelf")
    client_app_name: str = Field(default="Softshelf")
    icon_ico_b64: str | None = None

    @field_validator("product_slug")
    @classmethod
    def _check_slug(cls, v: str) -> str:
        if not _SLUG_RE.match(v):
            raise ValueError(
                "product_slug muss mit einem Buchstaben beginnen und darf "
                "nur Buchstaben, Ziffern, _, - enthalten (1-31 Zeichen)"
            )
        return v

    @field_validator("publisher", "client_app_name")
    @classmethod
    def _check_display_title(cls, v: str) -> str:
        if not _DISPLAY_TITLE_RE.match(v):
            raise ValueError(
                "max 60 Zeichen, keine Steuerzeichen oder HTML-Sonderzeichen "
                "(<, >, \", ', `)"
            )
        return v

    @field_validator("icon_ico_b64")
    @classmethod
    def _check_icon(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if len(v) > _MAX_ICON_B64_LEN:
            raise ValueError("icon_ico_b64 ist zu gross (>11 MB base64)")
        # Format/Charset-Check ohne den vollen Decode hier — der Handler
        # macht den eigentlichen Decode + Magic-Byte-Check, einmal reicht.
        if not _BASE64_RE.fullmatch(v):
            raise ValueError("icon_ico_b64 ist kein gueltiges base64")
        return v


@app.get("/health")
async def health():
    return {"status": "ok"}


_SELFTEST_SCRIPT = r"""
set -e
SELFTEST_DIR="$(mktemp -d -p /tmp sf-selftest-XXXXXX)"
cd "$SELFTEST_DIR"
cat > hello.py <<'PYEOF'
print("ok")
PYEOF
echo "=== wine python --version ==="
wine python --version 2>&1 || true
echo
echo "=== pyinstaller --version ==="
wine pyinstaller --version 2>&1 || true
echo
echo "=== build hello.exe ==="
wine pyinstaller --onefile --clean --noconfirm --distpath ./dist --workpath ./build --specpath . hello.py 2>&1
ls -la ./dist
if [ -f ./dist/hello.exe ]; then
    SIZE_KB=$(($(stat -c '%s' ./dist/hello.exe) / 1024))
    echo "SELFTEST_OK ($SIZE_KB KB)"
else
    echo "SELFTEST_FAIL: hello.exe not produced"
    exit 1
fi
"""


@app.post("/selftest")
async def selftest(x_build_auth: str | None = Header(default=None)):
    """Quick-Build-Probe: Wine + PyInstaller produzieren ein 1-Liner-EXE.
    Erfolgt unter dem regulaeren build-lock, damit kein Konflikt mit echtem
    Build. ~30s im Cold-Case."""
    _check_build_auth(x_build_auth)
    if _build_lock.locked():
        raise HTTPException(status_code=409, detail="Ein Build laeuft bereits.")
    async with _build_lock:
        try:
            proc = await asyncio.create_subprocess_exec(
                "bash", "-c", _SELFTEST_SCRIPT,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            log = stdout.decode("utf-8", errors="replace")
            ok = proc.returncode == 0 and "SELFTEST_OK" in log
            return {"ok": ok, "log": log}
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {"ok": False, "log": "Timeout (>120s)"}
        except Exception as e:
            return {"ok": False, "log": f"Selftest-Fehler: {e}"}


@app.post("/build")
async def build(req: BuildRequest, x_build_auth: str | None = Header(default=None)):
    """Triggert den build.sh-Lauf. Seriell — nur ein Build gleichzeitig."""
    _check_build_auth(x_build_auth)
    if _build_lock.locked():
        raise HTTPException(status_code=409, detail="Ein Build läuft bereits.")

    async with _build_lock:
        # Optional Icon dekodieren und in eine Temp-Datei legen, die build.sh
        # als ICON_PATH liest. PyInstaller braucht einen Pfad, kein bytes-Stream.
        # Validator hat bereits Base64-Charset + Length geprueft, hier dekodieren
        # wir einmal und validieren die ICO-Magic-Bytes.
        icon_path: str | None = None
        if req.icon_ico_b64:
            try:
                raw = base64.b64decode(req.icon_ico_b64, validate=True)
            except Exception:
                raise HTTPException(status_code=400, detail="icon_ico_b64 decode-Fehler")
            if not raw.startswith(_ICO_MAGIC):
                raise HTTPException(
                    status_code=400,
                    detail="icon_ico_b64 enthaelt keine ICO-Datei (Magic-Bytes fehlen)",
                )
            tmp = tempfile.NamedTemporaryFile(prefix="sf-icon-", suffix=".ico", delete=False)
            try:
                tmp.write(raw)
            finally:
                tmp.close()
            icon_path = tmp.name

        env = os.environ.copy()
        env["PROXY_URL"] = req.proxy_url
        env["VERSION"] = req.version
        env["PRODUCT_SLUG"] = req.product_slug
        env["PUBLISHER"] = req.publisher
        env["CLIENT_APP_NAME"] = req.client_app_name
        env["OUTPUT_DIR"] = "/app/downloads"
        if icon_path:
            env["ICON_PATH"] = icon_path
        # Branding-Icon zusaetzlich als base64 einbacken (nicht nur als
        # PyInstaller --icon = EXE-Datei-Icon), damit der Tray es offline
        # sofort als Icon nutzt statt des generierten Fallback-Quadrats.
        if req.icon_ico_b64:
            env["ICON_ICO_B64"] = req.icon_ico_b64

        try:
            proc = await asyncio.create_subprocess_exec(
                "/app/build.sh",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=900)
            log = stdout.decode("utf-8", errors="replace")
            ok = proc.returncode == 0
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {"ok": False, "log": "Timeout (>15 min)", "slug": req.product_slug}
        except Exception as e:
            return {"ok": False, "log": f"Builder-Fehler: {e}", "slug": req.product_slug}
        finally:
            if icon_path:
                try:
                    os.unlink(icon_path)
                except Exception:
                    pass

        # Artefakte verifizieren
        tray_name   = f"{req.product_slug}.exe"
        setup_name  = f"{req.product_slug}-setup.exe"
        tray_path   = os.path.join(env["OUTPUT_DIR"], tray_name)
        setup_path  = os.path.join(env["OUTPUT_DIR"], setup_name)
        if ok and os.path.isfile(tray_path) and os.path.isfile(setup_path):
            size_t = os.path.getsize(tray_path)
            size_s = os.path.getsize(setup_path)
            log += (
                f"\n\n=== Artefakte ===\n"
                f"{tray_name}: {size_t // 1024 // 1024} MB\n"
                f"{setup_name}: {size_s // 1024 // 1024} MB\n"
            )
            return {
                "ok": True,
                "log": log,
                "slug": req.product_slug,
                "artifacts": [tray_name, setup_name],
            }

        return {
            "ok": False,
            "log": log or "Build fehlgeschlagen (keine Artefakte)",
            "slug": req.product_slug,
        }
