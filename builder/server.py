"""
Builder-HTTP-API — triggert PyInstaller-Builds via Wine.

POST /build
  Body: {"proxy_url": "http://10.0.0.5:8765", "version": "1.2.0",
         "product_slug": "Softshelf"}
  Response: {"ok": true, "log": "...", "slug": "Softshelf",
             "artifacts": ["Softshelf.exe", "Softshelf-setup.exe"]}

GET /health
  Response: {"status": "ok"}

Läuft im Docker-Internal-Network auf Port 8766, nicht von außen erreichbar.
"""
import asyncio
import os
import re
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="Softshelf Builder", docs_url=None, redoc_url=None)

_build_lock = asyncio.Lock()

# Muss identisch zur Validierung im Proxy und in build.sh sein.
_SLUG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,30}$")


class BuildRequest(BaseModel):
    proxy_url: str = Field(min_length=1)
    version: str = Field(default="1.2.0")
    product_slug: str = Field(default="Softshelf")

    @field_validator("product_slug")
    @classmethod
    def _check_slug(cls, v: str) -> str:
        if not _SLUG_RE.match(v):
            raise ValueError(
                "product_slug muss mit einem Buchstaben beginnen und darf "
                "nur Buchstaben, Ziffern, _, - enthalten (1-31 Zeichen)"
            )
        return v


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/build")
async def build(req: BuildRequest):
    """Triggert den build.sh-Lauf. Seriell — nur ein Build gleichzeitig."""
    if _build_lock.locked():
        raise HTTPException(status_code=409, detail="Ein Build läuft bereits.")

    async with _build_lock:
        env = os.environ.copy()
        env["PROXY_URL"] = req.proxy_url
        env["VERSION"] = req.version
        env["PRODUCT_SLUG"] = req.product_slug
        env["OUTPUT_DIR"] = "/app/downloads"

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
