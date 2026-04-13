"""
Builder-HTTP-API — triggert PyInstaller-Builds via Wine.

POST /build
  Body: {"proxy_url": "http://10.0.0.5:8765", "version": "1.2.0"}
  Response: {"ok": true, "log": "..."}

GET /health
  Response: {"status": "ok"}

Läuft im Docker-Internal-Network auf Port 8766, nicht von außen erreichbar.
"""
import asyncio
import os
import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Softshelf Builder", docs_url=None, redoc_url=None)

_build_lock = asyncio.Lock()


class BuildRequest(BaseModel):
    proxy_url: str = Field(min_length=1)
    version: str = Field(default="1.2.0")


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
            return {"ok": False, "log": "Timeout (>15 min)"}
        except Exception as e:
            return {"ok": False, "log": f"Builder-Fehler: {e}"}

        # Artefakte verifizieren
        kiosk_exe = os.path.join(env["OUTPUT_DIR"], "softshelf.exe")
        setup_exe = os.path.join(env["OUTPUT_DIR"], "softshelf-setup.exe")
        if ok and os.path.isfile(kiosk_exe) and os.path.isfile(setup_exe):
            size_k = os.path.getsize(kiosk_exe)
            size_s = os.path.getsize(setup_exe)
            log += f"\n\n=== Artefakte ===\nsoftshelf.exe: {size_k // 1024 // 1024} MB\nsoftshelf-setup.exe: {size_s // 1024 // 1024} MB\n"
            return {"ok": True, "log": log}

        return {"ok": False, "log": log or "Build fehlgeschlagen (keine Artefakte)"}
