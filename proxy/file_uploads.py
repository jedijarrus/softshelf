"""
File-Upload-Helfer für custom MSI/EXE Pakete und Programm-Ordner.

Speicherung: /app/data/uploads/{sha256}.{ext}
Hash-basierte Dateinamen → automatische Deduplikation.

Drei Upload-Modi:
  • Single MSI: parse_msi_metadata() liefert Detection-Name + Uninstall-Cmd
  • Single EXE: keine Metadaten, User pflegt Felder selbst
  • Programm-Ordner: save_folder_upload() zippt die Dateien serverseitig zu
    einem .zip, parst die enthaltenen .exe/.msi/.bat/.cmd als Entry-Point-
    Kandidaten. Der Client macht beim Install Expand-Archive + entry_point.
"""
import asyncio
import hashlib
import os
import re
import secrets
import zipfile

from fastapi import UploadFile, HTTPException

import database

UPLOAD_DIR = os.path.join(os.path.dirname(database.DB_PATH), "uploads")
ALLOWED_EXTENSIONS = (".msi", ".exe")
ARCHIVE_ENTRY_EXTENSIONS = (".exe", ".msi", ".bat", ".cmd")
_PKG_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,99}$")


def _ensure_upload_dir():
    os.makedirs(UPLOAD_DIR, exist_ok=True)


def _slug_from_filename(filename: str) -> str:
    """
    Erzeugt einen package_name aus dem Dateinamen, regex-konform:
      'Softshelf Tool 2.1.msi' → 'Softshelf_Tool_2.1'
    """
    base = os.path.splitext(os.path.basename(filename))[0]
    slug = re.sub(r"[^a-zA-Z0-9._\-]", "_", base)
    slug = re.sub(r"_+", "_", slug).strip("_-.")
    if not slug or not slug[0].isalnum():
        slug = "pkg_" + slug
    return slug[:90]  # Platz fuer -2..-99 Suffix von _unique_name


async def _unique_name(slug: str) -> str:
    """Sucht einen freien Namen, indem ggf. -2, -3, ... angehängt wird."""
    candidate = slug[:100]
    n = 1
    while await database.get_package(candidate) is not None:
        n += 1
        candidate = f"{slug[:96]}-{n}"
    return candidate


async def save_upload(file: UploadFile, max_size_bytes: int) -> tuple[str, int, str]:
    """
    Streamt die Upload-Datei nach UPLOAD_DIR, berechnet SHA-256.
    Gibt (final_path, size_bytes, sha256) zurück.
    Raised HTTPException bei zu großer Datei oder ungültiger Extension.
    """
    _ensure_upload_dir()

    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Nur {', '.join(ALLOWED_EXTENSIONS)} erlaubt (war: {ext or 'ohne Endung'})",
        )

    tmp_path = os.path.join(UPLOAD_DIR, f"_tmp_{secrets.token_hex(8)}{ext}")
    h = hashlib.sha256()
    size = 0
    try:
        with open(tmp_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_size_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Datei zu groß (max {max_size_bytes // 1024 // 1024} MB)",
                    )
                h.update(chunk)
                out.write(chunk)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise

    sha256 = h.hexdigest()
    final_path = os.path.join(UPLOAD_DIR, f"{sha256}{ext}")

    if os.path.exists(final_path):
        # Datei mit gleichem Hash existiert bereits → tmp wegwerfen
        os.unlink(tmp_path)
    else:
        os.rename(tmp_path, final_path)

    return final_path, size, sha256


def find_file_path(sha256: str) -> str | None:
    """Sucht die gespeicherte Datei für einen gegebenen Hash (egal welche Extension)."""
    if not os.path.isdir(UPLOAD_DIR):
        return None
    for fn in os.listdir(UPLOAD_DIR):
        if fn.startswith(sha256 + "."):
            return os.path.join(UPLOAD_DIR, fn)
    return None


def delete_file(sha256: str) -> bool:
    """Löscht die Datei mit diesem Hash. Gibt True zurück wenn erfolgreich."""
    path = find_file_path(sha256)
    if path:
        try:
            os.unlink(path)
            return True
        except OSError:
            pass
    return False


async def parse_msi_metadata(path: str) -> dict:
    """
    Liest ProductCode, ProductName und ProductVersion aus einer MSI via `msiinfo`.
    Gibt {} zurück wenn msiinfo fehlt oder die Datei keine MSI ist.

    msiinfo wird via apt-Paket 'msitools' im Container bereitgestellt.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "msiinfo", "export", path, "Property",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            return {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

    result = {}
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        if "\t" not in line:
            continue
        key, _, val = line.partition("\t")
        key = key.strip()
        val = val.strip()
        if key in ("ProductCode", "ProductName", "ProductVersion", "Manufacturer"):
            result[key] = val
    return result


def build_msi_uninstall_cmd(product_code: str) -> str:
    """Standard-Uninstall-Command für eine MSI per Product-Code."""
    return f'msiexec /x "{product_code}" /qn /norestart'


async def parse_exe_metadata(path: str) -> dict:
    """
    Extrahiert ProductName und CompanyName aus einer EXE via 7z.

    7z parsed NSIS-Header, Inno-Setup-Daten, PE-VersionInfo und embedded
    Archive automatisch — robuster als unsere manuelle Binary-Analyse.
    Gibt {} zurück wenn 7z fehlt oder nichts findet.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "7z", "l", "-slt", path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            return {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

    result = {}
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if not val:
            continue
        if key == "ProductName" and "ProductName" not in result:
            result["ProductName"] = val
        elif key == "CompanyName" and "CompanyName" not in result:
            result["CompanyName"] = val
    return result


# ── Folder Upload (zippen serverseitig) ───────────────────────────────────────


async def save_folder_upload(
    files: list[UploadFile],
    max_size_bytes: int,
) -> tuple[str, int, str, list[str]]:
    """
    Streamt eine Liste von UploadFiles in einen temporären ZIP, hash't diesen,
    schiebt nach UPLOAD_DIR/<sha>.zip. Gibt (final_path, total_size, sha256,
    entries) zurück. `entries` enthält die installer-fähigen Dateien
    (.exe/.msi/.bat/.cmd) relativ zum ZIP-Root, sortiert.

    Erwartet: jedes UploadFile.filename enthält den Relativpfad innerhalb des
    Ordners (z.B. 'MyApp/setup.exe'). Frontend setzt das via
    `fd.append('files', f, f.webkitRelativePath)`.
    """
    _ensure_upload_dir()

    if not files:
        raise HTTPException(status_code=400, detail="Keine Dateien übergeben")

    tmp_path = os.path.join(UPLOAD_DIR, f"_tmp_{secrets.token_hex(8)}.zip")
    total_size = 0
    entries: list[str] = []
    seen_paths: set[str] = set()

    try:
        with zipfile.ZipFile(
            tmp_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
        ) as zf:
            for f in files:
                raw = (f.filename or "").replace("\\", "/")
                if not raw or raw.endswith("/"):
                    continue
                # Path-Traversal-Schutz: keine absoluten Pfade,
                # keine .., keine empty segments, keine Drive-Letter
                rel_raw = raw.lstrip("/")
                if rel_raw != raw:
                    raise HTTPException(
                        status_code=400, detail=f"Absolute Pfade nicht erlaubt: {raw}"
                    )
                parts = rel_raw.split("/")
                if any(p in ("..", "") for p in parts):
                    raise HTTPException(
                        status_code=400, detail=f"Ungültiger Pfad: {rel_raw}"
                    )
                if any(":" in p for p in parts):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Ungültiger Pfad (Drive-Letter): {rel_raw}",
                    )
                rel_path = "/".join(parts)
                if rel_path in seen_paths:
                    continue
                seen_paths.add(rel_path)

                # Streaming write in den ZIP, chunkweise
                with zf.open(rel_path, "w", force_zip64=True) as dest:
                    while True:
                        chunk = await f.read(1024 * 1024)
                        if not chunk:
                            break
                        total_size += len(chunk)
                        if total_size > max_size_bytes:
                            raise HTTPException(
                                status_code=413,
                                detail=(
                                    f"Ordner zu groß "
                                    f"(max {max_size_bytes // 1024 // 1024} MB)"
                                ),
                            )
                        dest.write(chunk)

                ext = os.path.splitext(rel_path)[1].lower()
                if ext in ARCHIVE_ENTRY_EXTENSIONS:
                    entries.append(rel_path)
    except HTTPException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise

    if not entries:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise HTTPException(
            status_code=400,
            detail="Im Ordner wurde keine .exe/.msi/.bat/.cmd gefunden — kein Entry-Point möglich.",
        )

    # SHA-256 vom finalen ZIP berechnen (sequenziell, schnell)
    h = hashlib.sha256()
    with open(tmp_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    sha256 = h.hexdigest()

    final_path = os.path.join(UPLOAD_DIR, f"{sha256}.zip")
    if os.path.exists(final_path):
        os.unlink(tmp_path)  # Dedup-Hit
    else:
        os.rename(tmp_path, final_path)

    entries.sort()
    return final_path, total_size, sha256, entries


def extract_archive_entries(zip_path: str) -> list[str]:
    """Liest die installer-fähigen Einträge aus einem bestehenden ZIP."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            entries = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                ext = os.path.splitext(info.filename)[1].lower()
                if ext in ARCHIVE_ENTRY_EXTENSIONS:
                    entries.append(info.filename)
            return sorted(entries)
    except (zipfile.BadZipFile, FileNotFoundError, OSError):
        return []


def extract_archive_filelist(zip_path: str) -> list[dict]:
    """Liest ALLE Dateien aus einem ZIP, gibt [{path, size}, ...] sortiert zurück."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            files = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                files.append({"path": info.filename, "size": info.file_size})
            files.sort(key=lambda f: f["path"].lower())
            return files
    except (zipfile.BadZipFile, FileNotFoundError, OSError):
        return []


async def edit_archive(
    source_path: str,
    remove_paths: set[str],
    add_files: list[UploadFile],
    add_prefix: str,
    max_size_bytes: int,
) -> tuple[str, int, str, list[dict], list[str]]:
    """
    Erzeugt aus source_path ein neues ZIP:
      - Pfade aus remove_paths werden weggelassen
      - add_files werden unter <add_prefix>/<filename> hinzugefügt
      - Wenn ein neuer Pfad gleich einem bestehenden ist, ersetzt die neue
        Datei die alte (replace mode)

    Returns: (final_path, total_size, sha256, all_files, executable_entries)
    Wirft HTTPException 400 wenn nach der Operation keine .exe/.msi/.bat/.cmd
    mehr im Archiv ist (kein Entry-Point möglich).
    """
    _ensure_upload_dir()

    add_prefix = (add_prefix or "").replace("\\", "/").strip("/")
    if add_prefix and (".." in add_prefix.split("/") or "" in add_prefix.split("/")):
        raise HTTPException(status_code=400, detail=f"Ungültiger Zielpfad: {add_prefix}")

    # Mappe target_path → UploadFile (eindeutig, letzter gewinnt bei Doppelt-Pick)
    new_paths: dict[str, UploadFile] = {}
    for f in add_files:
        raw = (f.filename or "").replace("\\", "/").lstrip("/")
        # Nur Basename verwenden — User stagert einzelne Files, kein Folder-Picker
        name = raw.split("/")[-1]
        if not name or ".." in name:
            raise HTTPException(status_code=400, detail=f"Ungültiger Dateiname: {raw}")
        target = f"{add_prefix}/{name}" if add_prefix else name
        new_paths[target] = f

    remove_set = {p.replace("\\", "/").strip("/") for p in remove_paths}

    tmp_path = os.path.join(UPLOAD_DIR, f"_tmp_{secrets.token_hex(8)}.zip")
    total_size = 0

    try:
        with zipfile.ZipFile(source_path, "r") as src, \
                zipfile.ZipFile(
                    tmp_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
                ) as dst:
            # 1. Bestehende Einträge übernehmen — außer entfernt oder ersetzt
            for info in src.infolist():
                if info.is_dir():
                    continue
                # Defense-in-depth: source-ZIP wurde ursprünglich von uns gebaut,
                # aber bei direktem Filesystem-Schreiben oder Bug könnten unsaubere
                # Pfade hier landen. Wir validieren nochmal genau wie save_folder_upload.
                src_path = info.filename.replace("\\", "/")
                if src_path.startswith("/"):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Source-ZIP enthält absoluten Pfad: {info.filename}",
                    )
                src_parts = src_path.split("/")
                if any(p in ("..", "") for p in src_parts):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Source-ZIP enthält ungültigen Pfad: {info.filename}",
                    )
                # Drive-letter-Präfix (z.B. "C:")
                if any(":" in p for p in src_parts):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Source-ZIP enthält ungültigen Pfad: {info.filename}",
                    )
                if info.filename in remove_set:
                    continue
                if info.filename in new_paths:
                    continue
                with src.open(info) as in_f, \
                        dst.open(info.filename, "w", force_zip64=True) as out_f:
                    while True:
                        chunk = in_f.read(1024 * 1024)
                        if not chunk:
                            break
                        total_size += len(chunk)
                        if total_size > max_size_bytes:
                            raise HTTPException(
                                status_code=413,
                                detail=(
                                    f"Paket würde zu groß werden "
                                    f"(max {max_size_bytes // 1024 // 1024} MB)"
                                ),
                            )
                        out_f.write(chunk)

            # 2. Neue Files anhängen
            for target, upload in new_paths.items():
                with dst.open(target, "w", force_zip64=True) as out_f:
                    while True:
                        chunk = await upload.read(1024 * 1024)
                        if not chunk:
                            break
                        total_size += len(chunk)
                        if total_size > max_size_bytes:
                            raise HTTPException(
                                status_code=413,
                                detail=(
                                    f"Paket würde zu groß werden "
                                    f"(max {max_size_bytes // 1024 // 1024} MB)"
                                ),
                            )
                        out_f.write(chunk)
    except HTTPException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise

    # SHA-256 berechnen
    h = hashlib.sha256()
    with open(tmp_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    sha256 = h.hexdigest()

    final_path = os.path.join(UPLOAD_DIR, f"{sha256}.zip")
    if os.path.exists(final_path):
        os.unlink(tmp_path)
    else:
        os.rename(tmp_path, final_path)

    all_files = extract_archive_filelist(final_path)
    executable_entries = sorted([
        f["path"] for f in all_files
        if os.path.splitext(f["path"])[1].lower() in ARCHIVE_ENTRY_EXTENSIONS
    ])

    if not executable_entries:
        raise HTTPException(
            status_code=400,
            detail=(
                "Nach der Bearbeitung ist keine .exe/.msi/.bat/.cmd mehr im Paket "
                "enthalten — kein Entry-Point möglich."
            ),
        )

    return final_path, total_size, sha256, all_files, executable_entries


def pick_default_entry(entries: list[str]) -> str | None:
    """
    Heuristik für den wahrscheinlichsten Installer in einer Eintragsliste:
      1. setup.exe / setup.msi (auf jeder Tiefe)
      2. install(er).exe / install(er).msi
      3. erste .exe (kürzester Pfad zuerst)
      4. erste .msi (kürzester Pfad zuerst)
      5. erster Eintrag überhaupt
    """
    if not entries:
        return None

    def basename_lower(p: str) -> str:
        return p.rsplit("/", 1)[-1].lower()

    by_depth = lambda p: (p.count("/"), p.lower())

    for p in sorted(entries, key=by_depth):
        if basename_lower(p) in ("setup.exe", "setup.msi"):
            return p
    for p in sorted(entries, key=by_depth):
        if basename_lower(p) in (
            "install.exe", "installer.exe", "install.msi", "installer.msi",
        ):
            return p
    exes = sorted(
        [p for p in entries if p.lower().endswith(".exe")], key=by_depth
    )
    if exes:
        return exes[0]
    msis = sorted(
        [p for p in entries if p.lower().endswith(".msi")], key=by_depth
    )
    if msis:
        return msis[0]
    return entries[0]


def get_storage_info() -> dict:
    """Free/used/total Bytes auf der UPLOAD_DIR-Partition (für UI-Anzeige).
    Verwendet shutil.disk_usage (portable, läuft auch unter Windows)."""
    import shutil
    _ensure_upload_dir()
    try:
        usage = shutil.disk_usage(UPLOAD_DIR)
        return {"total": usage.total, "used": usage.used, "free": usage.free}
    except OSError:
        return {"total": 0, "used": 0, "free": 0}
