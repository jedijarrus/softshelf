#!/bin/bash
# Baut den Tray-Client und den Installer aus /app/client_src.
# Dateinamen, Install-Pfad, Registry-Key und Autostart-Name werden aus
# PRODUCT_SLUG abgeleitet (CI-Branding). PROXY_URL + VERSION werden in
# _build_config.py eingebacken, damit die fertige EXE die richtige
# Default-Proxy-URL kennt.
#
# ENV:
#   PROXY_URL     - z. B. http://softshelf.example.com:8765
#   VERSION       - z. B. 1.2.0
#   PRODUCT_SLUG  - z. B. Softshelf, AcmeSoft, ...  [default: Softshelf]
#   OUTPUT_DIR    - z. B. /app/downloads

set -euo pipefail

: "${PROXY_URL:?PROXY_URL is required}"
: "${VERSION:?VERSION is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR is required}"
PRODUCT_SLUG="${PRODUCT_SLUG:-Softshelf}"

# Defense-in-depth: Slug wird in Dateinamen, Shell-Commands und Python-Code
# eingebettet. Der Proxy validiert schon beim Settings-Save, wir validieren
# hier nochmal, falls jemand den Builder direkt anspricht.
if ! [[ "$PRODUCT_SLUG" =~ ^[A-Za-z][A-Za-z0-9_-]{0,30}$ ]]; then
    echo "FEHLER: PRODUCT_SLUG '$PRODUCT_SLUG' ist ungueltig"
    echo "Erwartet: ^[A-Za-z][A-Za-z0-9_-]{0,30}\$"
    exit 1
fi

BUILD_DIR=/tmp/build-$$
mkdir -p "$BUILD_DIR"
cp -r /app/client_src/* "$BUILD_DIR/"
cd "$BUILD_DIR"

echo "=== EXE Builder ==="
echo "PRODUCT_SLUG: $PRODUCT_SLUG"
echo "PROXY_URL:    $PROXY_URL"
echo "VERSION:      $VERSION"
echo "OUTPUT_DIR:   $OUTPUT_DIR"
echo "BUILD_DIR:    $BUILD_DIR"
echo

# _build_config.py + _version.py via Python erzeugen, damit die Werte
# garantiert mit repr() escaped sind und kein Shell/Heredoc-Injection
# entstehen kann (PROXY_URL und PRODUCT_SLUG kommen aus dem Admin-UI).
PROXY_URL="$PROXY_URL" VERSION="$VERSION" PRODUCT_SLUG="$PRODUCT_SLUG" python3 - <<'PYEOF'
import os
import re

proxy_url = os.environ["PROXY_URL"]
version   = os.environ["VERSION"]
slug      = os.environ["PRODUCT_SLUG"]

# Defensive validation: keine Steuerzeichen, keine Quotes, keine Backslashes
# fuer proxy_url/version (landen in Python-Strings + PowerShell-Commands)
for ch in proxy_url + version:
    if ord(ch) < 32 or ch in ('"', "'", "\\", "\x7f"):
        raise SystemExit(f"Illegal character {ch!r} in PROXY_URL/VERSION")

# Slug: sehr strikt, muss die gleiche Regex wie der Proxy-Validator passen
if not re.match(r"^[A-Za-z][A-Za-z0-9_-]{0,30}$", slug):
    raise SystemExit(f"Illegal PRODUCT_SLUG: {slug!r}")

with open("_build_config.py", "w", encoding="utf-8") as f:
    f.write("# Generated at build time - do not edit\n")
    f.write(f"DEFAULT_PROXY_URL = {proxy_url!r}\n")
    f.write(f"BUILD_VERSION = {version!r}\n")
    f.write(f"PRODUCT_SLUG = {slug!r}\n")
with open("_version.py", "w", encoding="utf-8") as f:
    f.write(f"__version__ = {version!r}\n")
PYEOF

echo "=== Config injiziert ==="
cat _build_config.py
echo

# 1. Tray-Client bauen
echo "=== Baue ${PRODUCT_SLUG}.exe ==="
xvfb-run -a wine python -m PyInstaller \
    --onefile \
    --windowed \
    --name "${PRODUCT_SLUG}" \
    --distpath dist \
    --workpath "build-${PRODUCT_SLUG}" \
    --hidden-import win32ctypes.core \
    --hidden-import win32api \
    --noconfirm \
    main.py

if [ ! -f "dist/${PRODUCT_SLUG}.exe" ]; then
    echo "FEHLER: ${PRODUCT_SLUG}.exe nicht gebaut"
    exit 1
fi

# 2. Installer bauen (mit Tray-Client eingebettet)
echo
echo "=== Baue ${PRODUCT_SLUG}-setup.exe ==="
xvfb-run -a wine python -m PyInstaller \
    --onefile \
    --windowed \
    --name "${PRODUCT_SLUG}-setup" \
    --distpath dist \
    --workpath "build-${PRODUCT_SLUG}-setup" \
    --add-data "$(pwd)/dist/${PRODUCT_SLUG}.exe;." \
    --hidden-import win32ctypes.core \
    --hidden-import win32api \
    --noconfirm \
    setup.py

if [ ! -f "dist/${PRODUCT_SLUG}-setup.exe" ]; then
    echo "FEHLER: ${PRODUCT_SLUG}-setup.exe nicht gebaut"
    exit 1
fi

# 3. Alte EXEs aus OUTPUT_DIR entfernen (nur *.exe, keine anderen Files),
#    damit nach einem Slug-Wechsel keine Leichen liegen bleiben. Die
#    Download-Endpoints im Proxy pruefen sowieso gegen den aktuellen Slug,
#    aber ein sauberes Verzeichnis ist konfusionsfreier.
mkdir -p "$OUTPUT_DIR"
find "$OUTPUT_DIR" -maxdepth 1 -type f -name "*.exe" -delete || true

# 4. Nach OUTPUT_DIR kopieren
cp "dist/${PRODUCT_SLUG}.exe"       "${OUTPUT_DIR}/${PRODUCT_SLUG}.exe"
cp "dist/${PRODUCT_SLUG}-setup.exe" "${OUTPUT_DIR}/${PRODUCT_SLUG}-setup.exe"

echo
echo "=== Fertig ==="
ls -lh "$OUTPUT_DIR/"

# Aufraeumen
cd /
rm -rf "$BUILD_DIR"
