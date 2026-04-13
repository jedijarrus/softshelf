#!/bin/bash
# Baut softshelf.exe und softshelf-setup.exe aus /app/client_src.
# Injects PROXY_URL + VERSION als _build_config.py, damit die EXEs
# die richtige Default-Proxy-URL eingebacken bekommen.
#
# ENV:
#   PROXY_URL  - z. B. http://softshelf.example.com:8765
#   VERSION    - z. B. 1.2.0
#   OUTPUT_DIR - z. B. /app/downloads

set -euo pipefail

: "${PROXY_URL:?PROXY_URL is required}"
: "${VERSION:?VERSION is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR is required}"

BUILD_DIR=/tmp/build-$$
mkdir -p "$BUILD_DIR"
cp -r /app/client_src/* "$BUILD_DIR/"
cd "$BUILD_DIR"

echo "=== Kiosk EXE Builder ==="
echo "PROXY_URL:   $PROXY_URL"
echo "VERSION:     $VERSION"
echo "OUTPUT_DIR:  $OUTPUT_DIR"
echo "BUILD_DIR:   $BUILD_DIR"
echo

# _build_config.py + _version.py via Python erzeugen, damit die Werte
# garantiert mit repr() escaped sind und kein Shell/Heredoc-Injection
# entstehen kann (PROXY_URL wird vom Admin aus dem Web-UI gesetzt).
PROXY_URL="$PROXY_URL" VERSION="$VERSION" python3 - <<'PYEOF'
import os
proxy_url = os.environ["PROXY_URL"]
version   = os.environ["VERSION"]
# Defensive Validierung: keine Steuerzeichen, keine Quotes
for ch in proxy_url + version:
    if ord(ch) < 32 or ch in ('"', "'", "\\", "\x7f"):
        raise SystemExit(f"Illegal character {ch!r} in PROXY_URL/VERSION")
with open("_build_config.py", "w", encoding="utf-8") as f:
    f.write("# Generated at build time — do not edit\n")
    f.write(f"DEFAULT_PROXY_URL = {proxy_url!r}\n")
    f.write(f"BUILD_VERSION = {version!r}\n")
with open("_version.py", "w", encoding="utf-8") as f:
    f.write(f"__version__ = {version!r}\n")
PYEOF

echo "=== Config injiziert ==="
cat _build_config.py
echo

# 1. softshelf.exe bauen — --specpath weggelassen damit relative Pfade intuitiv sind
echo "=== Baue softshelf.exe ==="
xvfb-run -a wine python -m PyInstaller \
    --onefile \
    --windowed \
    --name softshelf \
    --distpath dist \
    --workpath build-softshelf \
    --hidden-import win32ctypes.core \
    --hidden-import win32api \
    --noconfirm \
    main.py

if [ ! -f dist/softshelf.exe ]; then
    echo "FEHLER: softshelf.exe nicht gebaut"
    exit 1
fi

# 2. softshelf-setup.exe bauen (mit softshelf.exe eingebettet)
# --add-data mit absolutem Pfad (sicher unabhängig vom spec-Path-Handling)
echo
echo "=== Baue softshelf-setup.exe ==="
xvfb-run -a wine python -m PyInstaller \
    --onefile \
    --windowed \
    --name softshelf-setup \
    --distpath dist \
    --workpath build-setup \
    --add-data "$(pwd)/dist/softshelf.exe;." \
    --hidden-import win32ctypes.core \
    --hidden-import win32api \
    --noconfirm \
    setup.py

if [ ! -f dist/softshelf-setup.exe ]; then
    echo "FEHLER: softshelf-setup.exe nicht gebaut"
    exit 1
fi

# 3. Nach OUTPUT_DIR kopieren
mkdir -p "$OUTPUT_DIR"
cp dist/softshelf.exe "$OUTPUT_DIR/softshelf.exe"
cp dist/softshelf-setup.exe "$OUTPUT_DIR/softshelf-setup.exe"

echo
echo "=== Fertig ==="
ls -lh "$OUTPUT_DIR/"

# Aufräumen
cd /
rm -rf "$BUILD_DIR"
