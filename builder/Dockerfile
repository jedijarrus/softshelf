# Wine-basierter Cross-Compile-Builder für Windows-EXEs.
#
# Basiert auf tobix/pywine, einem gewarteten Image mit:
#   - Debian + Wine 9.x (WineHQ-staging)
#   - Windows-Python 3.11 unter Wine
#   - Ready-to-use für PyInstaller-Cross-Builds
#
# Wir installieren darauf die Client-Dependencies (PyQt5, httpx, pystray …)
# unter dem Wine-Python und bauen so native Windows-EXEs.
#
# First-time build: ~3-5 min (nur pip installs + COPY).
# Cached builds: ~90 s.

FROM tobix/pywine:3.11

# Client-Dependencies + PyInstaller in das Wine-Python
RUN wine python -m pip install --upgrade pip \
 && wine python -m pip install --no-warn-script-location \
        pyinstaller==6.11.1 \
        httpx==0.27.2 \
        pystray==0.19.5 \
        Pillow==10.4.0 \
        pywebview==5.3.2 \
        pywin32==308

# Linux-seitige FastAPI für den HTTP-Trigger (auf 8766)
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --break-system-packages --no-cache-dir \
        fastapi==0.115.0 \
        "uvicorn[standard]==0.30.6"

# App-Code
WORKDIR /app
COPY builder/server.py /app/server.py
COPY builder/build.sh /app/build.sh

# Client-Source für die EXE-Generierung
COPY client /app/client_src

RUN chmod +x /app/build.sh \
 && mkdir -p /app/downloads

EXPOSE 8766

CMD ["python3", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8766"]
