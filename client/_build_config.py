"""
Build-Time-Konfiguration — wird im Container-Builder überschrieben.

Beim normalen `pyinstaller` aus dem Repo heraus wird diese Datei
unverändert übernommen. Wenn der Wine-Builder den EXE baut, schreibt
er diese Datei neu mit den aktuellen Runtime-Settings aus der Proxy-DB
(siehe builder/build.sh).

DEFAULT_PROXY_URL ist die URL, die der Installer als Default benutzt
wenn --proxy-url nicht explizit übergeben wurde. Für lokale Builds
kann sie leer bleiben — dann muss --proxy-url angegeben werden.
"""
DEFAULT_PROXY_URL = ""
BUILD_VERSION = "1.2.0"
