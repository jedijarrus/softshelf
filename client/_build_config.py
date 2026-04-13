"""
Build-Time-Konfiguration — wird im Container-Builder überschrieben.

Beim normalen `pyinstaller` aus dem Repo heraus wird diese Datei
unverändert übernommen. Wenn der Wine-Builder den EXE baut, schreibt
er diese Datei neu mit den aktuellen Runtime-Settings aus der Proxy-DB
(siehe builder/build.sh).

DEFAULT_PROXY_URL ist die URL, die der Installer als Default benutzt
wenn --proxy-url nicht explizit übergeben wurde. Für lokale Builds
kann sie leer bleiben — dann muss --proxy-url angegeben werden.

PRODUCT_SLUG bestimmt Dateiname, Install-Pfad, Registry-Key und
Autostart-Name. Wird im Admin-UI unter Einstellungen gepflegt und
vom Builder beim nächsten Build hier eingebacken.
"""
DEFAULT_PROXY_URL = ""
BUILD_VERSION = "1.2.0"
PRODUCT_SLUG = "Softshelf"
