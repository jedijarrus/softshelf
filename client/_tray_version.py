"""
Source-of-Truth für die Tray-Client-Version.

Bei jeder echten Aenderung an `client/`-Dateien (UI, Logic, Build-Config)
diesen Wert bumpen. Build-Flow (`_run_build_async` in `routes/admin.py`)
liest hier — _build_config.py wird beim Build mit diesem Wert befuellt
und ueber den Tray-Heartbeat als telemetrie reportet.

Versions-Schema: Semver, optional pre-release-Suffix (z.B. 2.4.0-rc1).
"""
TRAY_VERSION = "2.4.0"
