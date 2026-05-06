"""
Plugin-Host-Registry — generisches Plugin-System fuer Anwendungen die
Drop-in-DLL-Plugins haben (Notepad++, KeePass, vermutlich spaeter
Foobar2000, irfanview, etc).

Admin laedt eine Plugin-Datei hoch (.dll/.zip/.plgx), waehlt einen Host
aus dieser Registry, das Backend baut den passenden install/uninstall-
PowerShell zusammen. Kein Tactical-Round-Trip, kein winget.

Erweiterung: einfach neuen PluginHost-Eintrag in PLUGIN_HOSTS adden.
Die UI zieht die Liste via GET /admin/api/plugin-hosts.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PluginHost:
    id: str
    label: str
    process_names: tuple[str, ...]
    accepted_ext: tuple[str, ...]

    # PowerShell-Snippets — alle Snippets nutzen die Variablen
    #   $hostRoot       (Install-Verzeichnis der Anwendung)
    #   $pluginFolder   (Subdir-Name oder Filename-Stem, vom Admin gesetzt)
    #   $downloadPath   (lokaler Pfad der heruntergeladenen Plugin-Datei)
    # ps_resolve_root muss $hostRoot setzen (oder $null lassen wenn fehlt).
    # ps_install kopiert die Datei aus $downloadPath in den Plugin-Ordner.
    # ps_uninstall entfernt den Plugin-Ordner/-Datei.
    # ps_detect setzt $isInstalled = $true/$false.
    ps_resolve_root: str
    ps_install: str
    ps_uninstall: str
    ps_detect: str


_NPP = PluginHost(
    id="notepad++",
    label="Notepad++",
    process_names=("notepad++",),
    accepted_ext=(".zip", ".dll"),
    ps_resolve_root=r"""
$hostRoot = @('C:\Program Files\Notepad++','C:\Program Files (x86)\Notepad++') | ?{ Test-Path $_ } | Select-Object -First 1
""".strip(),
    ps_install=r"""
$target = Join-Path $hostRoot ('plugins\' + $pluginFolder)
New-Item -ItemType Directory -Force -Path $target | Out-Null
if ($downloadPath -like '*.zip') {
    # Defense-in-depth gegen ZIP-Slip: Pre-Validate dass alle Eintraege
    # relativ bleiben. PS 5.1 hat das Compression-Assembly nicht im
    # Default-Load — Add-Type laedt es. Wenn das fehlschlaegt, fallen
    # wir auf Expand-Archive's eigene Sicherung zurueck (PS 5.1+ ist
    # gegen ZIP-Slip seit 2019 gepatcht).
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $zip = [System.IO.Compression.ZipFile]::OpenRead($downloadPath)
        try {
            foreach ($e in $zip.Entries) {
                $p = $e.FullName
                if ($p -match '\.\.[\\/]' -or $p.StartsWith('/') -or $p.StartsWith('\') -or $p -match '^[A-Za-z]:') {
                    throw "ZIP-Eintrag mit verdaechtigem Pfad: $p"
                }
            }
        } finally {
            $zip.Dispose()
        }
    } catch [System.IO.FileLoadException], [System.IO.FileNotFoundException], [System.Management.Automation.RuntimeException] {
        if ($_.Exception.Message -like '*verdaechtigem Pfad*') { throw }
        _sfProgress "Hinweis: ZIP-Slip Pre-Check uebersprungen ($($_.Exception.Message))"
    }
    # Manche Notepad++-Plugin-ZIPs haben den Inhalt in einem Sub-Folder
    # (z.B. ZIP mit 'URLPlugin\URLPlugin.dll' statt nur 'URLPlugin.dll').
    # Wir entpacken in einen Staging-Ordner, suchen die DLL und kopieren
    # sie flach in den NPP-Plugin-Ordner.
    $stage = Join-Path $env:TEMP ('sf_npp_stage_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
        Expand-Archive -Path $downloadPath -DestinationPath $stage -Force
        $dlls = Get-ChildItem -Path $stage -Filter '*.dll' -Recurse -File
        if ($dlls.Count -eq 0) {
            throw "Keine .dll in der Plugin-ZIP gefunden."
        }
        foreach ($dll in $dlls) {
            Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $target $dll.Name) -Force
        }
        # Optionale Begleitdateien (.xml/.txt fuer manche NPP-Plugins) auch flach kopieren
        Get-ChildItem -Path $stage -Include '*.xml','*.txt','*.ini' -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $target $_.Name) -Force
        }
    } finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Copy-Item $downloadPath (Join-Path $target ($pluginFolder + '.dll')) -Force
}
""".strip(),
    ps_uninstall=r"""
$target = Join-Path $hostRoot ('plugins\' + $pluginFolder)
if (Test-Path $target) { Remove-Item $target -Recurse -Force }
""".strip(),
    ps_detect=r"""
$target = Join-Path $hostRoot ('plugins\' + $pluginFolder)
$isInstalled = Test-Path $target
""".strip(),
)


_KEEPASS = PluginHost(
    id="keepass",
    label="KeePass 2",
    process_names=("KeePass",),
    accepted_ext=(".plgx", ".dll"),
    ps_resolve_root=r"""
$hostRoot = @('C:\Program Files\KeePass Password Safe 2','C:\Program Files (x86)\KeePass Password Safe 2') | ?{ Test-Path $_ } | Select-Object -First 1
""".strip(),
    ps_install=r"""
$target = Join-Path $hostRoot 'Plugins'
New-Item -ItemType Directory -Force -Path $target | Out-Null
$ext = [IO.Path]::GetExtension($downloadPath)
Copy-Item $downloadPath (Join-Path $target ($pluginFolder + $ext)) -Force
""".strip(),
    ps_uninstall=r"""
$pluginsDir = Join-Path $hostRoot 'Plugins'
if (Test-Path $pluginsDir) {
    Get-ChildItem $pluginsDir -Filter ($pluginFolder + '.*') -ErrorAction SilentlyContinue | Remove-Item -Force
}
""".strip(),
    ps_detect=r"""
$pluginsDir = Join-Path $hostRoot 'Plugins'
if (Test-Path $pluginsDir) {
    $isInstalled = (Get-ChildItem $pluginsDir -Filter ($pluginFolder + '.*') -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0
} else {
    $isInstalled = $false
}
""".strip(),
)


PLUGIN_HOSTS: dict[str, PluginHost] = {
    _NPP.id: _NPP,
    _KEEPASS.id: _KEEPASS,
}


def get_host(host_id: str) -> PluginHost | None:
    return PLUGIN_HOSTS.get(host_id)


def list_hosts() -> list[dict]:
    """Listing fuer das Admin-UI — nur User-relevante Felder."""
    return [
        {
            "id": h.id,
            "label": h.label,
            "process_names": list(h.process_names),
            "accepted_ext": list(h.accepted_ext),
        }
        for h in PLUGIN_HOSTS.values()
    ]


def host_process_csv(host: PluginHost) -> str:
    """Komma-separierte Prozess-Liste fuer process_check."""
    return ",".join(host.process_names)
