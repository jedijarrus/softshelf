<#
.SYNOPSIS
    Softshelf - Deployment Script
    Laedt softshelf-setup.exe vom Proxy herunter und fuehrt sie still aus.

.PARAMETER ProxyUrl
    Public-URL des Softshelf-Proxy, z.B. http://softshelf.example.com:8765

.PARAMETER RegistrationSecret
    Shared Secret aus den Admin-Einstellungen. Wird nach dem Run aus dem
    Variable-Scope geloescht und nicht persistiert.

.PARAMETER SetupExeUrl
    Download-URL der Setup-EXE, z.B.
    https://softshelf.example.com/download/Softshelf-setup.exe
    HTTPS dringend empfohlen — die EXE laeuft als SYSTEM.

.PARAMETER SetupSha256
    Erwarteter SHA256 der Setup-EXE (aus Admin-UI -> Einstellungen ->
    Build-Status). Wenn nicht angegeben, holt das Script den Soll-Hash
    vom Proxy-Endpoint /api/v1/client-version-check. Der Download wird
    vor dem Start gegen den Hash geprueft — ohne verifizierbaren Hash
    laeuft die EXE NICHT an.

.NOTES
    Die Tactical-Agent-ID wird vom Installer selbst aus
    HKLM\SOFTWARE\TacticalRMM\agentid gelesen — kein -AgentId-Parameter
    noetig. Funktioniert auch ausserhalb von Tactical, solange der Tactical-
    Agent installiert ist.
#>
param(
    [Parameter(Mandatory=$true)] [string]$ProxyUrl,
    [Parameter(Mandatory=$true)] [string]$RegistrationSecret,
    [Parameter(Mandatory=$true)] [string]$SetupExeUrl,
    [Parameter(Mandatory=$false)] [string]$SetupSha256 = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

# TLS 1.2 erzwingen — sonst schlaegt Invoke-WebRequest auf aelteren Windows-
# Builds bei modernen Reverse-Proxies fehl.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Temp-Pfade. Der Error-Log-Name muss zum slug passen den setup.py schreibt
# (sonst sieht man bei einem Fehler nur "Unbekannter Fehler").
# Download in ein frisches, zufaellig benanntes Unterverzeichnis statt
# direkt nach C:\Windows\Temp — der vorhersagbare Pfad war ein
# Binary-Planting/TOCTOU-Fenster fuer eine EXE die als SYSTEM laeuft.
$SetupFile = [System.IO.Path]::GetFileName(([Uri]$SetupExeUrl).AbsolutePath)
if ([string]::IsNullOrWhiteSpace($SetupFile)) { $SetupFile = "setup.exe" }
$TempDir   = Join-Path $env:TEMP ("sf-deploy-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
$TempSetup = Join-Path $TempDir $SetupFile
$Slug      = [System.IO.Path]::GetFileNameWithoutExtension($SetupFile) -replace '-setup$',''
$ErrorLog  = Join-Path $env:TEMP ("{0}_setup_error.txt" -f $Slug.ToLower())

Write-Host "=== Deployment ===" -ForegroundColor Cyan
Write-Host "Proxy: $ProxyUrl"
Write-Host "Setup: $SetupFile"
Write-Host ""

# Installer herunterladen
Write-Host "Lade $SetupFile herunter..."
try {
    Invoke-WebRequest -Uri $SetupExeUrl -OutFile $TempSetup -UseBasicParsing
} catch {
    Write-Host "Download fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
Write-Host "Download abgeschlossen." -ForegroundColor Green

# SHA256-Verifikation VOR dem Start — die EXE laeuft als SYSTEM.
# Soll-Hash: Parameter > Proxy-API (client-version-check). Ohne
# verifizierbaren Hash wird abgebrochen.
$expectedSha = $SetupSha256.Trim().ToLower()
if (-not $expectedSha) {
    try {
        $vc = Invoke-RestMethod -Uri ("{0}/api/v1/client-version-check" -f $ProxyUrl.TrimEnd('/')) -UseBasicParsing
        if ($vc.setup_sha) { $expectedSha = ([string]$vc.setup_sha).Trim().ToLower() }
    } catch {
        Write-Host "Soll-Hash vom Proxy nicht abrufbar: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
if (-not $expectedSha) {
    Write-Host "Kein SHA256 verfuegbar (weder -SetupSha256 noch Proxy-API) — Abbruch." -ForegroundColor Red
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 3
}
$actualSha = (Get-FileHash -Path $TempSetup -Algorithm SHA256).Hash.ToLower()
if ($actualSha -ne $expectedSha) {
    Write-Host "SHA256-Mismatch! erwartet=$expectedSha erhalten=$actualSha — Abbruch." -ForegroundColor Red
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 3
}
Write-Host "SHA256 verifiziert." -ForegroundColor Green

# Installation starten. -NoNewWindow ist Pflicht unter SYSTEM/Session 0.
# Args werden als ARRAY uebergeben, damit PowerShell nichts re-quoten muss.
Write-Host "Starte Installation..."
$proc = Start-Process `
    -FilePath $TempSetup `
    -ArgumentList @("--proxy-url", $ProxyUrl, "--reg-secret", $RegistrationSecret) `
    -Wait -PassThru -NoNewWindow

if ($proc.ExitCode -ne 0) {
    $errMsg = if (Test-Path $ErrorLog) { Get-Content $ErrorLog -Raw } else { "Unbekannter Fehler" }
    Write-Host "Installation fehlgeschlagen (ExitCode $($proc.ExitCode)):" -ForegroundColor Red
    Write-Host $errMsg -ForegroundColor Red
    exit 1
}

# Aufraeumen
Remove-Item $TempDir  -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $ErrorLog -Force -ErrorAction SilentlyContinue
$RegistrationSecret = $null
[System.GC]::Collect()

Write-Host "=== Deployment abgeschlossen ===" -ForegroundColor Cyan
Write-Host "Der Tray-Client startet beim naechsten Benutzer-Login automatisch." -ForegroundColor Green
