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
    http://softshelf.example.com:8765/download/Softshelf-setup.exe

.NOTES
    Die Tactical-Agent-ID wird vom Installer selbst aus
    HKLM\SOFTWARE\TacticalRMM\agentid gelesen — kein -AgentId-Parameter
    noetig. Funktioniert auch ausserhalb von Tactical, solange der Tactical-
    Agent installiert ist.
#>
param(
    [Parameter(Mandatory=$true)] [string]$ProxyUrl,
    [Parameter(Mandatory=$true)] [string]$RegistrationSecret,
    [Parameter(Mandatory=$true)] [string]$SetupExeUrl
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

# TLS 1.2 erzwingen — sonst schlaegt Invoke-WebRequest auf aelteren Windows-
# Builds bei modernen Reverse-Proxies fehl.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Temp-Pfade. Der Error-Log-Name muss zum slug passen den setup.py schreibt
# (sonst sieht man bei einem Fehler nur "Unbekannter Fehler").
$SetupFile = [System.IO.Path]::GetFileName(([Uri]$SetupExeUrl).AbsolutePath)
if ([string]::IsNullOrWhiteSpace($SetupFile)) { $SetupFile = "setup.exe" }
$TempSetup = Join-Path $env:TEMP $SetupFile
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
Remove-Item $TempSetup -Force -ErrorAction SilentlyContinue
Remove-Item $ErrorLog  -Force -ErrorAction SilentlyContinue
$RegistrationSecret = $null
[System.GC]::Collect()

Write-Host "=== Deployment abgeschlossen ===" -ForegroundColor Cyan
Write-Host "Der Tray-Client startet beim naechsten Benutzer-Login automatisch." -ForegroundColor Green
