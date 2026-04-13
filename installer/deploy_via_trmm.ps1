<#
.SYNOPSIS
    Softshelf - Deployment Script
    Laedt softshelf-setup.exe herunter und fuehrt es still aus.

.PARAMETER ProxyUrl
    URL des Proxy-Servers, z.B. http://softshelf.example.com:8765

.PARAMETER RegistrationSecret
    Shared Secret (REGISTRATION_SECRET aus Proxy .env). Wird NICHT gespeichert.

.PARAMETER SetupExeUrl
    Download-URL fuer softshelf-setup.exe

.PARAMETER AgentId
    Optional. Tactical RMM Agent-ID. Standard: {{agent.agent_id}}
    (wird von Tactical automatisch eingesetzt)
#>
param(
    [Parameter(Mandatory=$true)]  [string]$ProxyUrl,
    [Parameter(Mandatory=$true)]  [string]$RegistrationSecret,
    [Parameter(Mandatory=$true)]  [string]$SetupExeUrl,
    [Parameter(Mandatory=$false)] [string]$AgentId = "{{agent.agent_id}}"
)

$ErrorActionPreference = "Stop"
# Temp-Dateiname aus der Download-URL ableiten, damit das Script automatisch
# mit dem aktuellen product_slug mitgeht (kein Hardcode). Uri.AbsolutePath
# strippt den Query-String schon selber, deshalb kein -replace noetig (und
# ausserdem wuerde -replace innerhalb eines Methoden-Call-Parens vom PS-
# Parser als zweites GetFileName-Argument missverstanden werden).
$SetupFile = [System.IO.Path]::GetFileName(([Uri]$SetupExeUrl).AbsolutePath)
if ([string]::IsNullOrWhiteSpace($SetupFile)) { $SetupFile = "setup.exe" }
$TempSetup = Join-Path $env:TEMP $SetupFile
$ErrorLog  = Join-Path $env:TEMP "setup_error.txt"

Write-Host "=== Deployment ===" -ForegroundColor Cyan
Write-Host "Proxy:   $ProxyUrl"
Write-Host "AgentId: $AgentId"
Write-Host "Setup:   $SetupFile"
Write-Host ""

# Installer herunterladen
Write-Host "Lade $SetupFile herunter..."
Invoke-WebRequest -Uri $SetupExeUrl -OutFile $TempSetup -UseBasicParsing
Write-Host "Download abgeschlossen." -ForegroundColor Green

# Installation starten (laeuft als SYSTEM, schreibt in HKLM)
Write-Host "Starte Installation..."
$proc = Start-Process `
    -FilePath $TempSetup `
    -ArgumentList "--proxy-url `"$ProxyUrl`" --reg-secret `"$RegistrationSecret`" --agent-id `"$AgentId`"" `
    -Wait -PassThru

if ($proc.ExitCode -ne 0) {
    $errMsg = if (Test-Path $ErrorLog) { Get-Content $ErrorLog -Raw } else { "Unbekannter Fehler" }
    Write-Host "Installation fehlgeschlagen (ExitCode $($proc.ExitCode)):" -ForegroundColor Red
    Write-Host $errMsg -ForegroundColor Red
    exit 1
}

# Aufraumen
Remove-Item $TempSetup -Force -ErrorAction SilentlyContinue
Remove-Item $ErrorLog  -Force -ErrorAction SilentlyContinue
$RegistrationSecret = $null
[System.GC]::Collect()

Write-Host "=== Deployment abgeschlossen ===" -ForegroundColor Cyan
Write-Host "Der Tray-Client startet beim naechsten Benutzer-Login automatisch." -ForegroundColor Green
