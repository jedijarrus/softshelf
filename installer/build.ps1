<#
.SYNOPSIS
    Baut softshelf.exe und softshelf-setup.exe mit PyInstaller.
    Einmal auf dem Build-PC ausfuehren, dann beide EXEs auf den internen Server kopieren.
#>

$RootDir   = Split-Path $PSScriptRoot -Parent
$ClientDir = Join-Path $RootDir "client"
$DistDir   = Join-Path $RootDir "dist"

Set-Location $ClientDir

Write-Host "=== Kiosk Build ===" -ForegroundColor Cyan
Write-Host "Client:  $ClientDir"
Write-Host "Output:  $DistDir"
Write-Host ""

# Abhaengigkeiten
Write-Host "Installiere Abhaengigkeiten..."
pip install -r requirements.txt --quiet
pip install pyinstaller --quiet

# ── 1. softshelf.exe (Tray-App) ───────────────────────────────────────────────────
Write-Host "Baue softshelf.exe..."
pyinstaller `
    --onefile `
    --windowed `
    --name softshelf `
    --distpath $DistDir `
    --hidden-import win32ctypes.core `
    --hidden-import win32api `
    --noconfirm `
    main.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "FEHLER: softshelf.exe Build fehlgeschlagen." -ForegroundColor Red
    exit 1
}
Write-Host "softshelf.exe OK" -ForegroundColor Green

# ── 2. softshelf-setup.exe (Installer, softshelf.exe eingebettet) ────────────────────
Write-Host "Baue softshelf-setup.exe..."
$KioskExe = Join-Path $DistDir "softshelf.exe"

pyinstaller `
    --onefile `
    --windowed `
    --name softshelf-setup `
    --distpath $DistDir `
    "--add-data=$KioskExe;." `
    --hidden-import win32ctypes.core `
    --hidden-import win32api `
    --noconfirm `
    setup.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "FEHLER: softshelf-setup.exe Build fehlgeschlagen." -ForegroundColor Red
    exit 1
}
Write-Host "softshelf-setup.exe OK" -ForegroundColor Green

# ── Zusammenfassung ───────────────────────────────────────────────────────────
$KioskSize = [math]::Round((Get-Item (Join-Path $DistDir "softshelf.exe")).Length / 1MB, 1)
$SetupSize = [math]::Round((Get-Item (Join-Path $DistDir "softshelf-setup.exe")).Length / 1MB, 1)

Write-Host ""
Write-Host "=== Build erfolgreich ===" -ForegroundColor Green
Write-Host "  dist\softshelf.exe         ($KioskSize MB)  – Tray-App (nur fuer manuelle Tests)"
Write-Host "  dist\softshelf-setup.exe   ($SetupSize MB)  – Installer (enthaelt softshelf.exe)"
Write-Host ""
Write-Host "Naechste Schritte:" -ForegroundColor Yellow
Write-Host "  1. softshelf-setup.exe auf internen File-Server kopieren"
Write-Host "  2. In Tactical RMM: deploy_via_trmm.ps1 als Script anlegen"
Write-Host "     Parameter:"
Write-Host "       -ProxyUrl           https://softshelf.example.com:8765"
Write-Host "       -RegistrationSecret <Wert aus Proxy .env: REGISTRATION_SECRET>"
Write-Host "       -AgentId            {{agent.agent_id}}"
Write-Host "       -SetupExeUrl        https://intern/softshelf-setup.exe"
