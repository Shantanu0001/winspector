# install_service.ps1
# Installs WinSpector as a Windows service with auto-restart on failure.
# Must be run from an elevated (Administrator) PowerShell.

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe  = Join-Path $ProjectDir ".venv\Scripts\python.exe"
$ServiceScript = Join-Path $ProjectDir "winspector_service.py"

Write-Host "Installing WinSpector service..." -ForegroundColor Cyan

# Install the service
& $PythonExe $ServiceScript install

# Configure failure recovery: restart after 60s, up to 3 times
sc.exe failure WinSpector reset= 86400 actions= restart/60000/restart/60000/restart/60000

# Set the service description
sc.exe description WinSpector "WinSpector EDR Monitor - process, driver and event telemetry"

Write-Host "Service installed. Starting..." -ForegroundColor Cyan
& $PythonExe $ServiceScript start

Write-Host "Done. Check status with: sc query WinSpector" -ForegroundColor Green
