# uninstall_service.ps1
# Stops and removes the WinSpector Windows service.
# Must be run from an elevated (Administrator) PowerShell.

$ErrorActionPreference = "SilentlyContinue"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe  = Join-Path $ProjectDir ".venv\Scripts\python.exe"
$ServiceScript = Join-Path $ProjectDir "winspector_service.py"

Write-Host "Stopping WinSpector service..." -ForegroundColor Cyan
& $PythonExe $ServiceScript stop

Start-Sleep 3

Write-Host "Removing WinSpector service..." -ForegroundColor Cyan
& $PythonExe $ServiceScript remove

Write-Host "Done." -ForegroundColor Green
