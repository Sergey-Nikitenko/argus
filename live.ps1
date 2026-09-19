# Argus — go live (DRY-RUN first). Run this in an ELEVATED PowerShell (Win+X -> Terminal (Admin)).
$ErrorActionPreference = 'Stop'

Write-Host "==> 1/2 enabling process-creation auditing (the eyes)" -ForegroundColor Cyan
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /get /subcategory:"Process Creation"

# Command-line capture is a SEPARATE toggle from the audit subcategory. Without it, 4688
# carries the image path but no CommandLine, so Argus's command-line heuristics (encoded PS,
# hidden window, -nop) can never fire. This key turns it on for NEW events.
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
  -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
Write-Host "    command-line capture: enabled" -ForegroundColor Green

Write-Host "`n==> 2/2 starting Argus watcher (DRY-RUN: flags but does NOT quarantine/kill)" -ForegroundColor Cyan
Write-Host "    stop anytime with Ctrl+C" -ForegroundColor Yellow
$env:ARGUS_DATA_DIR = 'C:\workspace\argus\data'
py C:\workspace\argus\run.py --watch --interval 30
