# Build the Argus Windows executable + installer.
#
#   1. Icon:          ensure dashboard/icon.png exists (Gemini) -> icon.ico (Pillow)
#   2. Freeze:        PyInstaller bundles Python + dashboard into dist/Argus.exe
#   3. Installer:     Inno Setup wraps Argus.exe into dist/installer/Argus-Setup.exe
#
# Run this from the project root (C:\workspace\argus) in PowerShell.

$ErrorActionPreference = "Stop"

Write-Host "==> 1/3 icon (png -> ico)"
py tools/make_icon.py
if ($LASTEXITCODE -ne 0) { Write-Warning "icon.ico step failed or Pillow missing; continuing without it" }

Write-Host "==> 2/3 freeze with PyInstaller"
py -m pip install --quiet pyinstaller
py -m PyInstaller --noconfirm --clean --onefile --name Argus `
    --add-data "dashboard;dashboard" `
    --icon "dashboard/icon.ico" `
    run.py

Write-Host "==> 3/3 Inno Setup installer"
$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    & $iscc packaging/installer.iss
} else {
    Write-Warning "Inno Setup not found — installer.iss is ready; install Inno Setup 6 and run: ISCC.exe packaging\installer.iss"
}

Write-Host "`nDone. Artifacts:"
Write-Host "  dist/Argus.exe                      (standalone exe)"
Write-Host "  dist/installer/Argus-Setup.exe      (installer, if Inno Setup ran)"
