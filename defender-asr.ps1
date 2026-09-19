<#
  Defender Attack Surface Reduction (ASR) — the PREVENTION layer for Argus.

  ASR rules enforce at the OS level and can BLOCK a process *before* it executes,
  which no userspace Python watchdog can do. Argus detects; ASR prevents. Together
  they close the "payload delivered before we reacted" gap.

  Usage (ELEVATED / admin PowerShell):
      powershell -ExecutionPolicy Bypass -File defender-asr.ps1          # BLOCK mode
      powershell -ExecutionPolicy Bypass -File defender-asr.ps1 audit    # log only, no block

  Try AUDIT first on a real machine: it logs what WOULD have been blocked so you can
  confirm nothing legitimate trips, then flip to BLOCK.

  Rule IDs:
    * 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC  Block execution of potentially obfuscated scripts
        -> kills  powershell.exe -enc ... / -w hidden / -exec bypass  (our whole demo)
    * D1E49AAC-8F56-4280-B9BA-993A6D77406C  Block process creations from PSExec and WMI (lateral movement)
    * D3E037E1-3EB8-44C8-A917-57927947596D  Block JS/VBS from launching downloaded executable content
#>

param(
    [ValidateSet('block', 'audit')]
    [string]$Mode = 'block'
)

# 1 = Block, 2 = Audit only
$action = if ($Mode -eq 'audit') { 2 } else { 1 }

$rules = [ordered]@{
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block obfuscated scripts (encoded PowerShell)'
    'D1E49AAC-8F56-4280-B9BA-993A6D77406C' = 'Block PSExec/WMI process creation (lateral movement)'
    'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JS/VBS launching downloaded content'
}

foreach ($id in $rules.Keys) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $action
}

$modeName = if ($action -eq 1) { 'BLOCK' } else { 'AUDIT-ONLY' }
Write-Host "ASR rules set to $modeName :"
foreach ($id in $rules.Keys) {
    Write-Host ("  {0}  ->  {1}" -f $id, $rules[$id])
}
Write-Host ""
Write-Host "Current ASR rule IDs configured:"
(Get-MpPreference).AttackSurfaceReductionRules_Ids
