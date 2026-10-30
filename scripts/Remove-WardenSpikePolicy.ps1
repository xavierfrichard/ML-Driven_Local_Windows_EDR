#Requires -RunAsAdministrator
<#
================================================================================
 Remove-WardenSpikePolicy.ps1  -  Warden Phase 0 Spike
================================================================================

 Rolls the VM back to a clean state by removing the App Control policies that
 Deploy-WardenSpikePolicy.ps1 deployed. It:

   1. Lists active policies via  CiTool --list-policies --json
   2. Selects the spike's policies: the fixed spike PolicyIDs
      (base {77EEF7EE-839E-49F6-ADF1-3BD853A234B1}, supplemental
      {591A5539-3983-4C77-92B7-583045489C23}) plus any policy whose FriendlyName
      contains "Warden Spike" (bases left by older runs had random GUIDs)
   3. Removes each with  CiTool --remove-policy "{PolicyID}"
      - SUPPLEMENTAL policies are removed BEFORE base policies (a base cannot be
        removed while a supplemental still expands it).

 The Warden service's own allow-list supplemental
 ({7A4D1C0A-5B2E-4F6A-9C3D-000000000001}, "Warden Allowlist Supplemental") is
 NOT a spike policy and is not removed by name. If it (or any other
 supplemental) still expands a spike base, the script stops and names it; pass
 -IncludeDependentSupplementals to remove those too.

 SAFETY
 ------
  * Refuses to run without -IUnderstandVmOnly (VM-only guard).
  * Supports -WhatIf: each removal is gated by ShouldProcess.
  * Unsigned multiple-policy removal is rebootless on Windows 11 24H2+ (earlier
    builds finish dropping the policy on the next refresh/reboot).

 ------------------------------------------------------------------------------
 VM-ONLY: run in an elevated PowerShell inside the isolated Windows 11 VM.
   .\scripts\Remove-WardenSpikePolicy.ps1 -IUnderstandVmOnly
 ------------------------------------------------------------------------------
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Mandatory acknowledgement that this runs only in a throwaway VM.
    [switch]$IUnderstandVmOnly,

    # Substring matched (case-insensitive) against a policy's FriendlyName.
    [string]$NamePrefix = 'Warden Spike',

    # Also remove supplementals that are not the spike's but expand a spike base
    # (for example the Warden service's allow-list supplemental).
    [switch]$IncludeDependentSupplementals
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SpikePolicyIds = @('{77EEF7EE-839E-49F6-ADF1-3BD853A234B1}', '{591A5539-3983-4C77-92B7-583045489C23}')

function Write-Step { param([string]$m) Write-Host "[warden] $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "[warden] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "[warden] $m" -ForegroundColor Yellow }
function Write-Err  { param([string]$m) Write-Host "[warden] $m" -ForegroundColor Red }

if (-not $IUnderstandVmOnly) {
    Write-Err "REFUSING TO RUN. This modifies Windows Application Control policy state."
    Write-Err "Run it ONLY inside an isolated Windows 11 VM. Re-run with:  -IUnderstandVmOnly"
    throw "Refused: -IUnderstandVmOnly was not supplied."
}

# Best-effort VM heuristic (warn-only). -IUnderstandVmOnly is the hard interlock;
# this simply makes an accidental run on real hardware noisy.
function Test-IsVirtualMachine {
    try {
        $cs  = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hay = "$($cs.Manufacturer) $($cs.Model)"
        return ($hay -match 'Virtual|VMware|Hyper-V|VirtualBox|KVM|QEMU|Xen|Parallels|Bochs|innotek')
    } catch {
        return $true
    }
}
if (-not (Test-IsVirtualMachine)) {
    Write-Warn "This machine does NOT look like a virtual machine. This removes WDAC policy"
    Write-Warn "state on REAL hardware. If that is not what you intend, STOP NOW (Ctrl+C)."
}

# Pinned System32 path, not a PATH lookup.
$CiTool = Join-Path ([Environment]::SystemDirectory) 'CiTool.exe'
if (-not (Test-Path -LiteralPath $CiTool)) {
    throw "CiTool.exe not found at $CiTool. This spike requires Windows 11 22H2+ (or Server 2025)."
}

# --- Enumerate active policies ------------------------------------------------
Write-Step "Listing policies: CiTool --list-policies --json"
$raw = & $CiTool --list-policies --json 2>&1
if ($LASTEXITCODE -ne 0) { throw "CiTool --list-policies failed (exit $LASTEXITCODE): $raw" }

# Safe property accessor: ConvertFrom-Json objects vary field-to-field, and
# Set-StrictMode throws on missing properties, so read defensively.
function Get-Prop {
    param($Obj, [string]$Name, $Default = $null)
    $prop = $Obj.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $Default
}

function ConvertTo-GuidKey {
    param([string]$Guid)
    return ([string]$Guid).Trim().Trim('{', '}').ToLowerInvariant()
}

$parsed = $raw | Out-String | ConvertFrom-Json
$policies = @(Get-Prop $parsed 'Policies' @())
if ($policies.Count -eq 0) {
    Write-Warn "No policies reported by CiTool. Nothing to do."
    return
}

$spikeKeys = @($SpikePolicyIds | ForEach-Object { ConvertTo-GuidKey $_ })

# The spike's policies: by fixed PolicyID, or by the "Warden Spike" friendly name.
$spike = @($policies | Where-Object {
    $friendly = Get-Prop $_ 'FriendlyName' ''
    $key = ConvertTo-GuidKey (Get-Prop $_ 'PolicyID' '')
    -not (Get-Prop $_ 'IsSystemPolicy' $false) -and
        (($spikeKeys -contains $key) -or ($friendly -and $friendly -like "*$NamePrefix*"))
})

if ($spike.Count -eq 0) {
    Write-Ok "No Warden spike policies are active. Machine is already clean."
    return
}

# Classify: a supplemental has BasePolicyID != its own PolicyID.
function Test-IsSupplemental {
    param($P)
    $base = ConvertTo-GuidKey (Get-Prop $P 'BasePolicyID' '')
    $self = ConvertTo-GuidKey (Get-Prop $P 'PolicyID' '')
    return ($base -and $self -and ($base -ne $self))
}

# Other supplementals that still expand a spike base would block its removal.
$spikeSelfKeys = @($spike | ForEach-Object { ConvertTo-GuidKey (Get-Prop $_ 'PolicyID' '') })
$spikeBaseKeys = @($spike | Where-Object { -not (Test-IsSupplemental $_) } | ForEach-Object { ConvertTo-GuidKey (Get-Prop $_ 'PolicyID' '') })
$dependents = @($policies | Where-Object {
    (Test-IsSupplemental $_) -and
        ($spikeSelfKeys -notcontains (ConvertTo-GuidKey (Get-Prop $_ 'PolicyID' ''))) -and
        ($spikeBaseKeys -contains (ConvertTo-GuidKey (Get-Prop $_ 'BasePolicyID' '')))
})
if ($dependents.Count -gt 0) {
    foreach ($d in $dependents) {
        Write-Warn "Supplemental $(Get-Prop $d 'PolicyID') ($(Get-Prop $d 'FriendlyName' '')) expands a spike base."
    }
    if (-not $IncludeDependentSupplementals) {
        Write-Err "These are not spike policies (one may be the Warden service's allow-list supplemental)."
        throw "Refused: re-run with -IncludeDependentSupplementals to remove them as well, or remove them first."
    }
}

# Order: supplementals first (a base cannot be removed while supplemented), then bases.
$supplementals = @(@($dependents) + @($spike | Where-Object { Test-IsSupplemental $_ }))
$bases         = @($spike | Where-Object { -not (Test-IsSupplemental $_) })
$ordered = @($supplementals + $bases)

Write-Step "Found $($ordered.Count) policy(ies) to remove ($($supplementals.Count) supplemental, $($bases.Count) base):"
foreach ($p in $ordered) {
    $kind = if (Test-IsSupplemental $p) { 'supplemental' } else { 'base' }
    Write-Host "    [$kind] $(Get-Prop $p 'PolicyID')  $(Get-Prop $p 'FriendlyName' '')" -ForegroundColor DarkGray
}

# --- Remove each --------------------------------------------------------------
$removed = 0
foreach ($p in $ordered) {
    $guid = Get-Prop $p 'PolicyID'
    $fname = Get-Prop $p 'FriendlyName' ''
    if ($PSCmdlet.ShouldProcess($guid, "CiTool --remove-policy ($fname)")) {
        Write-Step "Removing $guid : CiTool --remove-policy `"$guid`""
        $out = & $CiTool --remove-policy "$guid" 2>&1
        Write-Host ($out | Out-String)
        if ($LASTEXITCODE -ne 0) {
            Write-Err "CiTool --remove-policy failed (exit $LASTEXITCODE) for $guid"
            throw "Removal failed for $guid. Remaining policies were not touched."
        }
        Write-Ok "Removed $guid"
        $removed++
    } else {
        Write-Warn "[WhatIf] Would remove $guid ($fname)"
    }
}

Write-Host ''
Write-Ok "Done. Removed $removed policy(ies)."
Write-Host "  Verify:  CiTool --list-policies --json" -ForegroundColor DarkGray
Write-Warn "On Windows 11 pre-24H2, a reboot may be needed for removal to fully take effect."
