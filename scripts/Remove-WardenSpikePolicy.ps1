#Requires -RunAsAdministrator
<#
================================================================================
 Remove-WardenSpikePolicy.ps1  -  Warden Phase 0 Spike
================================================================================

 Rolls the VM back to a clean state by removing every Warden App Control policy
 that Deploy-WardenSpikePolicy.ps1 deployed. It:

   1. Lists active policies via  CiTool --list-policies --json
   2. Selects the ones whose FriendlyName / Id begins with "Warden"
   3. Removes each with  CiTool --remove-policy "{PolicyID}"
      - SUPPLEMENTAL policies are removed BEFORE base policies (a base cannot be
        removed while a supplemental still expands it).

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

    # Substring matched (case-insensitive) against a policy's FriendlyName/Id.
    [string]$NamePrefix = 'Warden'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

if (-not (Get-Command CiTool.exe -ErrorAction SilentlyContinue) -and
    -not (Test-Path "$env:WINDIR\System32\CiTool.exe")) {
    throw "CiTool.exe not found. This spike requires Windows 11 22H2+ (or Server 2025)."
}

# --- Enumerate active policies ------------------------------------------------
Write-Step "Listing policies: CiTool --list-policies --json"
$raw = & CiTool.exe --list-policies --json 2>&1
if ($LASTEXITCODE -ne 0) { throw "CiTool --list-policies failed (exit $LASTEXITCODE): $raw" }

# Safe property accessor: ConvertFrom-Json objects vary field-to-field, and
# Set-StrictMode throws on missing properties, so read defensively.
function Get-Prop {
    param($Obj, [string]$Name, $Default = $null)
    $prop = $Obj.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $Default
}

$parsed = $raw | Out-String | ConvertFrom-Json
$policies = Get-Prop $parsed 'Policies'
if (-not $policies) {
    Write-Warn "No policies reported by CiTool. Nothing to do."
    return
}

# Each policy exposes PolicyID, FriendlyName, and IsSystemPolicy among others.
$warden = @($policies | Where-Object {
    $friendly = Get-Prop $_ 'FriendlyName' ''
    -not (Get-Prop $_ 'IsSystemPolicy' $false) -and $friendly -and ($friendly -like "*$NamePrefix*")
})

if ($warden.Count -eq 0) {
    Write-Ok "No policies matching '$NamePrefix' are active. Machine is already clean."
    return
}

# Classify: a supplemental has BasePolicyID != its own PolicyID.
function Test-IsSupplemental {
    param($P)
    $base = Get-Prop $P 'BasePolicyID'
    $self = Get-Prop $P 'PolicyID'
    return ($base -and $self -and ($base -ne $self))
}

# Order: supplementals first (a base cannot be removed while supplemented), then bases.
$supplementals = @($warden | Where-Object { Test-IsSupplemental $_ })
$bases         = @($warden | Where-Object { -not (Test-IsSupplemental $_) })
$ordered = @($supplementals + $bases)

Write-Step "Found $($warden.Count) Warden policy(ies) to remove ($($supplementals.Count) supplemental, $($bases.Count) base):"
foreach ($p in $ordered) {
    $kind = if (Test-IsSupplemental $p) { 'supplemental' } else { 'base' }
    Write-Host "    [$kind] $(Get-Prop $p 'PolicyID')  $(Get-Prop $p 'FriendlyName')" -ForegroundColor DarkGray
}

# --- Remove each --------------------------------------------------------------
$removed = 0
foreach ($p in $ordered) {
    $guid = Get-Prop $p 'PolicyID'
    $fname = Get-Prop $p 'FriendlyName' ''
    if ($PSCmdlet.ShouldProcess($guid, "CiTool --remove-policy ($fname)")) {
        Write-Step "Removing $guid : CiTool --remove-policy `"$guid`""
        $out = & CiTool.exe --remove-policy "$guid" 2>&1
        Write-Host ($out | Out-String)
        if ($LASTEXITCODE -ne 0) {
            Write-Err "CiTool --remove-policy failed (exit $LASTEXITCODE) for $guid"
            throw "Removal failed for $guid. Remaining Warden policies were not touched."
        }
        Write-Ok "Removed $guid"
        $removed++
    } else {
        Write-Warn "[WhatIf] Would remove $guid ($fname)"
    }
}

Write-Host ''
Write-Ok "Done. Removed $removed Warden policy(ies)."
Write-Host "  Verify:  CiTool --list-policies --json" -ForegroundColor DarkGray
Write-Warn "On Windows 11 pre-24H2, a reboot may be needed for removal to fully take effect."
