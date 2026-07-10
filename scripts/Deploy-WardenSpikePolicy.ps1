#Requires -RunAsAdministrator
<#
================================================================================
 Deploy-WardenSpikePolicy.ps1  -  Warden Phase 0 Spike
================================================================================

 Builds and deploys the Warden WDAC policies inside an ISOLATED Windows 11 VM.

 WHAT IT DOES
 ------------
  * Derives a fresh multiple-policy BASE from Microsoft's shipped
    DefaultWindows_Audit.xml (does NOT hand-author a default-deny allowlist):
      - Copy   C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml
      - Reset  to a brand-new base GUID   (Set-CIPolicyIdInfo -ResetPolicyID)
      - Ensure options 6 (unsigned), 0 (UMCI), 16 (no-reboot), 17 (allow
        supplementals), and 3 (AUDIT - present by default; removed with -Enforce)
      - During the AUDIT phase, also removes option 19 (Dynamic Code Security),
        which has no audit mode and would otherwise enforce on first run
      - On ENFORCE, asserts options 9 (Advanced Boot Options / F8) and 10 (Boot
        Audit on Failure) so the first enforced ring stays recoverable
      - Compile with ConvertFrom-CIPolicy and deploy with CiTool --update-policy
  * With -DeploySupplemental: takes the hand-authored
    policy\WardenSpike.Supplemental.xml, points its BasePolicyID at the deployed
    base (Set-CIPolicyIdInfo -SupplementsBasePolicyID), regenerates the allow
    hash from the real lab exe (New-CIPolicy -Level Hash over an ISOLATED copy),
    compiles and deploys it. This is the "user clicks Allow" loop: the previously
    would-be-blocked exe now runs (union of allows).
  * The unsigned Warden.Spike reader tool (-WardenSpikeToolPath), when present, is
    automatically folded into the supplemental allow-set so an ENFORCE base does
    not block the very tool the spike relies on (goal #3).
  * With -Enforce: redeploys the SAME base with Audit Mode (option 3) removed.
    REFUSED unless a prior audit base already exists AND -IHaveReviewedAuditEvents
    is passed - you can never strip Audit Mode on a first, unobserved run.

 WHY THE BLOCK NEEDS NO DENY RULE
 --------------------------------
  DefaultWindows_Audit allows Windows via SIGNER rules but allows nothing for an
  unsigned user-folder binary. That binary is therefore blocked by ABSENCE OF
  ALLOW (3076 audit / 3077 enforce). Because it is not an explicit <Deny>, the
  supplemental Allow-by-hash can later unblock it (WDAC precedence: all Deny,
  then all Allow; Deny always wins - so we must NOT use Deny here).

 SAFETY
 ------
  * Refuses to run without -IUnderstandVmOnly (VM-only guard) and warns if the
    hardware does not look like a virtual machine.
  * Audit-FIRST: the default deployment is audit mode, which logs but does not
    block, so the VM cannot be locked out on first contact. -Enforce is gated so
    it can never run before an audit base has been deployed and reviewed.
  * Prints the exact CiTool --remove-policy {GUID} rollback command(s).
  * Unsigned + multiple-policy + HVCI-off => every deploy is reboot-free.
  * Supports -WhatIf: every CiTool/compile side effect is gated by ShouldProcess.

 ------------------------------------------------------------------------------
 VM-ONLY RUN SEQUENCE (elevated PowerShell inside the isolated Windows 11 VM):
   1. .\scripts\New-WardenLabExe.ps1
   2. .\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly              # audit base
        -> run %USERPROFILE%\WardenSpikeLab\hello.exe, observe event 3076
   3. .\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly -DeploySupplemental
        -> hello.exe now runs (union of allows)
   4. .\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly -Enforce -IHaveReviewedAuditEvents
        -> optional; requires a prior audit base; real blocks now log 3077
   5. .\scripts\Remove-WardenSpikePolicy.ps1 -IUnderstandVmOnly              # rollback
 ------------------------------------------------------------------------------
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Mandatory acknowledgement that this runs only in a throwaway VM.
    [switch]$IUnderstandVmOnly,

    # Redeploy the base with Audit Mode (option 3) removed => real enforcement.
    # REFUSED on a fresh machine: enforce requires a pre-existing audit base AND
    # -IHaveReviewedAuditEvents (see the enforce gate below). This preserves the
    # audit-first intent - you can never strip Audit Mode on the very first run.
    [switch]$Enforce,

    # Second, explicit confirmation that the audit (3076) events were reviewed.
    # REQUIRED together with -Enforce; enforce refuses without it. This is the
    # deliberate audit -> enforce line: you must assert you looked before blocking.
    [switch]$IHaveReviewedAuditEvents,

    # Build and deploy the allow-by-hash supplemental for the lab exe.
    [switch]$DeploySupplemental,

    # The lab exe whose hash the supplemental allows.
    [string]$LabExePath = (Join-Path $env:USERPROFILE 'WardenSpikeLab\hello.exe'),

    # The unsigned Warden.Spike dossier/reader tool (spike goal #3). It is
    # user-built and unsigned, so an ENFORCE base (which allows only
    # Windows/Store/Microsoft-signed code) would BLOCK it - a self-lockout of the
    # very tool the spike needs. When this exe exists it is automatically folded
    # into the supplemental allow-set so the reader keeps running under enforce.
    [string]$WardenSpikeToolPath = (Join-Path $env:USERPROFILE 'WardenSpikeLab\Warden.Spike.exe'),

    # Working directory for generated XML / .cip artifacts.
    [string]$WorkDir = (Join-Path $env:USERPROFILE 'WardenSpikeLab\policy')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------
function Write-Step { param([string]$m) Write-Host "[warden] $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "[warden] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "[warden] $m" -ForegroundColor Yellow }
function Write-Err  { param([string]$m) Write-Host "[warden] $m" -ForegroundColor Red }

# ----------------------------------------------------------------------------
# 0. Guards
# ----------------------------------------------------------------------------
if (-not $IUnderstandVmOnly) {
    Write-Err "REFUSING TO RUN."
    Write-Err "This script deploys a Windows Application Control (WDAC) policy that can"
    Write-Err "prevent code from running. Run it ONLY inside an isolated Windows 11 VM."
    Write-Err "Re-run with the explicit switch:  -IUnderstandVmOnly"
    throw "Refused: -IUnderstandVmOnly was not supplied."
}

# Best-effort VM heuristic. -IUnderstandVmOnly is the hard interlock (a deliberate
# confirmation switch); this is an EXTRA guardrail that warns loudly when the
# hardware does not look virtual, so a fat-fingered run on a physical host is at
# least noisy. It is intentionally warn-only (does not block) to avoid failing on
# nested/unknown virtualization the heuristic can't recognize.
function Test-IsVirtualMachine {
    try {
        $cs  = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hay = "$($cs.Manufacturer) $($cs.Model)"
        return ($hay -match 'Virtual|VMware|Hyper-V|VirtualBox|KVM|QEMU|Xen|Parallels|Bochs|innotek')
    } catch {
        return $true   # if we cannot determine, do not add friction
    }
}
if (-not (Test-IsVirtualMachine)) {
    Write-Warn "This machine does NOT look like a virtual machine (Win32_ComputerSystem"
    Write-Warn "manufacturer/model carries no known hypervisor marker). WDAC policies applied"
    Write-Warn "here affect REAL hardware. If this is genuinely a throwaway VM you may ignore"
    Write-Warn "this; otherwise STOP NOW (Ctrl+C) - you passed -IUnderstandVmOnly on a host."
}

# ConfigCI module (New-CIPolicy, Set-CIPolicyIdInfo, Set-RuleOption, ConvertFrom-CIPolicy)
if (-not (Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue)) {
    Import-Module ConfigCI -ErrorAction Stop
}
# CiTool ships in Windows 11 22H2+ / Server 2025.
if (-not (Get-Command CiTool.exe -ErrorAction SilentlyContinue) -and
    -not (Test-Path "$env:WINDIR\System32\CiTool.exe")) {
    throw "CiTool.exe not found. This spike requires Windows 11 22H2+ (or Server 2025)."
}

$Template = Join-Path $env:WINDIR 'schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml'
if (-not (Test-Path -LiteralPath $Template)) {
    throw "Microsoft template not found: $Template"
}

$RepoSupplemental = Join-Path $PSScriptRoot '..\policy\WardenSpike.Supplemental.xml'
$RepoSupplemental = [System.IO.Path]::GetFullPath($RepoSupplemental)

$SiNs = 'urn:schemas-microsoft-com:sipolicy'

if (-not (Test-Path -LiteralPath $WorkDir)) {
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
}
$BaseXml = Join-Path $WorkDir 'WardenBase.xml'
$SuppXml = Join-Path $WorkDir 'WardenSupp.xml'

# ----------------------------------------------------------------------------
# 0b. ENFORCE gate - enforce is a deliberate SECOND step, never a first run.
# ----------------------------------------------------------------------------
# Rationale: -Enforce on a FRESH machine would (1) create a DefaultWindows-derived
# base and (2) immediately strip Audit Mode, blocking every non-Microsoft binary
# BEFORE any 3076 audit event was ever observed - including the unsigned
# Warden.Spike reader tool. That side-steps the whole audit-first intent and is an
# easy self-lockout. So enforce is refused unless BOTH hold:
#   * a prior audit base already exists on disk (WardenBase.xml), and
#   * the operator explicitly passes -IHaveReviewedAuditEvents.
if ($Enforce) {
    if (-not (Test-Path -LiteralPath $BaseXml)) {
        Write-Err "REFUSING TO ENFORCE ON A FRESH MACHINE."
        Write-Err "No prior audit base was found at: $BaseXml"
        Write-Err "-Enforce would create a base and immediately remove Audit Mode, blocking every"
        Write-Err "non-Microsoft binary (including the unsigned Warden.Spike reader) before a single"
        Write-Err "3076 'would-block' event is ever seen."
        Write-Err "Deploy the AUDIT base first (run WITHOUT -Enforce), observe 3076, THEN enforce."
        throw "Refused: -Enforce requires an existing audit base ($BaseXml)."
    }
    if (-not $IHaveReviewedAuditEvents) {
        Write-Err "REFUSING TO ENFORCE."
        Write-Err "Enforce turns 'would-block' (3076) into REAL blocks (3077). Confirm you have"
        Write-Err "reviewed the audit events and are ready by ALSO passing:"
        Write-Err "  -IHaveReviewedAuditEvents"
        throw "Refused: -Enforce requires -IHaveReviewedAuditEvents."
    }
}

Write-Step "Template     : $Template"
Write-Step "Work dir     : $WorkDir"
Write-Step "Lab exe      : $LabExePath"
Write-Step "Reader tool  : $WardenSpikeToolPath"
$modeLabel = if ($Enforce) { 'ENFORCE' } else { 'AUDIT' }
if ($DeploySupplemental) { $modeLabel = "$modeLabel +SUPPLEMENTAL" }
Write-Step "Mode         : $modeLabel"

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

# Load a policy XML with a namespace manager bound to prefix 'si'.
function Get-PolicyXml {
    param([string]$Path)
    [xml]$doc = Get-Content -LiteralPath $Path -Raw
    $nsm = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $nsm.AddNamespace('si', $SiNs)
    return [pscustomobject]@{ Doc = $doc; Nsm = $nsm }
}

function Get-PolicyIdFromXml {
    param([string]$Path)
    $p = Get-PolicyXml -Path $Path
    $node = $p.Doc.SelectSingleNode('/si:SiPolicy/si:PolicyID', $p.Nsm)
    if (-not $node) { throw "No PolicyID element found in $Path" }
    return $node.InnerText.Trim()
}

# Bump the 4th component of VersionEx so an update is accepted (must be >= active).
function Step-PolicyVersion {
    param([string]$Path)
    $p = Get-PolicyXml -Path $Path
    $vNode = $p.Doc.SelectSingleNode('/si:SiPolicy/si:VersionEx', $p.Nsm)
    $parts = $vNode.InnerText.Trim().Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    $parts[3] = ([int]$parts[3] + 1).ToString()
    $vNode.InnerText = ($parts -join '.')
    $p.Doc.Save($Path)
    Write-Step "Bumped VersionEx -> $($vNode.InnerText)"
}

# Ensure a rule option is present (or absent with -Remove) via Set-RuleOption.
function Set-Option {
    param([string]$Path, [int]$Option, [switch]$Remove)
    if ($Remove) {
        Set-RuleOption -FilePath $Path -Option $Option -Delete
    } else {
        Set-RuleOption -FilePath $Path -Option $Option
    }
}

# Compile XML -> {PolicyID}.cip and return the .cip path.
function Build-Cip {
    param([string]$XmlPath)
    $policyId = Get-PolicyIdFromXml -Path $XmlPath
    $cip = Join-Path $WorkDir ("$policyId.cip")
    ConvertFrom-CIPolicy -XmlFilePath $XmlPath -BinaryFilePath $cip | Out-Null
    if (-not (Test-Path -LiteralPath $cip)) { throw "ConvertFrom-CIPolicy produced no output for $XmlPath" }
    return $cip
}

# Deploy a .cip via CiTool --update-policy (gated by ShouldProcess for -WhatIf).
function Deploy-Cip {
    param([string]$CipPath, [string]$Label)
    if ($PSCmdlet.ShouldProcess($CipPath, "CiTool --update-policy ($Label)")) {
        Write-Step "Deploying $Label : CiTool --update-policy `"$CipPath`" --json"
        $out = & CiTool.exe --update-policy "$CipPath" --json 2>&1
        Write-Host ($out | Out-String)
        if ($LASTEXITCODE -ne 0) { throw "CiTool --update-policy failed (exit $LASTEXITCODE) for $CipPath" }
        Write-Ok "$Label deployed (rebootless; unsigned multiple-policy)."
    } else {
        Write-Warn "[WhatIf] Would deploy $Label : CiTool --update-policy `"$CipPath`" --json"
    }
}

# ----------------------------------------------------------------------------
# 1. Build / refresh the BASE policy
# ----------------------------------------------------------------------------
$baseFreshlyCreated = $false

if (-not (Test-Path -LiteralPath $BaseXml)) {
    Write-Step "Creating fresh base from Microsoft template."
    Copy-Item -LiteralPath $Template -Destination $BaseXml -Force
    # Fresh, self-consistent base GUID (sets PolicyID AND BasePolicyID).
    $null = Set-CIPolicyIdInfo -FilePath $BaseXml -ResetPolicyID
    # Friendly Name/Id (the Remove script matches on the "Warden" prefix).
    $null = Set-CIPolicyIdInfo -FilePath $BaseXml -PolicyName 'Warden Spike Base' -PolicyId 'WardenSpikeBase'
    $baseFreshlyCreated = $true
} else {
    Write-Step "Reusing existing working base: $BaseXml"
}

$BaseGuid = Get-PolicyIdFromXml -Path $BaseXml
Write-Step "Base PolicyID: $BaseGuid"

# Required options on the base. DefaultWindows_Audit already carries 0/3/16;
# we assert them anyway (idempotent) and add 17 (allow supplementals).
Set-Option -Path $BaseXml -Option 6    # Enabled:Unsigned System Integrity Policy (rebootless)
Set-Option -Path $BaseXml -Option 0    # Enabled:UMCI (user-mode enforcement)
Set-Option -Path $BaseXml -Option 16   # Enabled:Update Policy No Reboot
Set-Option -Path $BaseXml -Option 17   # Enabled:Allow Supplemental Policies (Warden loop)

if ($Enforce) {
    Write-Warn "ENFORCE requested: removing Audit Mode (option 3). Blocks will be REAL (event 3077)."
    Set-Option -Path $BaseXml -Option 3 -Remove
    # First-enforced-ring recoverability. Assert the recovery affordances on the
    # base so a bad enforce policy can still be backed out of:
    #   9  Enabled:Advanced Boot Options Menu  (keeps the F8 recovery menu usable)
    #   10 Enabled:Boot Audit on Failure       (boot audits instead of bricking if
    #                                            the policy would block boot-critical code)
    Set-Option -Path $BaseXml -Option 9
    Set-Option -Path $BaseXml -Option 10
} else {
    Write-Step "AUDIT-first: ensuring Audit Mode (option 3) is present (would-block only, event 3076)."
    Set-Option -Path $BaseXml -Option 3
    # DefaultWindows_Audit inherits option 19 (Dynamic Code Security), which has NO
    # audit mode - it is ENFORCED even while the policy is in Audit Mode, so an
    # "audit" deploy is not strictly a no-op for dynamically-generated/JIT/unsigned-
    # at-runtime .NET code. Remove it during the audit-first phase so the FIRST run
    # is a genuine observe-only pass. (Idempotent: tolerate it already being absent.)
    try { Set-Option -Path $BaseXml -Option 19 -Remove }
    catch { Write-Step "Option 19 (Dynamic Code Security) already absent." }
}

# Version must increase on redeploy of the same PolicyID.
if (-not $baseFreshlyCreated) { Step-PolicyVersion -Path $BaseXml }

$BaseCip = Build-Cip -XmlPath $BaseXml
Deploy-Cip -CipPath $BaseCip -Label "BASE ($(if($Enforce){'enforce'}else{'audit'}))"

# ----------------------------------------------------------------------------
# 2. Build / refresh the SUPPLEMENTAL (allow user binaries by hash) - optional
# ----------------------------------------------------------------------------
# The supplemental allows the specific unsigned user binaries the spike needs:
#   * the lab exe (the "user clicks Allow" rehearsal), and
#   * the Warden.Spike reader tool (so an ENFORCE base does not block goal #3).
# We always include EVERY known target that exists on disk, so the allow-set is
# MONOTONIC: flipping to enforce never silently drops a binary that a previous
# audit-phase supplemental had allowed.
$suppTargets = @()
if (Test-Path -LiteralPath $LabExePath) {
    $suppTargets += (Resolve-Path -LiteralPath $LabExePath).Path
}
if (Test-Path -LiteralPath $WardenSpikeToolPath) {
    $suppTargets += (Resolve-Path -LiteralPath $WardenSpikeToolPath).Path
} elseif ($Enforce) {
    Write-Warn "Warden.Spike reader tool not found at: $WardenSpikeToolPath"
    Write-Warn "Enforce will NOT auto-allow it. If you build the reader later it will be BLOCKED"
    Write-Warn "until you re-run with the exe present (or -DeploySupplemental) so its hash is added."
}
$suppTargets = @($suppTargets | Select-Object -Unique)

# -DeploySupplemental is the explicit 'rehearse the allow loop' request, so if it
# was asked for, the lab exe MUST exist.
if ($DeploySupplemental -and -not (Test-Path -LiteralPath $LabExePath)) {
    throw "Lab exe not found: $LabExePath. Run scripts\New-WardenLabExe.ps1 first."
}

# Build a supplemental when explicitly requested, OR when enforcing and there is a
# user binary (esp. the reader) that would otherwise be self-locked-out.
$buildSupplemental = ($DeploySupplemental -or $Enforce) -and $suppTargets.Count -gt 0

$SuppGuid = $null
if ($buildSupplemental) {

    if (-not (Test-Path -LiteralPath $RepoSupplemental)) {
        throw "Hand-authored supplemental not found: $RepoSupplemental"
    }

    $suppExisted = Test-Path -LiteralPath $SuppXml

    Write-Step "Preparing supplemental from hand-authored template."
    # The fixed supplemental GUID from the checked-in file - must stay stable so
    # redeploys UPDATE the same supplemental instead of stacking duplicates.
    $FixedSuppGuid = Get-PolicyIdFromXml -Path $RepoSupplemental
    Copy-Item -LiteralPath $RepoSupplemental -Destination $SuppXml -Force

    # Point BasePolicyID at the deployed base; set friendly Name/Id.
    $null = Set-CIPolicyIdInfo -FilePath $SuppXml -SupplementsBasePolicyID $BaseGuid
    $null = Set-CIPolicyIdInfo -FilePath $SuppXml -PolicyName 'Warden Spike Supplemental (Allow user binaries)' -PolicyId 'WardenSpikeSupplemental'

    # Re-assert the fixed PolicyID (defensive: some ConfigCI builds may rewrite it).
    $spId = Get-PolicyXml -Path $SuppXml
    $idNode = $spId.Doc.SelectSingleNode('/si:SiPolicy/si:PolicyID', $spId.Nsm)
    if ($idNode.InnerText.Trim() -ne $FixedSuppGuid) {
        Write-Step "Re-asserting fixed supplemental PolicyID -> $FixedSuppGuid"
        $idNode.InnerText = $FixedSuppGuid
        $spId.Doc.Save($SuppXml)
    }

    # Fail LOUD if the base linkage did not take. The checked-in file ships an
    # all-zeros BasePolicyID placeholder (which would compile to an INERT
    # supplemental that supplements nothing); refuse to deploy that.
    $bpNode = $spId.Doc.SelectSingleNode('/si:SiPolicy/si:BasePolicyID', $spId.Nsm)
    $bpVal  = if ($bpNode) { $bpNode.InnerText.Trim() } else { '' }
    if (($bpVal -replace '[{}0\-]', '') -eq '') {
        throw "Supplemental BasePolicyID is empty/all-zeros after linkage ('$bpVal'). Refusing to deploy an inert supplemental."
    }

    # --- Regenerate the real allow hash(es) with New-CIPolicy -----------------
    # ISOLATED scan dir: copy ONLY the intended target exe(s) into a dedicated
    # folder and scan THAT. New-CIPolicy -ScanPath is recursive, so scanning the
    # lab folder directly (which also contains $WorkDir as a subfolder) would hash
    # and allow every stray PE under it - broadening the allow beyond the intended
    # binaries. Copying to an isolated dir constrains the allow-set to exactly the
    # files we chose.
    Write-Step "Computing Authenticode hash(es) via New-CIPolicy -Level Hash (isolated scan)."
    $scanDir = Join-Path $WorkDir '_scan'
    if (Test-Path -LiteralPath $scanDir) { Remove-Item -LiteralPath $scanDir -Recurse -Force }
    New-Item -ItemType Directory -Path $scanDir -Force | Out-Null
    foreach ($t in $suppTargets) {
        Copy-Item -LiteralPath $t -Destination (Join-Path $scanDir (Split-Path -Leaf $t)) -Force
        Write-Step "  scan target: $t"
    }
    $hashXml = Join-Path $WorkDir '_labhash.xml'
    # -UserPEs = user-mode PEs only; -NoScript = don't add script rules;
    # -MultiplePolicyFormat = emit multiple-policy-format rule IDs.
    New-CIPolicy -Level Hash -ScanPath $scanDir -UserPEs -NoScript -MultiplePolicyFormat -FilePath $hashXml -Fallback Hash 3>$null | Out-Null

    $hp = Get-PolicyXml -Path $hashXml
    # SHA-256 hashes are 64 hex chars (Authenticode SHA256 + first-page SHA256).
    # SHA-1 variants are 40 chars; we take only the SHA-256 ones.
    $sha256Allows = @($hp.Doc.SelectNodes('//si:FileRules/si:Allow', $hp.Nsm) |
        Where-Object { $_.Hash -and $_.Hash.Length -eq 64 })
    if ($sha256Allows.Count -eq 0) {
        throw "New-CIPolicy produced no SHA-256 hash rules for the scan targets (are they valid PEs?)."
    }
    Write-Step "Found $($sha256Allows.Count) SHA-256 hash rule(s) across $($suppTargets.Count) target(s)."

    # --- Inject those hashes into the hand-authored supplemental --------------
    $sp        = Get-PolicyXml -Path $SuppXml
    $doc       = $sp.Doc
    $nsm       = $sp.Nsm
    $fileRules = $doc.SelectSingleNode('/si:SiPolicy/si:FileRules', $nsm)
    $refParent = $doc.SelectSingleNode(
        "/si:SiPolicy/si:SigningScenarios/si:SigningScenario[@Value='12']/si:ProductSigners/si:FileRulesRef", $nsm)

    # Clear the placeholder Allow(s) and their refs; rebuild from real hashes.
    $fileRules.RemoveAll()
    $refParent.RemoveAll()

    $i = 0
    foreach ($src in $sha256Allows) {
        $id = "ID_ALLOW_WARDEN_USERBIN_$i"

        $allow = $doc.CreateElement('Allow', $SiNs)
        $allow.SetAttribute('ID', $id)
        $fn = if ($src.FriendlyName) { $src.FriendlyName } else { "Warden user binary hash $i" }
        $allow.SetAttribute('FriendlyName', $fn)
        $allow.SetAttribute('Hash', $src.Hash)
        $fileRules.AppendChild($allow) | Out-Null

        $ref = $doc.CreateElement('FileRuleRef', $SiNs)
        $ref.SetAttribute('RuleID', $id)
        $refParent.AppendChild($ref) | Out-Null

        Write-Step "  + $id  Hash=$($src.Hash)"
        $i++
    }
    $doc.Save($SuppXml)

    # Version must increase on redeploy of the same supplemental PolicyID.
    if ($suppExisted) { Step-PolicyVersion -Path $SuppXml }

    $SuppGuid = Get-PolicyIdFromXml -Path $SuppXml
    Write-Step "Supplemental PolicyID: $SuppGuid  (BasePolicyID -> $BaseGuid)"

    $SuppCip = Build-Cip -XmlPath $SuppXml
    Deploy-Cip -CipPath $SuppCip -Label "SUPPLEMENTAL (allow $($suppTargets.Count) user binary/ies)"
}

# ----------------------------------------------------------------------------
# 3. Summary + ROLLBACK commands (always printed)
# ----------------------------------------------------------------------------
Write-Host ''
Write-Ok  '================ Warden spike deployment summary ================'
Write-Host "  Base policy      : $BaseGuid   ($(if($Enforce){'ENFORCE / 3077'}else{'AUDIT / 3076'}))" -ForegroundColor Green
if ($SuppGuid) {
    Write-Host "  Supplemental     : $SuppGuid   (allows $($suppTargets.Count) user binary/ies by hash)" -ForegroundColor Green
}
Write-Host ''
Write-Warn 'ROLLBACK (remove the supplemental FIRST, then the base):'
if ($SuppGuid) {
    Write-Host "    CiTool --remove-policy `"$SuppGuid`"" -ForegroundColor Yellow
}
Write-Host "    CiTool --remove-policy `"$BaseGuid`"" -ForegroundColor Yellow
Write-Host "  Or:  .\scripts\Remove-WardenSpikePolicy.ps1 -IUnderstandVmOnly" -ForegroundColor Yellow
Write-Host ''
Write-Host '  Verify active policies:  CiTool --list-policies --json' -ForegroundColor DarkGray
Write-Host '  CI events:  Applications and Services Logs > Microsoft > Windows >' -ForegroundColor DarkGray
Write-Host '              CodeIntegrity > Operational  (3076 audit / 3077 enforce / 3089 signature)' -ForegroundColor DarkGray
Write-Ok  '================================================================='
