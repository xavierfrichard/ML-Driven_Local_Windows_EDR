#Requires -RunAsAdministrator
<#
================================================================================
 Deploy-WardenSpikePolicy.ps1  -  Warden Phase 0 Spike
================================================================================

 Builds and deploys the Warden WDAC policies inside an ISOLATED Windows 11 VM.

 WHAT IT DOES
 ------------
  * Regenerates the BASE on EVERY run from Microsoft's shipped
    DefaultWindows_Audit.xml (does NOT hand-author a default-deny allowlist, and
    never reuses a base XML left on disk by an earlier run):
      - Copy   C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml
      - Give it the spike's FIXED base PolicyID ($SpikeBasePolicyId), so redeploys
        update the same base instead of stacking new ones
      - Ensure options 6 (unsigned), 0 (UMCI), 16 (no-reboot), 17 (allow
        supplementals), and 3 (AUDIT - present by default; removed with -Enforce)
      - During the AUDIT phase, also removes option 19 (Dynamic Code Security),
        which has no audit mode and would otherwise enforce on first run
      - On ENFORCE, asserts options 9 (Advanced Boot Options / F8) and 10 (Boot
        Audit on Failure) so the first enforced ring stays recoverable
      - Sets VersionEx above the version currently deployed for that PolicyID
      - Compile with ConvertFrom-CIPolicy and deploy with CiTool --update-policy
  * With -DeploySupplemental: takes the hand-authored
    policy\WardenSpike.Supplemental.xml, points its BasePolicyID at the spike
    base (Set-CIPolicyIdInfo -SupplementsBasePolicyID), regenerates the allow
    hash from the real lab exe (New-CIPolicy -Level Hash over an ISOLATED copy
    whose SHA-256 must match -LabExeSha256), compiles and deploys it. This is the
    "user clicks Allow" loop: the previously would-be-blocked exe now runs.
  * The unsigned Warden.Spike reader tool (-WardenSpikeToolPath) is folded into
    the supplemental allow-set when it exists AND -WardenSpikeToolSha256 pins it,
    so an ENFORCE base does not block the very tool the spike relies on (goal #3).
  * With -Enforce: redeploys the base with Audit Mode (option 3) removed.
    REFUSED unless the spike base is already deployed (an audit run happened)
    AND -IHaveReviewedAuditEvents is passed.

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
  * Admin-only work folder. Everything this script compiles and deploys is built
    in %ProgramData%\WardenSpikeLab\policy, which the script creates, owns as
    Administrators and ACL-locks to SYSTEM + Administrators (protected, no
    inheritance), then empties on every run. A folder pre-created by anyone else
    is refused. Nothing that is deployed is read back from a user-writable place.
  * Hash-pinned lab binaries. The lab exe and the reader tool live in the user's
    profile (they must, to be blocked). Each is copied into the admin-only folder
    and its SHA-256 is checked against the pin you pass (-LabExeSha256 /
    -WardenSpikeToolSha256) before New-CIPolicy hashes it. New-WardenLabExe.ps1
    prints the value to pass.
  * Own PolicyIDs. The spike base ($SpikeBasePolicyId) and supplemental
    ($SpikeSupplementalPolicyId) never share an ID with the Warden service's
    allow-list supplemental ({7A4D1C0A-5B2E-4F6A-9C3D-000000000001}).
  * Audit-FIRST: the default deployment is audit mode, which logs but does not
    block, so the VM cannot be locked out on first contact. -Enforce is gated so
    it can never run before an audit base has been deployed and reviewed.
  * Prints the exact CiTool --remove-policy {GUID} rollback command(s).
  * Unsigned + multiple-policy + HVCI-off => every deploy is reboot-free.
  * Supports -WhatIf: every CiTool deploy is gated by ShouldProcess. The work
    folder is still prepared and the policies compiled under -WhatIf.

 ------------------------------------------------------------------------------
 VM-ONLY RUN SEQUENCE (elevated PowerShell inside the isolated Windows 11 VM):
   1. .\scripts\New-WardenLabExe.ps1
        -> prints the lab exe's SHA-256 to pass as -LabExeSha256
   2. .\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly              # audit base
        -> run %USERPROFILE%\WardenSpikeLab\hello.exe, observe event 3076
   3. .\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly -DeploySupplemental -LabExeSha256 <hash>
        -> hello.exe now runs (union of allows)
   4. .\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly -Enforce -IHaveReviewedAuditEvents -LabExeSha256 <hash>
        -> optional; requires a prior audit base; real blocks now log 3077
   5. .\scripts\Remove-WardenSpikePolicy.ps1 -IUnderstandVmOnly              # rollback
 ------------------------------------------------------------------------------
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Mandatory acknowledgement that this runs only in a throwaway VM.
    [switch]$IUnderstandVmOnly,

    # Redeploy the base with Audit Mode (option 3) removed => real enforcement.
    # REFUSED unless the spike base is already deployed AND
    # -IHaveReviewedAuditEvents is passed (see the enforce gate below).
    [switch]$Enforce,

    # Second, explicit confirmation that the audit (3076) events were reviewed.
    # REQUIRED together with -Enforce.
    [switch]$IHaveReviewedAuditEvents,

    # Build and deploy the allow-by-hash supplemental for the lab exe.
    [switch]$DeploySupplemental,

    # The lab exe whose hash the supplemental allows.
    [string]$LabExePath = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'WardenSpikeLab\hello.exe'),

    # SHA-256 (hex) the lab exe must have. Required whenever the lab exe goes into
    # the supplemental; New-WardenLabExe.ps1 prints it.
    [string]$LabExeSha256,

    # The unsigned Warden.Spike dossier/reader tool (spike goal #3). It is
    # user-built and unsigned, so an ENFORCE base would BLOCK it. When it exists
    # and -WardenSpikeToolSha256 pins it, it is folded into the supplemental.
    [string]$WardenSpikeToolPath = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'WardenSpikeLab\Warden.Spike.exe'),

    # SHA-256 (hex) the reader tool must have. Without it the tool is NOT allowed.
    [string]$WardenSpikeToolSha256,

    # Working directory for generated XML / .cip artifacts. Must be inside the
    # admin-only lab root (%ProgramData%\WardenSpikeLab); it is emptied every run.
    [string]$WorkDir = (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'WardenSpikeLab\policy')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The spike's own fixed PolicyIDs. They must never equal the Warden service's
# allow-list supplemental ({7A4D1C0A-5B2E-4F6A-9C3D-000000000001}): two policies
# with one PolicyID overwrite each other on every deploy.
$SpikeBasePolicyId         = '{77EEF7EE-839E-49F6-ADF1-3BD853A234B1}'
$SpikeSupplementalPolicyId = '{591A5539-3983-4C77-92B7-583045489C23}'
$ServiceSupplementalPolicyId = '{7A4D1C0A-5B2E-4F6A-9C3D-000000000001}'

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
# hardware does not look virtual. It is intentionally warn-only.
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

# Pinned System32 paths (not PATH or environment-variable lookups, which the
# user can redirect for their own elevated processes).
$WindowsDir = [Environment]::GetFolderPath('Windows')
$CiTool     = Join-Path ([Environment]::SystemDirectory) 'CiTool.exe'
if (-not (Test-Path -LiteralPath $CiTool)) {
    throw "CiTool.exe not found at $CiTool. This spike requires Windows 11 22H2+ (or Server 2025)."
}

$Template = Join-Path $WindowsDir 'schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml'
if (-not (Test-Path -LiteralPath $Template)) {
    throw "Microsoft template not found: $Template"
}

$RepoSupplemental = Join-Path $PSScriptRoot '..\policy\WardenSpike.Supplemental.xml'
$RepoSupplemental = [System.IO.Path]::GetFullPath($RepoSupplemental)

$SiNs = 'urn:schemas-microsoft-com:sipolicy'

# ----------------------------------------------------------------------------
# 0a. Admin-only work folder
# ----------------------------------------------------------------------------
$LabRoot = [System.IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'WardenSpikeLab'))
$WorkDir = [System.IO.Path]::GetFullPath($WorkDir)
if (-not ($WorkDir.StartsWith($LabRoot.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase))) {
    throw "Refused: -WorkDir must be inside the admin-only lab root $LabRoot (got $WorkDir)."
}

$SidAdministrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$SidSystem         = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$TrustedOwners = @($SidAdministrators.Value, $SidSystem.Value, $SidTrustedInstaller)

function Assert-NotReparsePoint {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) { throw "Refused: $Path exists and is not a directory." }
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Refused: $Path is a junction/symlink (reparse point). Delete it as an administrator and re-run."
    }
}

# Create (or adopt) $LabRoot as an Administrators-owned folder with a protected
# SYSTEM + Administrators-only ACL, then recreate $WorkDir empty inside it.
function Initialize-AdminOnlyWorkDir {
    # Every existing level down to the lab root must be a real directory.
    foreach ($dir in @((Split-Path -Parent $LabRoot), $LabRoot)) {
        if (Test-Path -LiteralPath $dir) { Assert-NotReparsePoint -Path $dir }
    }

    if (Test-Path -LiteralPath $LabRoot) {
        $owner = (Get-Acl -LiteralPath $LabRoot).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($TrustedOwners -notcontains $owner) {
            throw ("Refused: $LabRoot already exists and is owned by $owner, not Administrators/SYSTEM. " +
                   "Someone else may have pre-created it. Inspect and delete it as an administrator, then re-run.")
        }
    } else {
        New-Item -ItemType Directory -Path $LabRoot -WhatIf:$false | Out-Null
    }

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner($SidAdministrators)
    $acl.SetAccessRuleProtection($true, $false)   # no inherited entries
    foreach ($sid in @($SidSystem, $SidAdministrators)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $LabRoot -AclObject $acl -WhatIf:$false
    Assert-NotReparsePoint -Path $LabRoot

    # Start from an empty work folder every run. Directory.Delete does not follow
    # junctions inside the tree (it removes the link, not the target).
    if (Test-Path -LiteralPath $WorkDir) {
        Assert-NotReparsePoint -Path $WorkDir
        [System.IO.Directory]::Delete($WorkDir, $true)
    }
    New-Item -ItemType Directory -Path $WorkDir -WhatIf:$false | Out-Null
    Assert-NotReparsePoint -Path $WorkDir
}

Initialize-AdminOnlyWorkDir
$BaseXml = Join-Path $WorkDir 'WardenBase.xml'
$SuppXml = Join-Path $WorkDir 'WardenSupp.xml'

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

# Set a direct child element of SiPolicy (PolicyID, BasePolicyID, VersionEx).
function Set-PolicyElement {
    param([string]$Path, [string]$Name, [string]$Value)
    $p = Get-PolicyXml -Path $Path
    $node = $p.Doc.SelectSingleNode("/si:SiPolicy/si:$Name", $p.Nsm)
    if (-not $node) { throw "No $Name element found in $Path" }
    $node.InnerText = $Value
    $p.Doc.Save($Path)
}

function ConvertTo-GuidKey {
    param([string]$Guid)
    return ([string]$Guid).Trim().Trim('{', '}').ToLowerInvariant()
}

# Safe property accessor (CiTool JSON objects vary; StrictMode throws on missing).
function Get-Prop {
    param($Obj, [string]$Name, $Default = $null)
    $prop = $Obj.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $Default
}

# The deployed policy with this PolicyID (CiTool --list-policies), or $null.
function Get-DeployedPolicy {
    param([string]$PolicyId)
    $raw = & $CiTool --list-policies --json 2>&1
    if ($LASTEXITCODE -ne 0) { throw "CiTool --list-policies failed (exit $LASTEXITCODE): $raw" }
    $parsed = $raw | Out-String | ConvertFrom-Json
    $want = ConvertTo-GuidKey $PolicyId
    foreach ($p in @(Get-Prop $parsed 'Policies' @())) {
        if ((ConvertTo-GuidKey (Get-Prop $p 'PolicyID' '')) -eq $want) { return $p }
    }
    return $null
}

# A VersionEx above both the policy file's own and the one deployed for its
# PolicyID: WDAC applies an update to a deployed PolicyID only when the version
# goes up, and the XML is regenerated every run, so the file's version alone
# would repeat.
function Set-NextPolicyVersion {
    param([string]$Path, [string]$PolicyId)
    $p = Get-PolicyXml -Path $Path
    $vNode = $p.Doc.SelectSingleNode('/si:SiPolicy/si:VersionEx', $p.Nsm)
    $fileVersion = [version]$vNode.InnerText.Trim()
    $next = $fileVersion
    $deployed = Get-DeployedPolicy -PolicyId $PolicyId
    if ($deployed) {
        $text = [string](Get-Prop $deployed 'VersionString' '')
        $packed = Get-Prop $deployed 'Version' $null
        if (-not $text -and $null -ne $packed -and ([string]$packed) -match '^\d+$') {
            # Packed UInt64: major<<48 | minor<<32 | build<<16 | revision.
            $u = [UInt64]$packed
            $text = '{0}.{1}.{2}.{3}' -f ($u -shr 48), (($u -shr 32) -band 0xFFFF), (($u -shr 16) -band 0xFFFF), ($u -band 0xFFFF)
        }
        $dv = $null
        if ($text -and [version]::TryParse($text, [ref]$dv)) {
            $bumped = New-Object System.Version($dv.Major, $dv.Minor, [Math]::Max(0, $dv.Build), ([Math]::Max(0, $dv.Revision) + 1))
            if ($bumped -gt $next) { $next = $bumped }
        } else {
            throw "Policy $PolicyId is deployed but CiTool reported no parseable VersionString ('$text'); cannot pick a higher version."
        }
    }
    $vNode.InnerText = $next.ToString()
    $p.Doc.Save($Path)
    Write-Step "VersionEx for $PolicyId -> $next"
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

# Compile XML -> {PolicyID}.cip (in the admin-only work dir) and return the path.
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
        $out = & $CiTool --update-policy "$CipPath" --json 2>&1
        Write-Host ($out | Out-String)
        if ($LASTEXITCODE -ne 0) { throw "CiTool --update-policy failed (exit $LASTEXITCODE) for $CipPath" }
        Write-Ok "$Label deployed (rebootless; unsigned multiple-policy)."
    } else {
        Write-Warn "[WhatIf] Would deploy $Label : CiTool --update-policy `"$CipPath`" --json"
    }
}

# Copy a lab binary into the admin-only scan folder and check the COPY against
# its pinned SHA-256. The copy is what New-CIPolicy hashes, so a binary swapped
# in the user's profile after this check cannot reach the policy.
function Copy-PinnedBinary {
    param([string]$Source, [string]$ExpectedSha256, [string]$DestinationDir, [string]$Label)
    if (-not ($ExpectedSha256 -match '^[0-9A-Fa-f]{64}$')) {
        throw "Refused: $Label needs a 64-hex-digit SHA-256 pin."
    }
    $item = Get-Item -LiteralPath $Source -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Refused: $Label ($Source) is a symlink/reparse point."
    }
    $dest = Join-Path $DestinationDir (Split-Path -Leaf $Source)
    Copy-Item -LiteralPath $Source -Destination $dest -Force -WhatIf:$false
    $actual = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedSha256.ToUpperInvariant()) {
        Remove-Item -LiteralPath $dest -Force -WhatIf:$false
        throw "Refused: $Label at $Source has SHA-256 $actual, not the pinned $($ExpectedSha256.ToUpperInvariant())."
    }
    Write-Step "  pinned $Label : $Source  ($actual)"
    return $dest
}

# ----------------------------------------------------------------------------
# 0b. ENFORCE gate - enforce is a deliberate SECOND step, never a first run.
# ----------------------------------------------------------------------------
# Rationale: -Enforce on a FRESH machine would (1) create a DefaultWindows-derived
# base and (2) immediately strip Audit Mode, blocking every non-Microsoft binary
# BEFORE any 3076 audit event was ever observed. So enforce is refused unless BOTH:
#   * the spike base is already deployed (CiTool reports its PolicyID), and
#   * the operator explicitly passes -IHaveReviewedAuditEvents.
# (The deployed policy is the evidence: the work folder is emptied every run.)
if ($Enforce) {
    if (-not (Get-DeployedPolicy -PolicyId $SpikeBasePolicyId)) {
        Write-Err "REFUSING TO ENFORCE ON A FRESH MACHINE."
        Write-Err "The spike base $SpikeBasePolicyId is not deployed."
        Write-Err "-Enforce would create a base and immediately remove Audit Mode, blocking every"
        Write-Err "non-Microsoft binary (including the unsigned Warden.Spike reader) before a single"
        Write-Err "3076 'would-block' event is ever seen."
        Write-Err "Deploy the AUDIT base first (run WITHOUT -Enforce), observe 3076, THEN enforce."
        throw "Refused: -Enforce requires the audit base to be deployed first."
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
Write-Step "Work dir     : $WorkDir (admin-only, emptied each run)"
Write-Step "Lab exe      : $LabExePath"
Write-Step "Reader tool  : $WardenSpikeToolPath"
$modeLabel = if ($Enforce) { 'ENFORCE' } else { 'AUDIT' }
if ($DeploySupplemental) { $modeLabel = "$modeLabel +SUPPLEMENTAL" }
Write-Step "Mode         : $modeLabel"

# ----------------------------------------------------------------------------
# 1. Regenerate the BASE policy from the Microsoft template
# ----------------------------------------------------------------------------
Write-Step "Generating base from Microsoft template (never reused from disk)."
Copy-Item -LiteralPath $Template -Destination $BaseXml -Force -WhatIf:$false
# Converts the template to multiple-policy format with self-referencing IDs...
$null = Set-CIPolicyIdInfo -FilePath $BaseXml -ResetPolicyID
# ...then pins both IDs to the spike's fixed base ID, so every run updates the
# same deployed base instead of stacking a new one.
Set-PolicyElement -Path $BaseXml -Name 'PolicyID' -Value $SpikeBasePolicyId
Set-PolicyElement -Path $BaseXml -Name 'BasePolicyID' -Value $SpikeBasePolicyId
# Friendly Name/Id (the Remove script matches on the "Warden Spike" prefix).
$null = Set-CIPolicyIdInfo -FilePath $BaseXml -PolicyName 'Warden Spike Base' -PolicyId 'WardenSpikeBase'

$BaseGuid = Get-PolicyIdFromXml -Path $BaseXml
if ((ConvertTo-GuidKey $BaseGuid) -ne (ConvertTo-GuidKey $SpikeBasePolicyId)) {
    throw "Base PolicyID is $BaseGuid after generation, expected $SpikeBasePolicyId."
}
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
    # First-enforced-ring recoverability:
    #   9  Enabled:Advanced Boot Options Menu  (keeps the F8 recovery menu usable)
    #   10 Enabled:Boot Audit on Failure       (boot audits instead of bricking)
    Set-Option -Path $BaseXml -Option 9
    Set-Option -Path $BaseXml -Option 10
} else {
    Write-Step "AUDIT-first: ensuring Audit Mode (option 3) is present (would-block only, event 3076)."
    Set-Option -Path $BaseXml -Option 3
    # Option 19 (Dynamic Code Security) has NO audit mode - it is enforced even in
    # Audit Mode - so remove it during the audit-first phase. (Tolerate absence.)
    try { Set-Option -Path $BaseXml -Option 19 -Remove }
    catch { Write-Step "Option 19 (Dynamic Code Security) already absent." }
}

Set-NextPolicyVersion -Path $BaseXml -PolicyId $SpikeBasePolicyId

$BaseCip = Build-Cip -XmlPath $BaseXml
Deploy-Cip -CipPath $BaseCip -Label "BASE ($(if($Enforce){'enforce'}else{'audit'}))"

# ----------------------------------------------------------------------------
# 2. Build the SUPPLEMENTAL (allow pinned user binaries by hash) - optional
# ----------------------------------------------------------------------------
# The supplemental allows the specific unsigned user binaries the spike needs:
#   * the lab exe (the "user clicks Allow" rehearsal), and
#   * the Warden.Spike reader tool (so an ENFORCE base does not block goal #3).
# Each one is allowed only with a SHA-256 pin. The allow-set is rebuilt from the
# pinned binaries on every run.

# -DeploySupplemental is the explicit 'rehearse the allow loop' request, so if it
# was asked for, the lab exe MUST exist and be pinned.
if ($DeploySupplemental) {
    if (-not (Test-Path -LiteralPath $LabExePath)) {
        throw "Lab exe not found: $LabExePath. Run scripts\New-WardenLabExe.ps1 first."
    }
    if (-not $LabExeSha256) {
        throw "Refused: -DeploySupplemental needs -LabExeSha256 <hash> (New-WardenLabExe.ps1 prints it)."
    }
}

$labIncluded  = (Test-Path -LiteralPath $LabExePath) -and [bool]$LabExeSha256
$toolIncluded = (Test-Path -LiteralPath $WardenSpikeToolPath) -and [bool]$WardenSpikeToolSha256
if ((Test-Path -LiteralPath $WardenSpikeToolPath) -and -not $WardenSpikeToolSha256) {
    Write-Warn "Warden.Spike reader tool found at $WardenSpikeToolPath but no -WardenSpikeToolSha256 pin was given;"
    Write-Warn "it is NOT allowed. Under enforce it will be BLOCKED until you re-run with its SHA-256."
} elseif ($Enforce -and -not (Test-Path -LiteralPath $WardenSpikeToolPath)) {
    Write-Warn "Warden.Spike reader tool not found at: $WardenSpikeToolPath"
    Write-Warn "Enforce will NOT auto-allow it. If you build the reader later it will be BLOCKED"
    Write-Warn "until you re-run with the exe present and pinned (-WardenSpikeToolSha256)."
}
if ($Enforce -and (Test-Path -LiteralPath $LabExePath) -and -not $LabExeSha256) {
    Write-Warn "Lab exe present but not pinned (-LabExeSha256); it is NOT allowed and will be blocked under enforce."
}

# Build a supplemental when explicitly requested, OR when enforcing and there is
# a pinned user binary that would otherwise be self-locked-out.
$buildSupplemental = ($DeploySupplemental -or $Enforce) -and ($labIncluded -or $toolIncluded)

$SuppGuid = $null
$suppCount = 0
if ($buildSupplemental) {

    if (-not (Test-Path -LiteralPath $RepoSupplemental)) {
        throw "Hand-authored supplemental not found: $RepoSupplemental"
    }

    Write-Step "Preparing supplemental from hand-authored template."
    Copy-Item -LiteralPath $RepoSupplemental -Destination $SuppXml -Force -WhatIf:$false

    # The checked-in file must carry the spike's own PolicyID, never the service's.
    $repoSuppId = Get-PolicyIdFromXml -Path $SuppXml
    if ((ConvertTo-GuidKey $repoSuppId) -ne (ConvertTo-GuidKey $SpikeSupplementalPolicyId)) {
        throw "policy\WardenSpike.Supplemental.xml has PolicyID $repoSuppId, expected the spike's $SpikeSupplementalPolicyId."
    }
    if ((ConvertTo-GuidKey $repoSuppId) -eq (ConvertTo-GuidKey $ServiceSupplementalPolicyId)) {
        throw "Refused: the spike supplemental must not reuse the Warden service's PolicyID $ServiceSupplementalPolicyId."
    }

    # Point BasePolicyID at the spike base; set friendly Name/Id.
    $null = Set-CIPolicyIdInfo -FilePath $SuppXml -SupplementsBasePolicyID $BaseGuid
    $null = Set-CIPolicyIdInfo -FilePath $SuppXml -PolicyName 'Warden Spike Supplemental (Allow user binaries)' -PolicyId 'WardenSpikeSupplemental'

    # Re-assert the fixed PolicyID (defensive: some ConfigCI builds may rewrite it).
    $spId = Get-PolicyXml -Path $SuppXml
    $idNode = $spId.Doc.SelectSingleNode('/si:SiPolicy/si:PolicyID', $spId.Nsm)
    if ($idNode.InnerText.Trim() -ne $SpikeSupplementalPolicyId) {
        Write-Step "Re-asserting fixed supplemental PolicyID -> $SpikeSupplementalPolicyId"
        $idNode.InnerText = $SpikeSupplementalPolicyId
        $spId.Doc.Save($SuppXml)
    }

    # Fail LOUD if the base linkage did not take (an all-zeros BasePolicyID would
    # compile to an INERT supplemental that supplements nothing).
    $bpNode = $spId.Doc.SelectSingleNode('/si:SiPolicy/si:BasePolicyID', $spId.Nsm)
    $bpVal  = if ($bpNode) { $bpNode.InnerText.Trim() } else { '' }
    if (($bpVal -replace '[{}0\-]', '') -eq '') {
        throw "Supplemental BasePolicyID is empty/all-zeros after linkage ('$bpVal'). Refusing to deploy an inert supplemental."
    }

    # --- Regenerate the real allow hash(es) with New-CIPolicy -----------------
    # ISOLATED scan dir inside the admin-only work folder: only the pinned copies
    # are in it, so New-CIPolicy (which scans recursively) hashes exactly them.
    Write-Step "Computing Authenticode hash(es) via New-CIPolicy -Level Hash (isolated, pinned copies)."
    $scanDir = Join-Path $WorkDir '_scan'
    New-Item -ItemType Directory -Path $scanDir -Force -WhatIf:$false | Out-Null
    $copies = @()
    if ($labIncluded)  { $copies += Copy-PinnedBinary -Source $LabExePath -ExpectedSha256 $LabExeSha256 -DestinationDir $scanDir -Label 'lab exe' }
    if ($toolIncluded) { $copies += Copy-PinnedBinary -Source $WardenSpikeToolPath -ExpectedSha256 $WardenSpikeToolSha256 -DestinationDir $scanDir -Label 'reader tool' }
    $suppCount = $copies.Count
    $pins = @{}
    if ($labIncluded)  { $pins[(Join-Path $scanDir (Split-Path -Leaf $LabExePath))] = $LabExeSha256.ToUpperInvariant() }
    if ($toolIncluded) { $pins[(Join-Path $scanDir (Split-Path -Leaf $WardenSpikeToolPath))] = $WardenSpikeToolSha256.ToUpperInvariant() }

    $hashXml = Join-Path $WorkDir '_labhash.xml'
    # -UserPEs = user-mode PEs only; -NoScript = don't add script rules;
    # -MultiplePolicyFormat = emit multiple-policy-format rule IDs.
    New-CIPolicy -Level Hash -ScanPath $scanDir -UserPEs -NoScript -MultiplePolicyFormat -FilePath $hashXml -Fallback Hash 3>$null | Out-Null

    # The copies must still be the pinned bytes after New-CIPolicy hashed them.
    foreach ($copy in $pins.Keys) {
        $now = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash
        if ($now -ne $pins[$copy]) { throw "Refused: $copy changed while New-CIPolicy hashed it." }
    }
    $extra = @(Get-ChildItem -LiteralPath $scanDir -Recurse -Force -File | Where-Object { -not $pins.ContainsKey($_.FullName) })
    if ($extra.Count -gt 0) { throw "Refused: unexpected file(s) in the scan folder: $($extra.FullName -join ', ')" }

    $hp = Get-PolicyXml -Path $hashXml
    # SHA-256 hashes are 64 hex chars (Authenticode SHA256 + first-page SHA256).
    $sha256Allows = @($hp.Doc.SelectNodes('//si:FileRules/si:Allow', $hp.Nsm) |
        Where-Object { $_.Hash -and $_.Hash.Length -eq 64 })
    if ($sha256Allows.Count -eq 0) {
        throw "New-CIPolicy produced no SHA-256 hash rules for the scan targets (are they valid PEs?)."
    }
    Write-Step "Found $($sha256Allows.Count) SHA-256 hash rule(s) across $suppCount pinned target(s)."

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

    Set-NextPolicyVersion -Path $SuppXml -PolicyId $SpikeSupplementalPolicyId

    $SuppGuid = Get-PolicyIdFromXml -Path $SuppXml
    Write-Step "Supplemental PolicyID: $SuppGuid  (BasePolicyID -> $BaseGuid)"

    $SuppCip = Build-Cip -XmlPath $SuppXml
    Deploy-Cip -CipPath $SuppCip -Label "SUPPLEMENTAL (allow $suppCount pinned user binary/ies)"
}

# ----------------------------------------------------------------------------
# 3. Summary + ROLLBACK commands (always printed)
# ----------------------------------------------------------------------------
Write-Host ''
Write-Ok  '================ Warden spike deployment summary ================'
Write-Host "  Base policy      : $BaseGuid   ($(if($Enforce){'ENFORCE / 3077'}else{'AUDIT / 3076'}))" -ForegroundColor Green
if ($SuppGuid) {
    Write-Host "  Supplemental     : $SuppGuid   (allows $suppCount pinned user binary/ies by hash)" -ForegroundColor Green
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
