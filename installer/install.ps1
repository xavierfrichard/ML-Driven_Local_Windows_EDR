<#
.SYNOPSIS
    Installs and hardens the Warden zero-trust agent (Windows service + self-protection).

.DESCRIPTION
    Copies the published binaries into an ACL-locked install directory under Program Files, creates the
    ACL-locked data directory, registers the WardenAgent service as LocalSystem (launched by the pinned,
    Microsoft-signed Program Files dotnet host), applies the hardened service security descriptor (so
    standard users cannot stop/delete it), configures restart-on-kill recovery, enables the startup ACL
    lockdown, and starts the service. Optionally registers the tray UI to launch (elevated) at logon.

    RUN THIS ONLY on the target machine / inside the Win11 test VM, elevated, from 64-bit Windows
    PowerShell started with -NoProfile. It makes real, machine-wide changes. The SDDL and sc.exe arguments
    below mirror Warden.Hardening.HardeningSddl / Warden.Hardening.ServiceHardener so the C# and the
    installer stay in lockstep.

    WHY THE COPY: a LocalSystem service loads its code from its binPath on every start (and on every
    restart-on-failure). If that directory is user-writable - a repo `out\` folder, a user profile - any
    local user can swap Warden.Service.dll for SYSTEM code execution. So the binaries are copied to a
    directory only SYSTEM/Administrators can write, and the service points there.

    TRUST ROOTS: Program Files and ProgramData are read from HKLM and the known-folder API, never from
    $env:ProgramFiles / $env:ProgramData (a user's HKCU\Environment can override those in an elevated
    session). System tools are run by full System32 path, and modules load only from $PSHOME and Program
    Files.

    PRE-EXISTING DIRECTORIES: standard users can create folders under C:\ProgramData. If the data or
    install directory already exists and anything in it (or it itself) is a junction, symlink, hard link,
    owned by someone other than SYSTEM/Administrators/TrustedInstaller, or writable by anyone else, it is
    renamed aside (<dir>.untrusted-<timestamp>, never recursed into) and a fresh directory is created
    with its owner and DACL set atomically.

.PARAMETER BinDir
    Directory containing the published Warden.Service.dll (from `dotnet publish`). Copied to InstallDir\service.

.PARAMETER InstallDir
    Where the binaries live at run time. Default: <Program Files>\Warden. Must be under Program Files
    unless -AllowUnprotectedInstallDir is given.

.PARAMETER DataDir
    The agent's data directory. Default: <ProgramData>\Warden. Must be under ProgramData unless
    -AllowUnprotectedDataDir is given. Given to the service through its own registry Environment value
    (WARDEN_DATA_DIR) so every module (database, quarantine, WDAC work dir, snapshots, logs) and the
    hardener use it from the first start.

.PARAMETER ServiceName
    The Windows service name. Default: WardenAgent.

.PARAMETER UiDir
    Optional directory of the published tray UI (contains Warden.Ui.exe). Copied to InstallDir\ui and
    registered to launch elevated at logon.

.PARAMETER UiExe
    Back-compat alias: path to a published Warden.Ui.exe; its directory is used as -UiDir.

.PARAMETER DotnetHost
    Path to dotnet.exe. Default: <Program Files>\dotnet\dotnet.exe. Must be under Program Files unless
    -AllowUnpinnedDotnet is given. In every case it must carry a valid Microsoft Authenticode signature,
    and it, its folder, its parent folders, host\fxr and shared\Microsoft.NETCore.App must be owned and
    writable only by SYSTEM, Administrators or TrustedInstaller.

.PARAMETER WdacBasePolicyGuid
    Optional GUID of the machine's WDAC base policy the Warden supplemental attaches to (published as
    WARDEN_WDAC_BASE_POLICY_GUID). When omitted the service discovers it at run time.

.PARAMETER ManifestPath
    Optional SHA-256 manifest of every file in BinDir and UiDir (lines "<sha256>  service\<file>" /
    "<sha256>  ui\<file>", as written by -WriteManifest). Both trees are checked against it before and
    after the copy; any missing, extra or different file stops the install. The manifest itself must be
    in a folder only administrators can write.

.PARAMETER SignerThumbprint
    Optional SHA-1 thumbprint of the certificate sign.ps1 used. Every Warden*.dll / Warden*.exe in BinDir
    and UiDir must carry a valid Authenticode signature from exactly that certificate, before and after
    the copy. (Third-party DLLs are not signed by sign.ps1: use -ManifestPath to cover them too.)

.PARAMETER WriteManifest
    Write the SHA-256 manifest of BinDir (and UiDir) to this path and exit without installing anything.
    Run it right after a trusted build.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BinDir,
    [string] $InstallDir,
    [string] $DataDir,
    [string] $ServiceName = 'WardenAgent',
    [string] $UiDir,
    [string] $UiExe,
    [string] $DotnetHost,
    [string] $WdacBasePolicyGuid,
    [string] $ManifestPath,
    [string] $SignerThumbprint,
    [string] $WriteManifest,
    [switch] $AllowUnprotectedInstallDir,
    [switch] $AllowUnprotectedDataDir,
    [switch] $AllowUnpinnedDotnet
)

$ErrorActionPreference = 'Stop'

# ---- trusted roots (never from user-overridable environment variables) ------------------------------------
$SystemDir = [Environment]::SystemDirectory                 # GetSystemDirectory(): not read from the environment
$SystemDrive = [IO.Path]::GetPathRoot($SystemDir).TrimEnd('\')

function Get-ProgramFilesRoot {
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'Run install.ps1 from 64-bit PowerShell (32-bit PowerShell sees the x86 Program Files folder).'
    }
    $reg = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' -Name ProgramFilesDir).ProgramFilesDir
    $known = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if (-not $reg -or ($reg.TrimEnd('\') -ne $known.TrimEnd('\'))) {
        throw "Program Files location differs between HKLM ('$reg') and the known-folder API ('$known'); refusing."
    }
    return $reg.TrimEnd('\')
}

function Get-ProgramDataRoot {
    # Stored as %SystemDrive%\ProgramData; expand it from GetSystemDirectory, not from the environment.
    $key = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $raw = $key.GetValue('ProgramData', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if (-not $raw) { throw 'Cannot read the ProgramData location from HKLM.' }
    $expanded = ([string]$raw).Replace('%SystemDrive%', $SystemDrive).Replace('%SYSTEMDRIVE%', $SystemDrive)
    if ($expanded.Contains('%')) { throw "Unexpected ProgramData value in HKLM: '$raw'." }
    $known = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ($expanded.TrimEnd('\') -ne $known.TrimEnd('\')) {
        throw "ProgramData location differs between HKLM ('$expanded') and the known-folder API ('$known'); is %SystemDrive% overridden? Refusing."
    }
    return $expanded.TrimEnd('\')
}

$ProgramFilesRoot = Get-ProgramFilesRoot
$ProgramDataRoot = Get-ProgramDataRoot

# Modules load only from this PowerShell's own folder and Program Files, never the user's Documents.
$env:PSModulePath = (Join-Path $PSHOME 'Modules') + ';' + (Join-Path $ProgramFilesRoot 'WindowsPowerShell\Modules')

$Icacls = Join-Path $SystemDir 'icacls.exe'
$Robocopy = Join-Path $SystemDir 'robocopy.exe'
$ScExe = Join-Path $SystemDir 'sc.exe'

if (-not $InstallDir) { $InstallDir = Join-Path $ProgramFilesRoot 'Warden' }
if (-not $DataDir) { $DataDir = Join-Path $ProgramDataRoot 'Warden' }
if (-not $DotnetHost) { $DotnetHost = Join-Path $ProgramFilesRoot 'dotnet\dotnet.exe' }

# ---- security constants ---------------------------------------------------------------------------------
$SidSystem = 'S-1-5-18'
$SidAdmins = 'S-1-5-32-544'
$SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$TrustedSids = @($SidSystem, $SidAdmins, $SidTrustedInstaller)
$CreatorSids = @('S-1-3-0', 'S-1-3-1')   # CREATOR OWNER / CREATOR GROUP placeholders

# Rights that let the holder change what is in a folder or file: write/append data, write EA/attributes,
# delete child, delete, write DAC, write owner, GENERIC_ALL, GENERIC_WRITE.
$ContentWriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
# Rights on a parent folder that let the holder move a child aside and recreate it.
$AncestorReplaceMask = 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000
$FileAttributeReparsePoint = 0x400
$MaxTreeEntries = 200000

# Mirrors HardeningSddl.DataDirectoryDacl (+ owner Administrators). The install dir also lets Users read/execute.
$DataDirSddl = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$InstallDirSddl = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'

# Mirrors HardeningSddl.ServiceDacl - SYSTEM + Administrators full control; Authenticated Users may only
# query (no start/stop/change-config/delete).
$ServiceDacl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)'

# Roots the dotnet.exe signature must chain to.
$MicrosoftRootThumbprints = @(
    '8F43288AD272F3103B6FB1428485EA3014C0BCFE',   # Microsoft Root Certificate Authority 2011
    '3B1EFD3A66EA28B16697394703A72CA340A05BD5',   # Microsoft Root Certificate Authority 2010
    'CDD4EEAE6000AC7F40C3802C171E30148030C072'    # Microsoft Root Certificate Authority
)

# ---- helpers ----------------------------------------------------------------------------------------------
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'install.ps1 must be run from an elevated (Administrator) PowerShell.'
    }
}

# Resolve against PowerShell's current location (not the process CWD, which PowerShell does not keep in
# sync after `cd`) without requiring the path to exist yet.
function Resolve-Full([string] $p) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }

function Assert-Under([string] $path, [string] $root, [string] $what, [switch] $Allowed) {
    $full = (Resolve-Full $path).TrimEnd('\')
    $rootFull = (Resolve-Full $root).TrimEnd('\') + '\'
    if (([Uri]$full).IsUnc -or $full.StartsWith('\\')) { throw "$what must be a local path, not UNC." }
    if ([System.IO.Path]::GetPathRoot($full).TrimEnd('\') -ieq $full) { throw "$what must not be a drive root." }
    if (-not $full.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not $Allowed) {
            throw "$what '$full' is not under '$rootFull'. A LocalSystem service must not depend on a user-writable location; pass the matching -Allow* switch only if you know why."
        }
        Write-Warning "$what '$full' is outside '$rootFull' - make sure standard users cannot write to it or its parent folders."
    }
    return $full
}

function Invoke-Native([string] $exe, [string[]] $arguments, [string] $what, [int[]] $okCodes = @(0)) {
    & $exe @arguments | Out-Null
    if ($okCodes -notcontains $LASTEXITCODE) { throw "$what failed ($([IO.Path]::GetFileName($exe)) exit $LASTEXITCODE)." }
}

# Members of the local Administrators group (as owners they are as trusted as the group itself).
function Get-AdminMemberSids {
    try { return @(Get-LocalGroupMember -SID $SidAdmins -ErrorAction Stop | ForEach-Object { $_.SID.Value }) }
    catch { return @() }
}

function Read-Security([IO.FileSystemInfo] $Item) {
    $sections = [Security.AccessControl.AccessControlSections]'Owner, Access'
    if ($Item -is [IO.DirectoryInfo]) { return [IO.Directory]::GetAccessControl($Item.FullName, $sections) }
    return [IO.File]::GetAccessControl($Item.FullName, $sections)
}

# Problems with one object's owner and allow entries. $Mask selects the rights that count.
function Get-SecurityProblem([IO.FileSystemInfo] $Item, [int] $Mask, [string[]] $TrustedOwners, [switch] $SkipInheritOnly) {
    $out = @()
    try { $sec = Read-Security $Item }
    catch { return @("The permissions of $($Item.FullName) could not be read ($($_.Exception.GetType().Name)).") }
    $owner = $sec.GetOwner([Security.Principal.SecurityIdentifier])
    if (-not $owner -or ($TrustedOwners -notcontains $owner.Value)) {
        $ownerText = 'nobody'
        if ($owner) { $ownerText = $owner.Value }
        $out += "$($Item.FullName) is owned by $ownerText."
    }
    foreach ($rule in $sec.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($SkipInheritOnly -and ((([int]$rule.PropagationFlags) -band 2) -ne 0)) { continue }   # InheritOnly
        if ((([int]$rule.FileSystemRights) -band $Mask) -eq 0) { continue }
        $sid = $rule.IdentityReference.Value
        if (($TrustedSids -contains $sid) -or ($CreatorSids -contains $sid)) { continue }
        $out += "$($Item.FullName) lets $sid write to it or change its permissions."
    }
    return $out
}

# A junction / symlink / mount point, or a file with several hard links: either would redirect writes or
# ACL changes to an object somewhere else. Returns a reason or $null.
function Test-Redirect([IO.FileSystemInfo] $Item) {
    if (((([int]$Item.Attributes) -band $FileAttributeReparsePoint) -ne 0)) { return 'is a junction, symbolic link or mount point' }
    if ($Item -is [IO.FileInfo]) {
        try { if ($Item.LinkType -eq 'HardLink') { return 'has several hard links' } }
        catch { return 'could not be checked for hard links' }
    }
    return $null
}

# Every file and folder under $Dir, top-down, without ever following a junction or symlink.
# Calls $Visit for each entry; a redirect is reported through $OnRedirect and never descended into.
function Invoke-TreeWalk([string] $Dir, [scriptblock] $Visit, [scriptblock] $OnProblem) {
    $pending = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
    $pending.Push((New-Object IO.DirectoryInfo $Dir))
    $seen = 0
    while ($pending.Count -gt 0) {
        $d = $pending.Pop()
        try { $entries = $d.GetFileSystemInfos() }
        catch { & $OnProblem "$($d.FullName) could not be listed ($($_.Exception.GetType().Name))."; continue }
        foreach ($e in $entries) {
            $seen++
            if ($seen -gt $MaxTreeEntries) { & $OnProblem "$Dir holds more than $MaxTreeEntries entries; too many to verify."; return }
            $why = Test-Redirect $e
            if ($why) { & $OnProblem "$($e.FullName) $why."; continue }
            & $Visit $e
            if ($e -is [IO.DirectoryInfo]) { $pending.Push($e) }
        }
    }
}

# Problems anywhere in a tree: redirects, untrusted owners, untrusted writers.
function Find-TreeProblems([string] $Dir, [string[]] $TrustedOwners) {
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $root = New-Object IO.DirectoryInfo $Dir
    $why = Test-Redirect $root
    if ($why) { return @("$Dir $why.") }
    foreach ($p in @(Get-SecurityProblem $root $ContentWriteMask $TrustedOwners)) { $problems.Add($p) }
    Invoke-TreeWalk $Dir {
        param($e)
        foreach ($p in @(Get-SecurityProblem $e $ContentWriteMask $TrustedOwners)) { $problems.Add($p) }
    } {
        param($p)
        $problems.Add($p)
    }
    return $problems.ToArray()
}

# Parent folders up to the volume root: no redirect, and nobody else can move the child aside.
function Find-AncestorProblems([string] $Path, [switch] $RedirectsOnly) {
    $out = @()
    $d = (New-Object IO.DirectoryInfo $Path).Parent
    while ($d) {
        $why = Test-Redirect $d
        if ($why) { $out += "$($d.FullName) $why." }
        elseif (-not $RedirectsOnly) { $out += @(Get-SecurityProblem $d $AncestorReplaceMask $TrustedSids -SkipInheritOnly) }
        $d = $d.Parent
    }
    return $out
}

function Join-Problems([string[]] $problems) {
    $shown = @($problems | Select-Object -First 10)
    $more = ''
    if ($problems.Count -gt 10) { $more = " (+$($problems.Count - 10) more)" }
    return (($shown -join [Environment]::NewLine + '  ') + $more)
}

# H4: make $Dir a directory owned by Administrators with exactly the DACL in $Sddl.
# - An existing directory that anyone else controls (or that is or holds a redirect) is renamed aside,
#   never recursed into, and a fresh one is created with its owner and DACL set atomically.
# - An existing directory that only administrators control (an earlier install) keeps its contents; its
#   owners are normalised to Administrators and its DACL replaced (not merged).
# - The result is verified.
function Initialize-LockedDirectory([string] $Dir, [string] $Sddl, [string] $What, [switch] $AllowUnprotectedParents) {
    $ancestorRedirects = @(Find-AncestorProblems $Dir -RedirectsOnly)
    if ($ancestorRedirects.Count -gt 0) { throw "$What ${Dir}: a parent folder is a redirect: $(Join-Problems $ancestorRedirects)" }
    $ancestorProblems = @(Find-AncestorProblems $Dir)
    if ($ancestorProblems.Count -gt 0) {
        if (-not $AllowUnprotectedParents) { throw "$What ${Dir}: someone else can replace a parent folder: $(Join-Problems $ancestorProblems)" }
        Write-Warning "$What ${Dir}: $(Join-Problems $ancestorProblems)"
    }

    $item = New-Object IO.DirectoryInfo $Dir
    $isFile = [IO.File]::Exists($Dir)
    if ($item.Exists -or $isFile) {
        $problems = @()
        if ($isFile) { $problems = @("$Dir is a file.") }
        else { $problems = @(Find-TreeProblems $Dir ($TrustedSids + $AdminMemberSids)) }
        if ($problems.Count -gt 0) {
            $aside = '{0}.untrusted-{1}' -f $Dir, (Get-Date -Format 'yyyyMMdd-HHmmss')
            Write-Warning ("$What $Dir already existed and is not controlled only by administrators:" + [Environment]::NewLine +
                "  $(Join-Problems $problems)" + [Environment]::NewLine +
                "  Renaming it to $aside (its contents are not touched). Inspect it, then delete it.")
            # Renames the entry itself: a junction is moved as a link, its target is never touched.
            if ($isFile) { [IO.File]::Move($Dir, $aside) } else { [IO.Directory]::Move($Dir, $aside) }
        } else {
            # Only administrators control it (an earlier install): normalise owners; /L acts on links themselves.
            Invoke-Native $Icacls @($Dir, '/setowner', "*$SidAdmins", '/T', '/C', '/L', '/Q') "Setting the owner of $Dir"
        }
    }

    $sec = New-Object Security.AccessControl.DirectorySecurity
    $sec.SetSecurityDescriptorSddlForm($Sddl, [Security.AccessControl.AccessControlSections]'Owner, Access')
    $item.Refresh()
    if ($item.Exists) {
        # Replaces the DACL outright; icacls /grant:r would have kept other explicit entries.
        [IO.Directory]::SetAccessControl($Dir, $sec)
    } else {
        # Owner and DACL are set at creation: there is no moment at which anyone else can open it.
        [void][IO.Directory]::CreateDirectory($Dir, $sec)
    }

    # Verify. Someone may have created the directory between the rename and the creation above.
    $item.Refresh()
    $after = @(Find-TreeProblems $Dir $TrustedSids)
    $rootSec = Read-Security $item
    if ($rootSec.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $SidAdmins) { $after += "$Dir is not owned by Administrators." }
    if (-not $rootSec.AreAccessRulesProtected) { $after += "$Dir still inherits permissions from its parent." }
    if ($after.Count -gt 0) { throw "$What $Dir could not be locked: $(Join-Problems $after)" }
}

function Get-TreeFileHashes([string] $Dir, [string] $Prefix) {
    $map = @{}
    $rootFull = (New-Object IO.DirectoryInfo $Dir).FullName.TrimEnd('\')
    $problems = New-Object 'System.Collections.Generic.List[string]'
    if (Test-Redirect (New-Object IO.DirectoryInfo $Dir)) { throw "$Dir is a junction or symbolic link." }
    Invoke-TreeWalk $Dir {
        param($e)
        if ($e -is [IO.FileInfo]) {
            $rel = $Prefix + '\' + $e.FullName.Substring($rootFull.Length).TrimStart('\')
            $map[$rel] = (Get-FileHash -LiteralPath $e.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        }
    } {
        param($p)
        $problems.Add($p)
    }
    if ($problems.Count -gt 0) { throw "Cannot hash ${Dir}: $(Join-Problems $problems.ToArray())" }
    return $map
}

function Read-Manifest([string] $Path) {
    $map = @{}
    $lineNo = 0
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $lineNo++
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        if ($t -notmatch '^([0-9A-Fa-f]{64}) [ *]?(.+)$') { throw "Manifest line $lineNo is not '<sha256>  <path>'." }
        $hash = $Matches[1].ToUpperInvariant()
        $rel = $Matches[2].Trim().Replace('/', '\')
        $segments = $rel.Split('\')
        if (($segments[0] -notin @('service', 'ui')) -or ($segments -contains '..') -or ($segments -contains '.') -or $rel.Contains(':') -or ($segments -contains '')) {
            throw "Manifest line ${lineNo}: '$rel' must be a relative path under service\ or ui\."
        }
        if ($map.ContainsKey($rel)) { throw "Manifest lists '$rel' twice." }
        $map[$rel] = $hash
    }
    if ($map.Count -eq 0) { throw "Manifest $Path is empty." }
    return $map
}

function Assert-MatchesManifest([hashtable] $Expected, [hashtable] $Actual, [string] $Prefix, [string] $When) {
    $problems = @()
    foreach ($rel in $Actual.Keys) {
        if (-not $Expected.ContainsKey($rel)) { $problems += "$rel is not in the manifest" }
        elseif ($Expected[$rel] -ne $Actual[$rel]) { $problems += "$rel does not match the manifest" }
    }
    foreach ($rel in $Expected.Keys) {
        if ($rel.StartsWith($Prefix + '\', [StringComparison]::OrdinalIgnoreCase) -and -not $Actual.ContainsKey($rel)) {
            $problems += "$rel is missing"
        }
    }
    if ($problems.Count -gt 0) { throw "Binary verification failed $When ($Prefix): $(Join-Problems $problems)" }
}

function Assert-WardenSignatures([string] $Dir, [string] $Thumbprint, [string] $When) {
    $files = New-Object 'System.Collections.Generic.List[string]'
    Invoke-TreeWalk $Dir {
        param($e)
        if (($e -is [IO.FileInfo]) -and ($e.Name -match '^Warden.*\.(dll|exe)$')) { $files.Add($e.FullName) }
    } {
        param($p)
        throw "Cannot check signatures in ${Dir}: $p"
    }
    if ($files.Count -eq 0) { throw "No Warden*.dll / Warden*.exe found in $Dir." }
    $problems = @()
    foreach ($f in $files) {
        $sig = Get-AuthenticodeSignature -LiteralPath $f
        if ($sig.Status -ne 'Valid') { $problems += "$f signature is $($sig.Status)"; continue }
        if ($sig.SignerCertificate.Thumbprint -ne $Thumbprint) { $problems += "$f is signed by $($sig.SignerCertificate.Thumbprint), not $Thumbprint" }
    }
    if ($problems.Count -gt 0) { throw "Signature verification failed ${When}: $(Join-Problems $problems)" }
}

function Assert-Binaries([string] $Dir, [string] $Prefix, [string] $When) {
    if ($script:Manifest) { Assert-MatchesManifest $script:Manifest (Get-TreeFileHashes $Dir $Prefix) $Prefix $When }
    if ($SignerThumbprint) { Assert-WardenSignatures $Dir $SignerThumbprint $When }
}

# M8: the host every start of the LocalSystem service runs through.
function Assert-TrustedDotnetHost([string] $Path) {
    $f = New-Object IO.FileInfo $Path
    if (-not $f.Exists) { throw "dotnet host not found at $Path. Install the .NET 8 runtime for all users, or pass -DotnetHost." }
    $problems = @()
    $why = Test-Redirect $f
    if ($why) { $problems += "$Path $why." }
    $problems += @(Get-SecurityProblem $f $ContentWriteMask $TrustedSids)
    $problems += @(Get-SecurityProblem $f.Directory $ContentWriteMask $TrustedSids)
    $problems += @(Find-AncestorProblems $f.DirectoryName)
    foreach ($sub in @('host\fxr', 'shared\Microsoft.NETCore.App')) {
        $p = Join-Path $f.DirectoryName $sub
        if ([IO.Directory]::Exists($p)) { $problems += @(Find-TreeProblems $p $TrustedSids) }
    }
    if ($problems.Count -gt 0) {
        throw "The dotnet host is not controlled only by SYSTEM/Administrators/TrustedInstaller: $(Join-Problems $problems)"
    }

    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid') { throw "$Path has no valid Authenticode signature ($($sig.Status))." }
    if ($sig.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "$Path is not signed by Microsoft (signer: $($sig.SignerCertificate.Subject))."
    }
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    [void]$chain.Build($sig.SignerCertificate)
    $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
    if ($MicrosoftRootThumbprints -notcontains $root) { throw "$Path signature does not chain to a Microsoft root (root $root)." }
}

function Copy-Tree([string] $from, [string] $to) {
    # /MIR keeps the target an exact copy; /XJ never follows junctions or symlinks in the source.
    & $Robocopy $from $to /MIR /XJ /NFL /NDL /NJH /NJS /NP /R:2 /W:1 | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed copying $from -> $to (exit $LASTEXITCODE)." }
}

# ---- validate inputs ------------------------------------------------------------------------------------
$BinDir = (Resolve-Full $BinDir).TrimEnd('\')
$serviceDll = Join-Path $BinDir 'Warden.Service.dll'
if (-not (Test-Path -LiteralPath $serviceDll)) { throw "Warden.Service.dll not found in $BinDir. Run 'dotnet publish' first." }

if ($UiExe -and -not $UiDir) { $UiDir = Split-Path -Parent (Resolve-Full $UiExe) }
if ($UiDir) {
    $UiDir = (Resolve-Full $UiDir).TrimEnd('\')
    if (-not (Test-Path -LiteralPath (Join-Path $UiDir 'Warden.Ui.exe'))) { throw "Warden.Ui.exe not found in $UiDir." }
}

if ($WriteManifest) {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $all = Get-TreeFileHashes $BinDir 'service'
    if ($UiDir) { $ui = Get-TreeFileHashes $UiDir 'ui'; foreach ($k in $ui.Keys) { $all[$k] = $ui[$k] } }
    foreach ($k in ($all.Keys | Sort-Object)) { $lines.Add(('{0}  {1}' -f $all[$k], $k)) }
    [IO.File]::WriteAllLines((Resolve-Full $WriteManifest), $lines.ToArray(), (New-Object Text.UTF8Encoding($false)))
    Write-Host "Wrote $($lines.Count) entries to $WriteManifest. Keep it where only administrators can write, and pass it as -ManifestPath."
    return
}

Assert-Admin
$AdminMemberSids = Get-AdminMemberSids

$InstallDir = Assert-Under $InstallDir $ProgramFilesRoot 'InstallDir' -Allowed:$AllowUnprotectedInstallDir
$DataDir    = Assert-Under $DataDir    $ProgramDataRoot  'DataDir'    -Allowed:$AllowUnprotectedDataDir
$DotnetHost = Assert-Under $DotnetHost $ProgramFilesRoot 'DotnetHost' -Allowed:$AllowUnpinnedDotnet
Assert-TrustedDotnetHost $DotnetHost

if ($WdacBasePolicyGuid) {
    $g = [Guid]::Empty
    if (-not [Guid]::TryParse($WdacBasePolicyGuid.Trim('{', '}'), [ref] $g) -or $g -eq [Guid]::Empty) {
        throw "-WdacBasePolicyGuid '$WdacBasePolicyGuid' is not a valid, non-empty GUID."
    }
    $WdacBasePolicyGuid = '{' + $g.ToString().ToUpperInvariant() + '}'
}

# ---- verify the binaries before touching anything ------------------------------------------------------
$script:Manifest = $null
if ($SignerThumbprint) {
    if ($SignerThumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw '-SignerThumbprint must be a 40-hex-character SHA-1 thumbprint.' }
    $SignerThumbprint = $SignerThumbprint.ToUpperInvariant()
}
if ($ManifestPath) {
    $ManifestPath = Resolve-Full $ManifestPath
    $mf = New-Object IO.FileInfo $ManifestPath
    if (-not $mf.Exists) { throw "Manifest $ManifestPath not found." }
    # A manifest anyone can edit verifies nothing.
    $mfProblems = @()
    $why = Test-Redirect $mf
    if ($why) { $mfProblems += "$ManifestPath $why." }
    $mfProblems += @(Get-SecurityProblem $mf $ContentWriteMask ($TrustedSids + $AdminMemberSids))
    $mfProblems += @(Get-SecurityProblem $mf.Directory $ContentWriteMask ($TrustedSids + $AdminMemberSids))
    $mfProblems += @(Find-AncestorProblems $mf.DirectoryName)
    if ($mfProblems.Count -gt 0) { throw "Move the manifest to a folder only administrators can write: $(Join-Problems $mfProblems)" }
    $script:Manifest = Read-Manifest $ManifestPath
}
if ($script:Manifest -or $SignerThumbprint) {
    Assert-Binaries $BinDir 'service' 'before the copy'
    if ($UiDir) { Assert-Binaries $UiDir 'ui' 'before the copy' }
} else {
    Write-Warning ('The binaries are NOT verified: pass -SignerThumbprint (after sign.ps1) and/or -ManifestPath ' +
        '(from install.ps1 -WriteManifest right after a trusted build). Anything that could write to ' +
        "$BinDir before now gets its code run as SYSTEM.")
}

# ---- 0) quiesce a previous install: the copy below overwrites files a running service/tray would lock ----
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host "Stopping running service $ServiceName ..."
    Stop-Service -Name $ServiceName -Force
    (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
$ui = Get-Process -Name 'Warden.Ui' -ErrorAction SilentlyContinue
if ($ui) {
    Write-Host 'Closing the running Warden tray UI ...'
    $ui | Stop-Process -Force
    Start-Sleep -Seconds 1
}

# ---- 1) install directory: lock it, copy into a staging folder inside it, verify, swap -----------------
Write-Host "Installing binaries to $InstallDir ..."
Initialize-LockedDirectory $InstallDir $InstallDirSddl 'InstallDir' -AllowUnprotectedParents:$AllowUnprotectedInstallDir

function Install-Tree([string] $from, [string] $name, [string] $prefix) {
    $final = Join-Path $InstallDir $name
    $stage = Join-Path $InstallDir ($name + '.staging')
    if ([IO.Directory]::Exists($stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
    Copy-Tree $from $stage
    # Files take the locked folder's inherited DACL; make Administrators their owner.
    Invoke-Native $Icacls @($stage, '/setowner', "*$SidAdmins", '/T', '/C', '/L', '/Q') "Setting the owner of $stage"
    if ($script:Manifest -or $SignerThumbprint) { Assert-Binaries $stage $prefix 'after the copy' }
    if ([IO.Directory]::Exists($final)) { Remove-Item -LiteralPath $final -Recurse -Force }
    Rename-Item -LiteralPath $stage -NewName $name
    return $final
}

$serviceDir = Install-Tree $BinDir 'service' 'service'
$uiTarget = $null
if ($UiDir) { $uiTarget = Install-Tree $UiDir 'ui' 'ui' }
$installedDll = Join-Path $serviceDir 'Warden.Service.dll'

# ---- 2) ACL-locked data directory (owner Administrators; SYSTEM + Administrators only; no inheritance) -----
Write-Host "Creating locked data directory $DataDir ..."
Initialize-LockedDirectory $DataDir $DataDirSddl 'DataDir' -AllowUnprotectedParents:$AllowUnprotectedDataDir

# ---- 3) register the service (LocalSystem, auto-start), pinned dotnet host, installed DLL ------------------
$binPath = '"{0}" "{1}"' -f $DotnetHost, $installedDll
if ($existing) {
    Write-Host "Service $ServiceName exists; updating its binPath ..."
    # CIM passes the path string verbatim; `sc.exe config binPath=` would mangle the embedded quotes
    # under Windows PowerShell 5.1's native-argument quoting.
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
    $r = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{ PathName = $binPath; StartMode = 'Automatic' }
    if ($r.ReturnValue -ne 0) { throw "Could not update the service binPath (Win32_Service.Change returned $($r.ReturnValue))." }
} else {
    Write-Host "Registering service $ServiceName ..."
    New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName 'Warden Zero-Trust Agent' `
        -StartupType Automatic `
        -Description 'Warden: local ML/LLM-driven zero-trust application control (WDAC-enforced).' | Out-Null
}

# ---- 4) harden who can control the service; restart-on-kill recovery ---------------------------------------
Write-Host 'Applying service security descriptor + recovery ...'
Invoke-Native $ScExe @('sdset', $ServiceName, $ServiceDacl) 'sc sdset'
Invoke-Native $ScExe @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/60000/restart/60000/restart/60000') 'sc failure'
Invoke-Native $ScExe @('failureflag', $ServiceName, '1') 'sc failureflag'

# ---- 5) configuration read by the service ----------------------------------------------------------------
# New machine environment variables only reach services after a reboot, so the service gets its settings
# from its own registry Environment value, which the SCM reads at every start. Entries this script does
# not manage (for example secrets added by Set-WardenSecret.ps1) are kept.
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$managed = @('WARDEN_DATA_DIR', 'WARDEN_ENFORCE_HARDENING', 'WARDEN_WDAC_BASE_POLICY_GUID')
$current = @()
$prop = Get-ItemProperty -LiteralPath $svcKey -Name Environment -ErrorAction SilentlyContinue
if ($prop) { $current = @($prop.Environment) }
$serviceEnv = @($current | Where-Object { $_ -and ($managed -notcontains ($_.Split('=', 2)[0])) })
$serviceEnv += "WARDEN_DATA_DIR=$DataDir"
$serviceEnv += 'WARDEN_ENFORCE_HARDENING=1'   # re-apply the ACL lockdown on every start
if ($WdacBasePolicyGuid) { $serviceEnv += "WARDEN_WDAC_BASE_POLICY_GUID=$WdacBasePolicyGuid" }
New-ItemProperty -LiteralPath $svcKey -Name Environment -PropertyType MultiString -Value ([string[]]$serviceEnv) -Force | Out-Null

# Machine scope too, for tools and the UI. WARDEN_ENFORCE_HARDENING is service-only: a machine-wide value
# would make every dev/console run re-ACL the data directory. Remove it if an older install set it.
[Environment]::SetEnvironmentVariable('WARDEN_DATA_DIR', $DataDir, 'Machine')
[Environment]::SetEnvironmentVariable('WARDEN_ENFORCE_HARDENING', $null, 'Machine')
if ($WdacBasePolicyGuid) {
    [Environment]::SetEnvironmentVariable('WARDEN_WDAC_BASE_POLICY_GUID', $WdacBasePolicyGuid, 'Machine')
}

# ---- 6) optionally register the tray UI to run (elevated) at logon ------------------------------------------
if ($uiTarget) {
    Write-Host 'Registering the tray UI to launch at logon ...'
    $action  = New-ScheduledTaskAction -Execute (Join-Path $uiTarget 'Warden.Ui.exe')
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    # Highest: the tray UI answers block prompts and edits policy over pipes that admit only elevated
    # callers (its manifest is requireAdministrator). At-logon tasks with RunLevel Highest start elevated
    # for administrator accounts without a UAC prompt; standard-user accounts do not get the tray.
    # Residual risk (see README): the task runs with the user's own environment, so anything running as
    # that user can set .NET loader variables for the next elevated start. No wrapper launcher is safe
    # here (cmd waits with a console window; start/ShellExecute, PowerShell and WSH all have their own
    # per-user hijack paths), so this is mitigated in the UI build (StartupHookSupport=false), not here.
    Register-ScheduledTask -TaskName 'WardenUi' -Action $action -Trigger $trigger -Settings $set -RunLevel Highest -Force | Out-Null
}

# ---- 7) start it -------------------------------------------------------------------------------------------
Write-Host "Starting $ServiceName ..."
Invoke-Native $ScExe @('start', $ServiceName) 'sc start' @(0, 1056)   # 1056: already running

# Bring the (elevated) tray up right away in this session so nobody has to log off/on to get it: the task
# runs as the interactive user at Highest run level, so this is the same thing the logon trigger would do.
if ($uiTarget) {
    Write-Host 'Starting the tray UI ...'
    Start-ScheduledTask -TaskName 'WardenUi' -ErrorAction SilentlyContinue
}

Write-Host "Warden installed and started. Verify with:  sc.exe qc $ServiceName  /  sc.exe sdshow $ServiceName"
Write-Host "  binaries: $InstallDir   data: $DataDir   host: $DotnetHost"
