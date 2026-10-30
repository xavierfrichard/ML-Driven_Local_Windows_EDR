<#
.SYNOPSIS
    Stops and removes the Warden zero-trust agent.

.DESCRIPTION
    Stops and deletes the WardenAgent service, removes the machine-scoped configuration variables and the
    tray-UI logon task, removes the install directory, and (with -RemoveData) removes the locked data
    directory. Run elevated, from 64-bit Windows PowerShell started with -NoProfile, on the target
    machine / in the VM.

    Destructive operations are confined to directories under Program Files / ProgramData (resolved from
    HKLM, not from environment variables) and are confirmed unless -Force is given. Right before each
    directory is removed - after the confirmation prompt - the whole tree is checked again: if anything
    in it is a junction, symbolic link, mount point or hard link, or is owned or writable by anyone other
    than SYSTEM / Administrators / TrustedInstaller, nothing is removed. The removal itself walks the tree
    without following links and deletes one entry at a time; it never runs a recursive takeown, icacls or
    Remove-Item that could follow a junction.

    Not removed (see installer\README.md): the deployed WDAC supplemental policy, firewall rules, IFEO /
    exploit-protection settings and ASR rule changes made from the UI.

.PARAMETER ServiceName
    The Windows service name. Default: WardenAgent.

.PARAMETER InstallDir
    Where the binaries were installed. Default: <Program Files>\Warden.

.PARAMETER DataDir
    The agent's data directory. Default: the service's WARDEN_DATA_DIR, else the WARDEN_DATA_DIR machine
    variable, else <ProgramData>\Warden.

.PARAMETER RemoveData
    Also delete the data directory (database, quarantine, logs). Off by default.

.PARAMETER Force
    Skip the confirmation prompts.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string] $ServiceName = 'WardenAgent',
    [string] $InstallDir,
    [string] $DataDir,
    [switch] $RemoveData,
    [switch] $Force
)

$ErrorActionPreference = 'Continue'

# ---- trusted roots (never from user-overridable environment variables) ------------------------------------
$SystemDir = [Environment]::SystemDirectory
$SystemDrive = [IO.Path]::GetPathRoot($SystemDir).TrimEnd('\')

function Get-ProgramFilesRoot {
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'Run uninstall.ps1 from 64-bit PowerShell.'
    }
    $reg = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' -Name ProgramFilesDir).ProgramFilesDir
    $known = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if (-not $reg -or ($reg.TrimEnd('\') -ne $known.TrimEnd('\'))) {
        throw "Program Files location differs between HKLM ('$reg') and the known-folder API ('$known'); refusing."
    }
    return $reg.TrimEnd('\')
}

function Get-ProgramDataRoot {
    $key = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $raw = $key.GetValue('ProgramData', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if (-not $raw) { throw 'Cannot read the ProgramData location from HKLM.' }
    $expanded = ([string]$raw).Replace('%SystemDrive%', $SystemDrive).Replace('%SYSTEMDRIVE%', $SystemDrive)
    if ($expanded.Contains('%')) { throw "Unexpected ProgramData value in HKLM: '$raw'." }
    $known = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ($expanded.TrimEnd('\') -ne $known.TrimEnd('\')) {
        throw "ProgramData location differs between HKLM ('$expanded') and the known-folder API ('$known'); refusing."
    }
    return $expanded.TrimEnd('\')
}

$ErrorActionPreference = 'Stop'
$ProgramFilesRoot = Get-ProgramFilesRoot
$ProgramDataRoot = Get-ProgramDataRoot
$ErrorActionPreference = 'Continue'

$env:PSModulePath = (Join-Path $PSHOME 'Modules') + ';' + (Join-Path $ProgramFilesRoot 'WindowsPowerShell\Modules')
$ScExe = Join-Path $SystemDir 'sc.exe'
$TakeownExe = Join-Path $SystemDir 'takeown.exe'
$Icacls = Join-Path $SystemDir 'icacls.exe'

if (-not $InstallDir) { $InstallDir = Join-Path $ProgramFilesRoot 'Warden' }

$SidAdmins = 'S-1-5-32-544'
$TrustedSids = @('S-1-5-18', $SidAdmins, 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$CreatorSids = @('S-1-3-0', 'S-1-3-1')
$ContentWriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
$FileAttributeReparsePoint = 0x400
$MaxTreeEntries = 200000

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'uninstall.ps1 must be run from an elevated (Administrator) PowerShell.'
    }
}

function Resolve-Full([string] $p) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }

function Get-AdminMemberSids {
    try { return @(Get-LocalGroupMember -SID $SidAdmins -ErrorAction Stop | ForEach-Object { $_.SID.Value }) }
    catch { return @() }
}

function Read-Security([IO.FileSystemInfo] $Item) {
    $sections = [Security.AccessControl.AccessControlSections]'Owner, Access'
    if ($Item -is [IO.DirectoryInfo]) { return [IO.Directory]::GetAccessControl($Item.FullName, $sections) }
    return [IO.File]::GetAccessControl($Item.FullName, $sections)
}

function Get-SecurityProblem([IO.FileSystemInfo] $Item, [string[]] $TrustedOwners) {
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
        if ((([int]$rule.FileSystemRights) -band $ContentWriteMask) -eq 0) { continue }
        $sid = $rule.IdentityReference.Value
        if (($TrustedSids -contains $sid) -or ($CreatorSids -contains $sid)) { continue }
        $out += "$($Item.FullName) lets $sid write to it or change its permissions."
    }
    return $out
}

function Test-Redirect([IO.FileSystemInfo] $Item) {
    if (((([int]$Item.Attributes) -band $FileAttributeReparsePoint) -ne 0)) { return 'is a junction, symbolic link or mount point' }
    if ($Item -is [IO.FileInfo]) {
        try { if ($Item.LinkType -eq 'HardLink') { return 'has several hard links' } }
        catch { return 'could not be checked for hard links' }
    }
    return $null
}

# Every entry under $Dir, parents before children, never following a junction or symlink. Problems
# (redirects, unreadable folders, too many entries) are collected, never skipped silently.
function Get-TreeEntries([string] $Dir, [System.Collections.Generic.List[string]] $Problems) {
    $entries = New-Object 'System.Collections.Generic.List[System.IO.FileSystemInfo]'
    $pending = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
    $pending.Push((New-Object IO.DirectoryInfo $Dir))
    while ($pending.Count -gt 0) {
        $d = $pending.Pop()
        try { $children = $d.GetFileSystemInfos() }
        catch { $Problems.Add("$($d.FullName) could not be listed ($($_.Exception.GetType().Name))."); continue }
        foreach ($e in $children) {
            if ($entries.Count -ge $MaxTreeEntries) { $Problems.Add("$Dir holds more than $MaxTreeEntries entries."); return ,$entries }
            $why = Test-Redirect $e
            if ($why) { $Problems.Add("$($e.FullName) $why."); continue }
            $entries.Add($e)
            if ($e -is [IO.DirectoryInfo]) { $pending.Push($e) }
        }
    }
    return ,$entries
}

# Refuse to operate destructively on anything that is not a subdirectory of an expected root, is a link,
# or sits under a link: a typo or a hostile -DataDir must never turn this loose on C:\Windows.
function Assert-SafeTarget([string] $path, [string[]] $roots, [string] $what) {
    $full = (Resolve-Full $path).TrimEnd('\')
    if (([Uri]$full).IsUnc -or $full.StartsWith('\\')) { throw "$what must be a local path." }
    if ([System.IO.Path]::GetPathRoot($full).TrimEnd('\') -ieq $full) { throw "$what must not be a drive root." }
    $under = $false
    foreach ($r in $roots) {
        $rootFull = (Resolve-Full $r).TrimEnd('\') + '\'
        if ($full.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) { $under = $true }
    }
    if (-not $under) { throw "$what '$full' is not under any of: $($roots -join ', '). Refusing to remove it." }
    $item = New-Object IO.DirectoryInfo $full
    for ($d = $item; $d; $d = $d.Parent) {
        if ($d.Exists -and (Test-Redirect $d)) { throw "$what '$full': $($d.FullName) is a junction, symbolic link or mount point; refusing." }
    }
    if ([IO.File]::Exists($full)) { throw "$what '$full' is a file, not a directory; refusing." }
    return $full
}

# Deletes one entry that has just been checked again; never follows a link.
function Remove-OneEntry([IO.FileSystemInfo] $Entry) {
    $Entry.Refresh()
    if (-not $Entry.Exists) { return }
    $why = Test-Redirect $Entry
    if ($why) { throw "$($Entry.FullName) $why (appeared during removal); stopping." }
    try {
        if ($Entry -is [IO.DirectoryInfo]) { [IO.Directory]::Delete($Entry.FullName, $false) }
        else { [IO.File]::SetAttributes($Entry.FullName, [IO.FileAttributes]::Normal); [IO.File]::Delete($Entry.FullName) }
    } catch [UnauthorizedAccessException] {
        # This single entry only (no /R, no /T): take ownership, grant Administrators, retry.
        & $TakeownExe /F $Entry.FullName /A | Out-Null
        & $Icacls $Entry.FullName /grant "*${SidAdmins}:F" /L /Q | Out-Null
        if ($Entry -is [IO.DirectoryInfo]) { [IO.Directory]::Delete($Entry.FullName, $false) }
        else { [IO.File]::SetAttributes($Entry.FullName, [IO.FileAttributes]::Normal); [IO.File]::Delete($Entry.FullName) }
    }
}

function Remove-LockedTree([string] $dir, [string[]] $roots, [string] $what) {
    $first = Assert-SafeTarget $dir $roots $what
    if (-not [IO.Directory]::Exists($first)) { return }
    if (-not ($Force -or $PSCmdlet.ShouldProcess($first, "Remove $what recursively"))) { return }

    # M9: check again now, after the prompt, right before anything is changed.
    $safe = Assert-SafeTarget $dir $roots $what
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $root = New-Object IO.DirectoryInfo $safe
    foreach ($p in @(Get-SecurityProblem $root ($TrustedSids + $AdminMemberSids))) { $problems.Add($p) }
    $entries = Get-TreeEntries $safe $problems
    foreach ($e in $entries) {
        foreach ($p in @(Get-SecurityProblem $e ($TrustedSids + $AdminMemberSids))) { $problems.Add($p) }
    }
    if ($problems.Count -gt 0) {
        $shown = @($problems | Select-Object -First 10) -join ([Environment]::NewLine + '  ')
        throw ("Refusing to remove $what ${safe}: it is not controlled only by administrators or holds a link:" +
            [Environment]::NewLine + "  $shown" + [Environment]::NewLine +
            '  Inspect it and remove it by hand without following links.')
    }

    # Children before parents.
    for ($i = $entries.Count - 1; $i -ge 0; $i--) { Remove-OneEntry $entries[$i] }
    Remove-OneEntry $root
    Write-Host "Removed $what $safe"
}

Assert-Admin
$AdminMemberSids = Get-AdminMemberSids

# The data directory the service was actually using, read before the service (and its key) is deleted.
if (-not $DataDir) {
    $svcEnv = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name Environment -ErrorAction SilentlyContinue).Environment
    foreach ($entry in @($svcEnv)) {
        if ($entry -and $entry.StartsWith('WARDEN_DATA_DIR=', [StringComparison]::OrdinalIgnoreCase)) { $DataDir = $entry.Split('=', 2)[1] }
    }
}
if (-not $DataDir) { $DataDir = [Environment]::GetEnvironmentVariable('WARDEN_DATA_DIR', 'Machine') }
if (-not $DataDir) { $DataDir = Join-Path $ProgramDataRoot 'Warden' }

Write-Host "Stopping and deleting $ServiceName ..."
& $ScExe stop $ServiceName | Out-Null
if ($LASTEXITCODE -notin @(0, 1060, 1062)) { Write-Warning "sc stop returned $LASTEXITCODE." }   # 1060 no such service, 1062 not started
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    try { $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } catch { Write-Warning "$ServiceName did not stop within 30 s." }
}
& $ScExe delete $ServiceName | Out-Null
if ($LASTEXITCODE -notin @(0, 1060)) { Write-Warning "sc delete returned $LASTEXITCODE." }

Write-Host 'Removing machine configuration ...'
foreach ($name in 'WARDEN_ENFORCE_HARDENING', 'WARDEN_DATA_DIR', 'WARDEN_WDAC_BASE_POLICY_GUID') {
    [Environment]::SetEnvironmentVariable($name, $null, 'Machine')
}

Write-Host 'Removing the tray-UI logon task (if present) ...'
Unregister-ScheduledTask -TaskName 'WardenUi' -Confirm:$false -ErrorAction SilentlyContinue

# Binaries: always removed (they are ours). Confined to Program Files.
try {
    Remove-LockedTree $InstallDir @($ProgramFilesRoot) 'install directory'
} catch {
    Write-Warning $_
}

if ($RemoveData) {
    try {
        Remove-LockedTree $DataDir @($ProgramDataRoot) 'data directory'
    } catch {
        Write-Warning $_
    }
}

Write-Host 'Warden uninstalled. Not removed: the WDAC supplemental policy, firewall rules, IFEO and ASR changes (see installer\README.md).'
