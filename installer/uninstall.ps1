<#
.SYNOPSIS
    Stops and removes the Warden zero-trust agent.

.DESCRIPTION
    Stops and deletes the WardenAgent service, removes the machine-scoped configuration variables and the
    tray-UI logon task, removes the install directory, and (with -RemoveData) removes the locked data
    directory. Run elevated, on the target machine / in the VM.

    Destructive operations are confined to directories under %ProgramFiles% / %ProgramData% (or the paths
    recorded at install time) and are confirmed unless -Force is given.

.PARAMETER ServiceName
    The Windows service name. Default: WardenAgent.

.PARAMETER InstallDir
    Where the binaries were installed. Default: %ProgramFiles%\Warden.

.PARAMETER DataDir
    The agent's data directory. Default: the WARDEN_DATA_DIR machine variable, else %ProgramData%\Warden.

.PARAMETER RemoveData
    Also delete the data directory (database, quarantine, logs). Off by default.

.PARAMETER Force
    Skip the confirmation prompts.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string] $ServiceName = 'WardenAgent',
    [string] $InstallDir = (Join-Path $env:ProgramFiles 'Warden'),
    [string] $DataDir,
    [switch] $RemoveData,
    [switch] $Force
)

$ErrorActionPreference = 'Continue'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'uninstall.ps1 must be run from an elevated (Administrator) PowerShell.'
    }
}

function Resolve-Full([string] $p) { [System.IO.Path]::GetFullPath($p) }

# Refuse to operate destructively on anything that is not a subdirectory of an expected root: a typo or a
# hostile -DataDir must never turn "takeown /R + icacls /reset /T + Remove-Item -Recurse" loose on C:\Windows.
function Assert-SafeTarget([string] $path, [string[]] $roots, [string] $what) {
    $full = (Resolve-Full $path).TrimEnd('\')
    if ($full.StartsWith('\\')) { throw "$what must be a local path." }
    if ([System.IO.Path]::GetPathRoot($full).TrimEnd('\') -ieq $full) { throw "$what must not be a drive root." }
    $item = Get-Item -LiteralPath $full -ErrorAction SilentlyContinue
    if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "$what is a reparse point (junction/symlink); refusing." }
    foreach ($r in $roots) {
        $rootFull = (Resolve-Full $r).TrimEnd('\') + '\'
        if ($full.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) { return $full }
    }
    throw "$what '$full' is not under any of: $($roots -join ', '). Refusing to remove it."
}

function Remove-LockedTree([string] $dir, [string] $what) {
    if (-not (Test-Path -LiteralPath $dir)) { return }
    if ($Force -or $PSCmdlet.ShouldProcess($dir, "Remove $what recursively")) {
        # The directory is locked to SYSTEM+Administrators; take ownership and reset the ACL before removing.
        & takeown /F $dir /R /D Y | Out-Null
        & icacls $dir /reset /T /C | Out-Null
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
        Write-Host "Removed $what $dir"
    }
}

Assert-Admin

if (-not $DataDir) {
    $DataDir = [Environment]::GetEnvironmentVariable('WARDEN_DATA_DIR', 'Machine')
    if (-not $DataDir) { $DataDir = Join-Path $env:ProgramData 'Warden' }
}

Write-Host "Stopping and deleting $ServiceName ..."
& sc.exe stop $ServiceName | Out-Null
Start-Sleep -Seconds 2
& sc.exe delete $ServiceName | Out-Null

Write-Host 'Removing machine configuration ...'
foreach ($name in 'WARDEN_ENFORCE_HARDENING', 'WARDEN_DATA_DIR', 'WARDEN_WDAC_BASE_POLICY_GUID') {
    [Environment]::SetEnvironmentVariable($name, $null, 'Machine')
}

Write-Host 'Removing the tray-UI logon task (if present) ...'
Unregister-ScheduledTask -TaskName 'WardenUi' -Confirm:$false -ErrorAction SilentlyContinue

# Binaries: always removed (they are ours). Confined to %ProgramFiles%.
try {
    $safeInstall = Assert-SafeTarget $InstallDir @($env:ProgramFiles) 'InstallDir'
    Remove-LockedTree $safeInstall 'install directory'
} catch {
    Write-Warning $_
}

if ($RemoveData) {
    try {
        $safeData = Assert-SafeTarget $DataDir @($env:ProgramData) 'DataDir'
        Remove-LockedTree $safeData 'data directory'
    } catch {
        Write-Warning $_
    }
}

Write-Host 'Warden uninstalled.'
