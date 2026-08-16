<#
.SYNOPSIS
    Installs and hardens the Warden zero-trust agent (Windows service + self-protection).

.DESCRIPTION
    Copies the published binaries into an ACL-locked install directory under %ProgramFiles%, creates the
    ACL-locked data directory, registers the WardenAgent service as LocalSystem (launched by the pinned
    %ProgramFiles%\dotnet host), applies the hardened service security descriptor (so standard users
    cannot stop/delete it), configures restart-on-kill recovery, enables the startup ACL lockdown, and
    starts the service. Optionally registers the tray UI to launch (elevated) at logon.

    RUN THIS ONLY on the target machine / inside the Win11 test VM, elevated. It makes real, machine-wide
    changes. The SDDL and sc.exe arguments below mirror Warden.Hardening.HardeningSddl /
    Warden.Hardening.ServiceHardener so the C# and the installer stay in lockstep.

    WHY THE COPY: a LocalSystem service loads its code from its binPath on every start (and on every
    restart-on-failure). If that directory is user-writable - a repo `out\` folder, a user profile - any
    local user can swap Warden.Service.dll for SYSTEM code execution. So the binaries are copied to a
    directory only SYSTEM/Administrators can write, and the service points there.

.PARAMETER BinDir
    Directory containing the published Warden.Service.dll (from `dotnet publish`). Copied to InstallDir\service.

.PARAMETER InstallDir
    Where the binaries live at run time. Default: %ProgramFiles%\Warden. Must be under %ProgramFiles%
    unless -AllowUnprotectedInstallDir is given.

.PARAMETER DataDir
    The agent's data directory. Default: %ProgramData%\Warden. Must be under %ProgramData% unless
    -AllowUnprotectedDataDir is given. Published to the service via the machine env var WARDEN_DATA_DIR
    so every module (database, quarantine, WDAC work dir, snapshots, logs) and the hardener use it.

.PARAMETER ServiceName
    The Windows service name. Default: WardenAgent.

.PARAMETER UiDir
    Optional directory of the published tray UI (contains Warden.Ui.exe). Copied to InstallDir\ui and
    registered to launch elevated at logon.

.PARAMETER UiExe
    Back-compat alias: path to a published Warden.Ui.exe; its directory is used as -UiDir.

.PARAMETER DotnetHost
    Path to dotnet.exe. Default: %ProgramFiles%\dotnet\dotnet.exe. Must be under %ProgramFiles% unless
    -AllowUnpinnedDotnet is given (a user-profile dotnet would be a user-writable host for a SYSTEM service).

.PARAMETER WdacBasePolicyGuid
    Optional GUID of the machine's WDAC base policy the Warden supplemental attaches to (published as
    WARDEN_WDAC_BASE_POLICY_GUID). When omitted the service discovers it at run time.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BinDir,
    [string] $InstallDir = (Join-Path $env:ProgramFiles 'Warden'),
    [string] $DataDir = (Join-Path $env:ProgramData 'Warden'),
    [string] $ServiceName = 'WardenAgent',
    [string] $UiDir,
    [string] $UiExe,
    [string] $DotnetHost = (Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'),
    [string] $WdacBasePolicyGuid,
    [switch] $AllowUnprotectedInstallDir,
    [switch] $AllowUnprotectedDataDir,
    [switch] $AllowUnpinnedDotnet
)

$ErrorActionPreference = 'Stop'

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
    $full = Resolve-Full $path
    $rootFull = (Resolve-Full $root).TrimEnd('\') + '\'
    if (-not $full.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not $Allowed) {
            throw "$what '$full' is not under '$rootFull'. A LocalSystem service must not depend on a user-writable location; pass the matching -Allow* switch only if you know why."
        }
        Write-Warning "$what '$full' is outside '$rootFull' - make sure standard users cannot write to it."
    }
    if ($full.StartsWith('\\')) { throw "$what must be a local path, not UNC." }
    if ([System.IO.Path]::GetPathRoot($full).TrimEnd('\') -ieq $full.TrimEnd('\')) { throw "$what must not be a drive root." }
    return $full
}

function Lock-Directory([string] $dir, [switch] $UsersMayReadExecute) {
    # No inheritance, explicit grants only. SYSTEM + Administrators full; optionally Users read/execute
    # (the tray UI and the service binaries must be loadable, never writable, by non-admins).
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    # SIDs rather than names so this works on non-English Windows (S-1-5-18 SYSTEM, S-1-5-32-544
    # Administrators, S-1-5-32-545 Users).
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    if ($UsersMayReadExecute) { $grants += '*S-1-5-32-545:(OI)(CI)RX' }
    $icaclsArgs = @($dir, '/inheritance:r', '/grant:r') + $grants
    & icacls @icaclsArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed for $dir (exit $LASTEXITCODE)." }
}

function Copy-Tree([string] $from, [string] $to) {
    New-Item -ItemType Directory -Path $to -Force | Out-Null
    # /MIR keeps the target an exact copy (stale DLLs from an older publish are removed).
    & robocopy $from $to /MIR /NFL /NDL /NJH /NJS /NP /R:2 /W:1 | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed copying $from -> $to (exit $LASTEXITCODE)." }
}

Assert-Admin

# Mirrors HardeningSddl.ServiceDacl - SYSTEM + Administrators full control; Authenticated Users may only
# query (no start/stop/change-config/delete).
$ServiceDacl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)'

# ---- validate inputs ------------------------------------------------------------------------------------
$serviceDll = Join-Path $BinDir 'Warden.Service.dll'
if (-not (Test-Path -LiteralPath $serviceDll)) { throw "Warden.Service.dll not found in $BinDir. Run 'dotnet publish' first." }

if ($UiExe -and -not $UiDir) { $UiDir = Split-Path -Parent (Resolve-Full $UiExe) }
if ($UiDir -and -not (Test-Path -LiteralPath (Join-Path $UiDir 'Warden.Ui.exe'))) { throw "Warden.Ui.exe not found in $UiDir." }

$InstallDir = Assert-Under $InstallDir $env:ProgramFiles 'InstallDir' -Allowed:$AllowUnprotectedInstallDir
$DataDir    = Assert-Under $DataDir    $env:ProgramData  'DataDir'    -Allowed:$AllowUnprotectedDataDir
$DotnetHost = Resolve-Full $DotnetHost
if (-not (Test-Path -LiteralPath $DotnetHost)) { throw "dotnet host not found at $DotnetHost. Install the .NET 8 runtime for all users, or pass -DotnetHost." }
$null = Assert-Under $DotnetHost $env:ProgramFiles 'DotnetHost' -Allowed:$AllowUnpinnedDotnet

if ($WdacBasePolicyGuid) {
    $g = [Guid]::Empty
    if (-not [Guid]::TryParse($WdacBasePolicyGuid.Trim('{', '}'), [ref] $g) -or $g -eq [Guid]::Empty) {
        throw "-WdacBasePolicyGuid '$WdacBasePolicyGuid' is not a valid, non-empty GUID."
    }
    $WdacBasePolicyGuid = '{' + $g.ToString().ToUpperInvariant() + '}'
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

# ---- 1) install directory: copy binaries, lock it ---------------------------------------------------------
Write-Host "Installing binaries to $InstallDir ..."
$serviceDir = Join-Path $InstallDir 'service'
Copy-Tree (Resolve-Full $BinDir) $serviceDir
$uiTarget = $null
if ($UiDir) {
    $uiTarget = Join-Path $InstallDir 'ui'
    Copy-Tree (Resolve-Full $UiDir) $uiTarget
}
Lock-Directory $InstallDir -UsersMayReadExecute
$installedDll = Join-Path $serviceDir 'Warden.Service.dll'

# ---- 2) ACL-locked data directory (SYSTEM + Administrators only; no inheritance) ---------------------------
Write-Host "Creating locked data directory $DataDir ..."
Lock-Directory $DataDir

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
& sc.exe sdset $ServiceName $ServiceDacl | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null

# ---- 5) machine-scoped configuration read by the service -----------------------------------------------------
[Environment]::SetEnvironmentVariable('WARDEN_ENFORCE_HARDENING', '1', 'Machine')   # re-apply the ACL lockdown on every start
[Environment]::SetEnvironmentVariable('WARDEN_DATA_DIR', $DataDir, 'Machine')       # the one data directory for every module
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
    Register-ScheduledTask -TaskName 'WardenUi' -Action $action -Trigger $trigger -Settings $set -RunLevel Highest -Force | Out-Null
}

# ---- 7) start it -------------------------------------------------------------------------------------------
Write-Host "Starting $ServiceName ..."
& sc.exe start $ServiceName | Out-Null

# Bring the (elevated) tray up right away in this session so nobody has to log off/on to get it: the task
# runs as the interactive user at Highest run level, so this is the same thing the logon trigger would do.
if ($uiTarget) {
    Write-Host 'Starting the tray UI ...'
    Start-ScheduledTask -TaskName 'WardenUi' -ErrorAction SilentlyContinue
}

Write-Host 'Warden installed and started. Verify with:  sc.exe qc WardenAgent  /  sc.exe sdshow WardenAgent'
Write-Host "  binaries: $InstallDir   data: $DataDir   host: $DotnetHost"
