<#
.SYNOPSIS
    Installs and hardens the Warden zero-trust agent (Windows service + self-protection).

.DESCRIPTION
    Creates the ACL-locked data directory, registers the WardenAgent service as LocalSystem, applies the
    hardened service security descriptor (so standard users cannot stop/delete it), configures
    restart-on-kill recovery, enables the startup ACL lockdown, and starts the service. Optionally
    registers the user-session tray UI to launch at logon.

    RUN THIS ONLY on the target machine / inside the Win11 test VM, elevated. It makes real, machine-wide
    changes. The SDDL and sc.exe arguments below mirror Warden.Hardening.HardeningSddl /
    Warden.Hardening.ServiceHardener so the C# and the installer stay in lockstep.

.PARAMETER BinDir
    Directory containing the published Warden.Service.dll (from `dotnet publish`).

.PARAMETER DataDir
    The agent's data directory. Default: %ProgramData%\Warden.

.PARAMETER ServiceName
    The Windows service name. Default: WardenAgent.

.PARAMETER UiExe
    Optional full path to the tray UI exe; if given, it is registered to launch at logon.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BinDir,
    [string] $DataDir = (Join-Path $env:ProgramData 'Warden'),
    [string] $ServiceName = 'WardenAgent',
    [string] $UiExe
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'install.ps1 must be run from an elevated (Administrator) PowerShell.'
    }
}

Assert-Admin

# Mirrors HardeningSddl.ServiceDacl — SYSTEM + Administrators full control; Authenticated Users may only
# query (no start/stop/change-config/delete).
$ServiceDacl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)'

$serviceDll = Join-Path $BinDir 'Warden.Service.dll'
if (-not (Test-Path $serviceDll)) { throw "Warden.Service.dll not found in $BinDir. Run 'dotnet publish' first." }

$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if (-not $dotnet) { throw 'dotnet host not found on PATH.' }

# 1) ACL-locked data directory (SYSTEM + Administrators only; no inheritance; no access for others).
Write-Host "Creating locked data directory $DataDir ..."
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
& icacls $DataDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

# 2) Register the service (LocalSystem, auto-start). binPath launches the DLL via the trusted dotnet
#    host. Use New-Service (not `sc.exe create`): it passes the binary path to the SCM verbatim, so the
#    embedded quotes around the exe + DLL are not mangled by PowerShell's native-argument handling.
$binPath = '"{0}" "{1}"' -f $dotnet, $serviceDll
Write-Host "Registering service $ServiceName ..."
New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName 'Warden Zero-Trust Agent' `
    -StartupType Automatic `
    -Description 'Warden: local ML/LLM-driven zero-trust application control (WDAC-enforced).' | Out-Null

# 3) Harden who can control the service, and configure restart-on-kill recovery.
Write-Host 'Applying service security descriptor + recovery ...'
& sc.exe sdset $ServiceName $ServiceDacl | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null

# 4) Enable the service's startup ACL lockdown of the data dir + DB (read by Program.cs).
[Environment]::SetEnvironmentVariable('WARDEN_ENFORCE_HARDENING', '1', 'Machine')

# 5) Optionally register the tray UI to run at logon (runs in the user session, not session 0).
if ($UiExe) {
    if (-not (Test-Path $UiExe)) { throw "UI exe not found: $UiExe" }
    Write-Host 'Registering the tray UI to launch at logon ...'
    $action  = New-ScheduledTaskAction -Execute $UiExe
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'WardenUi' -Action $action -Trigger $trigger -Settings $set -RunLevel Limited -Force | Out-Null
}

# 6) Start it.
Write-Host "Starting $ServiceName ..."
& sc.exe start $ServiceName | Out-Null

Write-Host 'Warden installed and started. Verify with:  sc.exe qc WardenAgent  /  sc.exe sdshow WardenAgent'
