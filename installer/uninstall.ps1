<#
.SYNOPSIS
    Stops and removes the Warden zero-trust agent.

.DESCRIPTION
    Stops and deletes the WardenAgent service, removes the startup-hardening environment variable and the
    tray-UI logon task, and (with -RemoveData) removes the locked data directory. Run elevated, on the
    target machine / in the VM.

.PARAMETER ServiceName
    The Windows service name. Default: WardenAgent.

.PARAMETER DataDir
    The agent's data directory. Default: %ProgramData%\Warden.

.PARAMETER RemoveData
    Also delete the data directory (database, quarantine, logs). Off by default.
#>
[CmdletBinding()]
param(
    [string] $ServiceName = 'WardenAgent',
    [string] $DataDir = (Join-Path $env:ProgramData 'Warden'),
    [switch] $RemoveData
)

$ErrorActionPreference = 'Continue'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'uninstall.ps1 must be run from an elevated (Administrator) PowerShell.'
    }
}

Assert-Admin

Write-Host "Stopping and deleting $ServiceName ..."
& sc.exe stop $ServiceName | Out-Null
Start-Sleep -Seconds 2
& sc.exe delete $ServiceName | Out-Null

Write-Host 'Removing startup-hardening flag ...'
[Environment]::SetEnvironmentVariable('WARDEN_ENFORCE_HARDENING', $null, 'Machine')

Write-Host 'Removing the tray-UI logon task (if present) ...'
Unregister-ScheduledTask -TaskName 'WardenUi' -Confirm:$false -ErrorAction SilentlyContinue

if ($RemoveData) {
    Write-Host "Removing data directory $DataDir ..."
    # The directory is locked to SYSTEM+Administrators; take ownership and reset the ACL before removing.
    & takeown /F $DataDir /R /D Y | Out-Null
    & icacls $DataDir /reset /T /C | Out-Null
    Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Warden uninstalled.'
