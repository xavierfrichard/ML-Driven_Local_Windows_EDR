<#
.SYNOPSIS
    Stores or removes one Warden secret (API key or ML model pin) in the service's protected secret store.

.DESCRIPTION
    The WardenAgent service reads its secrets from <DataDir>\secrets\<Name>.bin. Each file is a DPAPI blob
    (machine scope, bound to the secret's name) and the folder and files are owned by Administrators and
    readable and writable only by SYSTEM and Administrators. See Warden.Secrets.WardenSecretStore.

    This replaces the old machine environment variables WARDEN_VT_API_KEY and WARDEN_ANTHROPIC_API_KEY.
    Machine environment variables live in HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment,
    which every user can read, and every process inherits them. The service still reads them as a deprecated
    fallback and logs a warning; pass -RemoveLegacyVariable to delete the old variable once the key is stored.

    The service reads secrets at startup: restart it afterwards (Restart-Service WardenAgent).

    RUN ELEVATED, on the machine where the service runs (a DPAPI machine-scope blob only decrypts there).

.PARAMETER Name
    VirusTotalApiKey, AnthropicApiKey or MlModelSha256.

.PARAMETER Value
    The secret, as a SecureString. When omitted (and -ModelPath is not used) you are prompted for it, so the
    key never appears in the command history.

.PARAMETER ModelPath
    MlModelSha256 only: compute the pin from this model file instead of typing the hash. Deploy the model to
    <DataDir>\ml\model.onnx and pin that exact file.

.PARAMETER Remove
    Delete the stored secret instead of writing it.

.PARAMETER RemoveLegacyVariable
    VirusTotalApiKey / AnthropicApiKey only: also delete the old machine environment variable.

.PARAMETER DataDir
    The Warden data directory. Default: the machine variable WARDEN_DATA_DIR, else %ProgramData%\Warden.

.EXAMPLE
    .\Set-WardenSecret.ps1 -Name VirusTotalApiKey -RemoveLegacyVariable
    (prompts for the key)

.EXAMPLE
    .\Set-WardenSecret.ps1 -Name MlModelSha256 -ModelPath "$env:ProgramData\Warden\ml\model.onnx"

.EXAMPLE
    .\Set-WardenSecret.ps1 -Name AnthropicApiKey -Remove
#>
#Requires -RunAsAdministrator
[CmdletBinding(DefaultParameterSetName = 'Set', SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('VirusTotalApiKey', 'AnthropicApiKey', 'MlModelSha256')]
    [string] $Name,

    [Parameter(ParameterSetName = 'Set')]
    [System.Security.SecureString] $Value,

    [Parameter(ParameterSetName = 'Set')]
    [string] $ModelPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
    [switch] $Remove,

    [switch] $RemoveLegacyVariable,

    [string] $DataDir
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

# Keep these in lockstep with Warden.Secrets.WardenSecretStore.
$EntropyPrefix = 'Warden.Secret.v1:'
$LegacyVariables = @{ VirusTotalApiKey = 'WARDEN_VT_API_KEY'; AnthropicApiKey = 'WARDEN_ANTHROPIC_API_KEY' }
# S-1-5-18 SYSTEM, S-1-5-32-544 Administrators, NT SERVICE\TrustedInstaller.
$TrustedOwners = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell.'
    }
}

function Assert-NotLink([string] $path) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$path is a symbolic link or junction; refusing to use it." }
}

function Assert-TrustedOwner([string] $path) {
    $owner = (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedOwners -notcontains $owner) {
        throw "$path is owned by $owner, not SYSTEM or Administrators. Re-run install.ps1 (it recreates the data directory with the right owner) before storing secrets."
    }
}

function Set-LockedAcl([string] $path, [switch] $Directory) {
    # Owner Administrators; no inheritance; SYSTEM + Administrators full control only. SIDs, so this works on
    # non-English Windows.
    $grants = if ($Directory) { @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F') } else { @('*S-1-5-18:F', '*S-1-5-32-544:F') }
    & icacls $path /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed for $path (exit $LASTEXITCODE)." }
    $icaclsArgs = @($path, '/inheritance:r', '/grant:r') + $grants
    & icacls @icaclsArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed for $path (exit $LASTEXITCODE)." }
}

function Get-PlainBytes([System.Security.SecureString] $secure) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        return [Text.Encoding]::UTF8.GetBytes($plain.Trim())
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

Assert-Admin
try { Add-Type -AssemblyName System.Security } catch { }   # ProtectedData on Windows PowerShell 5.1

# ---- locate and check the store ---------------------------------------------------------------------------
if (-not $DataDir) {
    $DataDir = [Environment]::GetEnvironmentVariable('WARDEN_DATA_DIR', 'Machine')
    if (-not $DataDir) { $DataDir = Join-Path $env:ProgramData 'Warden' }
}
$DataDir = [IO.Path]::GetFullPath($DataDir)
if (-not (Test-Path -LiteralPath $DataDir -PathType Container)) {
    throw "The Warden data directory $DataDir does not exist. Run install.ps1 first."
}
Assert-NotLink $DataDir
Assert-TrustedOwner $DataDir

$secretsDir = Join-Path $DataDir 'secrets'
$target = Join-Path $secretsDir ($Name + '.bin')

# ---- remove ------------------------------------------------------------------------------------------------
if ($Remove) {
    if (Test-Path -LiteralPath $target) {
        Assert-NotLink $target
        if ($PSCmdlet.ShouldProcess($target, 'Delete stored secret')) {
            Remove-Item -LiteralPath $target -Force
            Write-Host "Removed $Name from the protected store."
        }
    }
    else {
        Write-Host "$Name is not in the protected store."
    }
    if ($RemoveLegacyVariable -and $LegacyVariables.ContainsKey($Name)) {
        [Environment]::SetEnvironmentVariable($LegacyVariables[$Name], $null, 'Machine')
        Write-Host "Removed the machine environment variable $($LegacyVariables[$Name])."
    }
    Write-Host 'Restart the service to apply: Restart-Service WardenAgent'
    return
}

# ---- read the value ----------------------------------------------------------------------------------------
if ($ModelPath) {
    if ($Name -ne 'MlModelSha256') { throw '-ModelPath is only valid with -Name MlModelSha256.' }
    $hash = (Get-FileHash -LiteralPath $ModelPath -Algorithm SHA256).Hash
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($hash)
    Write-Host "Pinning $ModelPath (SHA-256 $hash)."
}
else {
    if (-not $Value) { $Value = Read-Host -AsSecureString "Value for $Name" }
    $plainBytes = Get-PlainBytes $Value
}

try {
    if ($plainBytes.Length -eq 0) { throw 'The value is empty.' }
    if ($Name -eq 'MlModelSha256') {
        $text = [Text.Encoding]::UTF8.GetString($plainBytes)
        if ($text -notmatch '^[0-9A-Fa-f]{64}$') { throw 'MlModelSha256 must be 64 hexadecimal characters (a SHA-256).' }
    }

    $entropy = [Text.Encoding]::UTF8.GetBytes($EntropyPrefix + $Name)
    $blob = [Security.Cryptography.ProtectedData]::Protect($plainBytes, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)

    # Round-trip before replacing anything.
    $check = [Security.Cryptography.ProtectedData]::Unprotect($blob, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    if ($check.Length -ne $plainBytes.Length) { throw 'DPAPI round-trip check failed; nothing was written.' }
    [Array]::Clear($check, 0, $check.Length)
}
finally {
    [Array]::Clear($plainBytes, 0, $plainBytes.Length)
}

if (-not $PSCmdlet.ShouldProcess($target, "Store $Name")) { return }

# ---- write: locked folder, temp file in the same folder, lock it, then replace ------------------------------
if (Test-Path -LiteralPath $secretsDir) {
    Assert-NotLink $secretsDir
}
else {
    New-Item -ItemType Directory -Path $secretsDir | Out-Null
}
Set-LockedAcl $secretsDir -Directory

$temp = Join-Path $secretsDir ($Name + '.bin.' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {
    [IO.File]::WriteAllBytes($temp, $blob)
    Set-LockedAcl $temp
    if (Test-Path -LiteralPath $target) { Assert-NotLink $target }
    Move-Item -LiteralPath $temp -Destination $target -Force
}
finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
}
Write-Host "Stored $Name in $target (DPAPI machine scope; SYSTEM and Administrators only)."

if ($RemoveLegacyVariable -and $LegacyVariables.ContainsKey($Name)) {
    [Environment]::SetEnvironmentVariable($LegacyVariables[$Name], $null, 'Machine')
    Write-Host "Removed the machine environment variable $($LegacyVariables[$Name])."
}
elseif ($LegacyVariables.ContainsKey($Name) -and [Environment]::GetEnvironmentVariable($LegacyVariables[$Name], 'Machine')) {
    Write-Warning "The world-readable machine variable $($LegacyVariables[$Name]) is still set. The store wins, but remove the variable: re-run with -RemoveLegacyVariable."
}
Write-Host 'Restart the service to apply: Restart-Service WardenAgent'
