<#
.SYNOPSIS
    Authenticode-signs Warden's managed binaries.

.DESCRIPTION
    Signs the built Warden .dll/.exe files with signtool.exe (from the Windows SDK) using a code-signing
    certificate. Signing REQUIRES a code-signing certificate - a self-signed cert for personal test use,
    or an EV/OV cert for distribution. Without a certificate this script cannot sign; it is provided so
    the release step is scripted and reproducible.

    Warden's managed binaries are not signed automatically by the build (no certificate is committed). Run
    this after `dotnet publish`, before packaging/installing, on a machine with the SDK + certificate.

.PARAMETER Path
    A file or directory to sign. Directories are searched recursively for Warden*.dll / Warden*.exe.

.PARAMETER Thumbprint
    SHA-1 thumbprint of a code-signing certificate in the current user's certificate store (Cert:\CurrentUser\My).

.PARAMETER TimestampUrl
    RFC-3161 timestamp server URL. Default: http://timestamp.digicert.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Path,
    [Parameter(Mandatory = $true)] [string] $Thumbprint,
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'

if ($Thumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw "-Thumbprint must be a 40-hex-character SHA-1 thumbprint." }

# Prefer the SDK's own copy (newest version by real version-number ordering, not string ordering: 10.0.9
# must not beat 10.0.19041). Only fall back to PATH when no SDK is installed.
$kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$signtoolPath = Get-ChildItem -LiteralPath $kitsRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d+(\.\d+){1,3}$' } |
    Sort-Object { [Version] $_.Name } -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
if (-not $signtoolPath) {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { $signtoolPath = $cmd.Source }
}
if (-not $signtoolPath) { throw 'signtool.exe not found. Install the Windows SDK.' }
Write-Host "Using $signtoolPath"

$targets = @()
if (Test-Path -LiteralPath $Path -PathType Container) {
    $targets = Get-ChildItem -LiteralPath $Path -Recurse -Include 'Warden*.dll', 'Warden*.exe' | Select-Object -ExpandProperty FullName
} else {
    $targets = @((Resolve-Path -LiteralPath $Path).Path)
}
if ($targets.Count -eq 0) { throw "No Warden binaries found under $Path." }

foreach ($t in $targets) {
    Write-Host "Signing $t ..."
    & $signtoolPath sign /sha1 $Thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $t
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $t (exit $LASTEXITCODE)." }
}

Write-Host "Signed $($targets.Count) file(s). Verify with:  signtool verify /pa /all <file>"
