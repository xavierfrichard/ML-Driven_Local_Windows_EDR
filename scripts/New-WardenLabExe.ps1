#Requires -RunAsAdministrator
<#
================================================================================
 New-WardenLabExe.ps1  -  Warden Phase 0 Spike
================================================================================

 Creates a harmless, unsigned "lab" executable so the spike has something safe
 to be blocked by WDAC. The exe just prints a line and exits. Because it is
 UNSIGNED and lives in a USER folder, the DefaultWindows_Audit-derived base
 policy blocks it by ABSENCE OF ALLOW (event 3076 in audit / 3077 in enforce) -
 no Deny rule needed. See policy/README.md.

 Output (default):  %USERPROFILE%\WardenSpikeLab\hello.exe

 It compiles with the .NET Framework C# compiler (csc.exe) that ships in-box on
 every Windows 11 machine, so no .NET SDK is required. If that compiler is not
 found it falls back to the .NET SDK (`dotnet build`).

 ------------------------------------------------------------------------------
 VM-ONLY RUN SEQUENCE (elevated PowerShell inside the isolated Windows 11 VM):
   1. .\scripts\New-WardenLabExe.ps1
   2. .\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly              # audit base
   3. .\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly -DeploySupplemental
   4. .\scripts\Deploy-WardenSpikePolicy.ps1 -IUnderstandVmOnly -Enforce     # optional
   5. .\scripts\Remove-WardenSpikePolicy.ps1 -IUnderstandVmOnly              # rollback
 ------------------------------------------------------------------------------
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Folder to hold the lab exe. A user-writable path on purpose.
    [string]$LabDir = (Join-Path $env:USERPROFILE 'WardenSpikeLab'),

    # Exe file name.
    [string]$ExeName = 'hello.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$m) Write-Host "[lab] $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "[lab] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "[lab] $m" -ForegroundColor Yellow }

$exePath = Join-Path $LabDir $ExeName

Write-Step "Lab directory : $LabDir"
Write-Step "Target exe     : $exePath"

if (-not (Test-Path -LiteralPath $LabDir)) {
    if ($PSCmdlet.ShouldProcess($LabDir, 'Create lab directory')) {
        New-Item -ItemType Directory -Path $LabDir -Force | Out-Null
        Write-Ok "Created $LabDir"
    }
}

# ---- Trivial, obviously-harmless C# source -----------------------------------
$srcPath = Join-Path $LabDir 'hello.cs'
$source = @'
using System;

// Warden Phase 0 lab executable. Harmless: prints a line and exits 0.
internal static class WardenLabHello
{
    private static int Main()
    {
        Console.WriteLine("Warden lab exe: if you can read this, WDAC ALLOWED me to run.");
        return 0;
    }
}
'@

if ($PSCmdlet.ShouldProcess($srcPath, 'Write C# source')) {
    Set-Content -LiteralPath $srcPath -Value $source -Encoding UTF8
    Write-Ok "Wrote source $srcPath"
}

# ---- Compile: prefer in-box .NET Framework csc.exe, else dotnet SDK -----------
$cscCandidates = @(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
)
$csc = $cscCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if ($PSCmdlet.ShouldProcess($exePath, 'Compile lab exe')) {

    if ($csc) {
        Write-Step "Compiling with in-box C# compiler: $csc"
        # /nologo quiet, no PDB, target the console exe directly.
        & $csc /nologo /optimize+ /debug- "/out:$exePath" $srcPath | ForEach-Object { Write-Host "    $_" }
        if ($LASTEXITCODE -ne 0) { throw "csc.exe failed with exit code $LASTEXITCODE" }
    }
    else {
        Write-Warn "In-box csc.exe not found; falling back to .NET SDK (dotnet build)."
        $dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue)
        if (-not $dotnet) {
            throw "Neither in-box csc.exe nor 'dotnet' is available. Cannot build the lab exe."
        }
        $projDir = Join-Path $LabDir '_labproj'
        New-Item -ItemType Directory -Path $projDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $projDir 'Program.cs') -Value $source -Encoding UTF8
        $csproj = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>hello</AssemblyName>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <UseAppHost>true</UseAppHost>
  </PropertyGroup>
</Project>
'@
        Set-Content -LiteralPath (Join-Path $projDir 'lab.csproj') -Value $csproj -Encoding UTF8
        & dotnet build (Join-Path $projDir 'lab.csproj') -c Release -o $projDir\out | ForEach-Object { Write-Host "    $_" }
        if ($LASTEXITCODE -ne 0) { throw "dotnet build failed with exit code $LASTEXITCODE" }
        Copy-Item -LiteralPath (Join-Path $projDir 'out\hello.exe') -Destination $exePath -Force
    }

    if (-not (Test-Path -LiteralPath $exePath)) {
        throw "Compilation reported success but $exePath does not exist."
    }

    # Flat SHA-256 for the operator's reference (NOTE: WDAC uses the Authenticode
    # image hash, which the deploy script computes with New-CIPolicy - this flat
    # hash is only a human sanity check, not what goes into the policy).
    $flat = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash
    Write-Ok  "Built lab exe: $exePath"
    Write-Host "[lab] Flat SHA-256 (reference only): $flat" -ForegroundColor DarkGray
    Write-Host "[lab] Run it to test:  & '$exePath'" -ForegroundColor DarkGray
}
