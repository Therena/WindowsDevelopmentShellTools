#Requires -Version 5.1

<#
.SYNOPSIS
    Installs Windows-Development-Shell-Tools into your per-user module folders.

.DESCRIPTION
    Copies the repository Module folder (manifest and root module) into versioned directories under:
      - Windows PowerShell 5.1:  Documents\WindowsPowerShell\Modules
      - PowerShell 7+ (pwsh):    Documents\PowerShell\Modules

    Run this script from Windows using either powershell.exe or pwsh.exe; it installs to both locations
    so the module is available in either host. Non-Windows hosts only receive the PowerShell Core path.

.PARAMETER Force
    Replace an existing install of the same module version under a target path.

.PARAMETER SkipWindowsPowerShell
    Do not install under Documents\WindowsPowerShell\Modules.

.PARAMETER SkipPowerShellCore
    Do not install under Documents\PowerShell\Modules.

.EXAMPLE
    .\Install-DevelopmentShellTools.ps1

.EXAMPLE
    .\Install-DevelopmentShellTools.ps1 -Force
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force,
    [switch]$SkipWindowsPowerShell,
    [switch]$SkipPowerShellCore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Avoid $IsWindows directly: it does not exist in Windows PowerShell 5.1 under Set-StrictMode.
$isWinAutomatic = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
$runningOnWindows = ($env:OS -eq 'Windows_NT') -or ($null -ne $isWinAutomatic -and $isWinAutomatic.Value)

$repoRoot = $PSScriptRoot
$moduleSource = Join-Path $repoRoot 'Module'
$manifestPath = Join-Path $moduleSource 'Windows-Development-Shell-Tools.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Manifest not found: $manifestPath"
}

$data = Import-PowerShellDataFile -LiteralPath $manifestPath
$version = $data.ModuleVersion
$rootModule = $data.RootModule
if ([string]::IsNullOrWhiteSpace($version)) {
    throw 'ModuleVersion is missing from the manifest.'
}
if ([string]::IsNullOrWhiteSpace($rootModule)) {
    throw 'RootModule is missing from the manifest.'
}

$required = @(
    (Join-Path $moduleSource $rootModule),
    $manifestPath
)
foreach ($p in $required) {
    if (-not (Test-Path -LiteralPath $p)) {
        throw "Required module file not found: $p"
    }
}

$moduleName = 'Windows-Development-Shell-Tools'
$targets = [System.Collections.Generic.List[hashtable]]::new()

if ($runningOnWindows -and -not $SkipWindowsPowerShell) {
    $targets.Add(@{
        Label = 'Windows PowerShell 5.1'
        Base  = Join-Path $HOME 'Documents\WindowsPowerShell\Modules'
    })
}

if (-not $SkipPowerShellCore) {
    $targets.Add(@{
        Label = 'PowerShell 7+ (Core)'
        Base  = Join-Path $HOME 'Documents\PowerShell\Modules'
    })
}

if ($targets.Count -eq 0) {
    throw 'No installation targets selected (all skips enabled or unsupported platform).'
}

foreach ($t in $targets) {
    $destDir = Join-Path $t.Base $moduleName | Join-Path -ChildPath $version
    if (Test-Path -LiteralPath $destDir) {
        if (-not $Force) {
            throw @"
Installation already exists: $destDir
Use -Force to replace it, or remove that folder manually.
"@
        }
        if ($PSCmdlet.ShouldProcess($destDir, 'Remove existing module version folder')) {
            Remove-Item -LiteralPath $destDir -Recurse -Force
        }
    }

    if ($PSCmdlet.ShouldProcess($destDir, "Install $moduleName $version for $($t.Label)")) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        Get-ChildItem -LiteralPath $moduleSource -File | Copy-Item -Destination $destDir -Force
        Write-Host "Installed for $($t.Label): $destDir"
    }
}

if (-not $WhatIfPreference) {
    Write-Host @"

Import the module in a new session:
  Import-Module $moduleName

Or by path:
  Import-Module '$manifestPath'   # from this repo clone
"@
}
