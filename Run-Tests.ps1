#Requires -Version 5.1
<#
.SYNOPSIS
Runs Pester tests for Windows-Development-Shell-Tools.

.DESCRIPTION
Requires Pester 5.x: Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0.0 -Force

.EXAMPLE
.\Run-Tests.ps1
#>
[CmdletBinding()]
param ()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

try {
    Import-Module Pester -MinimumVersion 5.0.0 -ErrorAction Stop
}
catch {
    Write-Error @"
Pester 5 is required. Install with:

  Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0.0 -Force

Original error: $_
"@
    exit 1
}

$testPath = Join-Path $repoRoot 'Tests'
if (-not (Test-Path -LiteralPath $testPath)) {
    Write-Error "Tests folder not found: $testPath"
    exit 1
}

$result = Invoke-Pester -Path $testPath -PassThru -CI
if ($result.FailedCount -gt 0) {
    exit 1
}
