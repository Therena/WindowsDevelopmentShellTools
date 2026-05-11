function Install-GitCommitMsgTicketHook {
<#

.SYNOPSIS
Installs a commit-msg hook that runs Invoke-GitCommitMsgTicketHook via PowerShell.

.DESCRIPTION
Writes .git/hooks/commit-msg (POSIX stub for Git for Windows) and .git/hooks/commit-msg-ticket-runner.ps1, which imports this module and validates the commit message. Paths to pwsh (or Windows PowerShell) and the module manifest are fixed at install time. Existing files from a prior installation are always replaced. A marker comment is embedded so Uninstall-GitCommitMsgTicketHook can remove only these hooks.

.PARAMETER GitRepositoryPath
Path to the repository root (folder that contains .git) or to a bare .git directory.

.LINK
https://github.com/Therena/WindowsDevelopmentShellTools

.EXAMPLE
Install-GitCommitMsgTicketHook -GitRepositoryPath 'C:\Sources\MyRepo'

#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$GitRepositoryPath
    )

    $resolved = Resolve-Path -LiteralPath $GitRepositoryPath -ErrorAction Stop
    $candidate = $resolved.Path
    $gitDir = $null
    if (Test-Path -LiteralPath (Join-Path $candidate '.git') -PathType Container) {
        $gitDir = Join-Path $candidate '.git'
    }
    elseif ((Split-Path -Leaf $candidate) -eq '.git' -and (Test-Path -LiteralPath $candidate -PathType Container)) {
        $gitDir = $candidate
    }
    else {
        throw "Install-GitCommitMsgTicketHook: Unter '$candidate' wurde kein Git-Repository gefunden (.git fehlt)."
    }

    $hooksDir = Join-Path $gitDir 'hooks'
    if (-not (Test-Path -LiteralPath $hooksDir -PathType Container)) {
        New-Item -ItemType Directory -Path $hooksDir -Force -ErrorAction Stop | Out-Null
    }

    $hookPath = Join-Path $hooksDir 'commit-msg'
    $runnerPath = Join-Path $hooksDir 'commit-msg-ticket-runner.ps1'

    $hookMarker = 'wdsh-tools:git-commit-msg-ticket-hook'

    $pwsh = (Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $pwsh) {
        $pwsh = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    if (-not (Test-Path -LiteralPath $pwsh -PathType Leaf)) {
        throw "Install-GitCommitMsgTicketHook: Weder pwsh noch powershell.exe gefunden."
    }

    $module = $ExecutionContext.SessionState.Module
    if (-not $module -or $module.Name -ne 'Windows-Development-Shell-Tools') {
        $module = Get-Module Windows-Development-Shell-Tools | Select-Object -First 1
    }
    if (-not $module) {
        throw "Install-GitCommitMsgTicketHook: Modul 'Windows-Development-Shell-Tools' ist nicht geladen. Importieren Sie das Modul und wiederholen Sie die Installation."
    }

    $moduleRoot = $module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($moduleRoot) -and -not [string]::IsNullOrWhiteSpace($module.Path)) {
        $moduleRoot = Split-Path -LiteralPath $module.Path -Parent
    }
    if ([string]::IsNullOrWhiteSpace($moduleRoot)) {
        throw "Install-GitCommitMsgTicketHook: Modulbasis (ModuleBase) konnte nicht ermittelt werden."
    }
    $manifestPath = Join-Path $moduleRoot 'Windows-Development-Shell-Tools.psd1'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Install-GitCommitMsgTicketHook: Manifest nicht gefunden: $manifestPath"
    }

    $pwshUnix = $pwsh -replace '\\', '/'
    $runnerUnix = $runnerPath -replace '\\', '/'

    $shellHook = @"
#!/bin/sh
# $hookMarker
# commit-msg: Ticket-ID aus Branch in Commit-Nachricht (Windows-Development-Shell-Tools).
# Umgehen: git commit --no-verify  oder  `$env:SKIP_TICKET_HOOK=1 git commit ...
exec "$pwshUnix" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$runnerUnix" "`$1"
"@

    $manifestLiteral = $manifestPath.Replace("'", "''")
    $runnerContent = @"
# $hookMarker
param(
    [Parameter(Mandatory)]
    [string] `$CommitMessagePath
)
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
`$repoRoot = & git rev-parse --show-toplevel 2>`$null
if (`$LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(`$repoRoot)) { exit 0 }
Set-Location -LiteralPath `$repoRoot
Import-Module -LiteralPath '$manifestLiteral' -Force -ErrorAction Stop
try {
    Invoke-GitCommitMsgTicketHook -CommitMessagePath `$CommitMessagePath -GitRepositoryPath `$repoRoot
} catch {
    [Console]::Error.WriteLine(`$_.Exception.Message)
    exit 1
}
exit 0
"@

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false

    if ($PSCmdlet.ShouldProcess($runnerPath, 'Schreiben commit-msg-ticket-runner.ps1')) {
        [System.IO.File]::WriteAllText($runnerPath, $runnerContent.Replace("`r`n", "`n"), $utf8NoBom)
    }
    if ($PSCmdlet.ShouldProcess($hookPath, 'Schreiben commit-msg')) {
        [System.IO.File]::WriteAllText($hookPath, $shellHook.Replace("`r`n", "`n"), $utf8NoBom)
    }
}
