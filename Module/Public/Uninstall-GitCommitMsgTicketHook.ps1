function Uninstall-GitCommitMsgTicketHook {
<#

.SYNOPSIS
Removes the commit-msg ticket hook installed by Install-GitCommitMsgTicketHook.

.DESCRIPTION
Deletes .git/hooks/commit-msg-ticket-runner.ps1 when it contains the module marker, and .git/hooks/commit-msg when it contains the same marker (so unrelated hooks are left untouched).

.PARAMETER GitRepositoryPath
Path to the repository root (folder that contains .git) or to a bare .git directory.

.LINK
https://github.com/Therena/WindowsDevelopmentShellTools

.EXAMPLE
Uninstall-GitCommitMsgTicketHook -GitRepositoryPath 'C:\Sources\MyRepo'

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
        throw "Uninstall-GitCommitMsgTicketHook: Unter '$candidate' wurde kein Git-Repository gefunden (.git fehlt)."
    }

    $hooksDir = Join-Path $gitDir 'hooks'
    if (-not (Test-Path -LiteralPath $hooksDir -PathType Container)) {
        return
    }

    $hookMarker = 'wdsh-tools:git-commit-msg-ticket-hook'
    $hookPath = Join-Path $hooksDir 'commit-msg'
    $runnerPath = Join-Path $hooksDir 'commit-msg-ticket-runner.ps1'

    function Test-HookFileHasMarker {
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return $false
        }
        $head = [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false))
        return $head.Contains($hookMarker)
    }

    if (Test-HookFileHasMarker -Path $runnerPath) {
        if ($PSCmdlet.ShouldProcess($runnerPath, 'Entfernen commit-msg-ticket-runner.ps1')) {
            Remove-Item -LiteralPath $runnerPath -Force -ErrorAction Stop
        }
    }

    if (Test-HookFileHasMarker -Path $hookPath) {
        if ($PSCmdlet.ShouldProcess($hookPath, 'Entfernen commit-msg')) {
            Remove-Item -LiteralPath $hookPath -Force -ErrorAction Stop
        }
    }
}
