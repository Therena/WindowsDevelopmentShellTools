function Invoke-GitCommitMsgTicketHook {
<#

.SYNOPSIS
Validates that a Git commit message contains the Jira-style ticket id inferred from the current branch (commit-msg hook logic).

.DESCRIPTION
Mirrors a typical commit-msg hook: if the last path segment of the branch starts with a token like PROJ-123, the commit message must contain that id (case-insensitive). Skips validation when the environment variable SKIP_TICKET_HOOK is set, during an in-progress merge (MERGE_HEAD), on detached HEAD, or when the branch is HEAD, main, master, develop, or dev.

Intended to be called from a Git hook or from Install-GitCommitMsgTicketHook's generated runner script. Use git commit --no-verify to bypass the hook.

.PARAMETER CommitMessagePath
Path to the file containing the commit message (Git passes this as the first argument to commit-msg).

.PARAMETER GitRepositoryPath
Root of the working tree. When omitted, the repository is resolved with git rev-parse --show-toplevel using the current location.

.LINK
https://github.com/Therena/WindowsDevelopmentShellTools

.EXAMPLE
Invoke-GitCommitMsgTicketHook -CommitMessagePath $args[0]

Typical usage from a hook runner after Set-Location to the repository root.

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CommitMessagePath,

        [Parameter()]
        [string]$GitRepositoryPath
    )

    if (-not [string]::IsNullOrEmpty($env:SKIP_TICKET_HOOK)) {
        return
    }

    if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) {
        throw "Invoke-GitCommitMsgTicketHook: 'git' wurde nicht im PATH gefunden."
    }

    if (-not $GitRepositoryPath) {
        $top = & git rev-parse --show-toplevel 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($top)) {
            throw "Invoke-GitCommitMsgTicketHook: Kein Git-Repository (rev-parse --show-toplevel fehlgeschlagen)."
        }
        $GitRepositoryPath = $top
    }

    $repo = (Resolve-Path -LiteralPath $GitRepositoryPath -ErrorAction Stop).Path

    $null = & git -C $repo rev-parse -q --verify MERGE_HEAD 2>$null
    if ($LASTEXITCODE -eq 0) {
        return
    }

    $branch = (& git -C $repo rev-parse --abbrev-ref HEAD 2>$null).Trim()
    if ($LASTEXITCODE -ne 0) {
        return
    }

    switch ($branch) {
        'HEAD' { return }
        'main' { return }
        'master' { return }
        'develop' { return }
        'dev' { return }
    }

    $segments = $branch -split '/', [System.StringSplitOptions]::None
    $slug = $segments[$segments.Length - 1]
    if ([string]::IsNullOrEmpty($slug)) {
        return
    }

    $ticket = $null
    if ($slug -match '^([A-Za-z][A-Za-z0-9]*-[0-9]+)') {
        $ticket = $Matches[1]
    }

    if ([string]::IsNullOrEmpty($ticket)) {
        return
    }

    $msgFile = $CommitMessagePath
    if (-not [System.IO.Path]::IsPathRooted($msgFile)) {
        $msgFile = Join-Path -Path (Get-Location).Path -ChildPath $msgFile
    }
    $msgFile = (Resolve-Path -LiteralPath $msgFile -ErrorAction Stop).Path

    $message = [System.IO.File]::ReadAllText($msgFile)
    if ($null -eq $message) {
        $message = ''
    }

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $comparison = [System.Globalization.CompareOptions]::IgnoreCase
    if ($culture.CompareInfo.IndexOf($message, $ticket, $comparison) -lt 0) {
        $err = @(
            "Commit abgebrochen: Die Nachricht enthält nicht die Ticket-ID aus dem Branch: $ticket"
            "  Aktueller Branch: $branch"
            "  (Umgehen bei Ausnahmefällen: git commit --no-verify)"
        ) -join [Environment]::NewLine
        throw $err
    }
}
