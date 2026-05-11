. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

BeforeDiscovery {
    $global:GitTicketTest_HasGit = $null -ne (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)
}

function global:Initialize-GitTicketTestRepositories {
    if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) {
        return
    }
    $haveTicket = $global:GitTicketTest_TicketRepo -and (Test-Path -LiteralPath $global:GitTicketTest_TicketRepo)
    $haveInstall = $global:GitTicketTest_InstallRepo -and (Test-Path -LiteralPath $global:GitTicketTest_InstallRepo)
    if ($haveTicket -and $haveInstall) {
        return
    }
    foreach ($p in @($global:GitTicketTest_TicketRepo, $global:GitTicketTest_InstallRepo)) {
        if ($p -and (Test-Path -LiteralPath $p)) {
            Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $ticketRepo = Join-Path ([System.IO.Path]::GetTempPath()) ("wdst-ticket-{0}" -f [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $ticketRepo -Force | Out-Null
    Push-Location -LiteralPath $ticketRepo
    try {
        & git init 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'git init failed'
        }
        & git config user.email 'test@example.com' 2>$null | Out-Null
        & git config user.name 'test' 2>$null | Out-Null
        'init' | Set-Content -LiteralPath 'README.md' -Encoding utf8
        & git add README.md 2>$null | Out-Null
        & git commit -m 'init' 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'git commit failed'
        }
    }
    finally {
        Pop-Location
    }
    $global:GitTicketTest_TicketRepo = $ticketRepo
    $global:GitTicketTest_MsgFile = Join-Path $ticketRepo 'commit-msg-test.txt'

    $installRepo = Join-Path ([System.IO.Path]::GetTempPath()) ("wdst-install-{0}" -f [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $installRepo -Force | Out-Null
    Push-Location -LiteralPath $installRepo
    try {
        & git init 2>$null | Out-Null
        & git config user.email 'test@example.com' 2>$null | Out-Null
        & git config user.name 'test' 2>$null | Out-Null
        'x' | Set-Content -LiteralPath 'README.md' -Encoding utf8
        & git add README.md 2>$null | Out-Null
        & git commit -m 'init' 2>$null | Out-Null
    }
    finally {
        Pop-Location
    }
    $global:GitTicketTest_InstallRepo = $installRepo
}

Describe 'Git commit-msg ticket hook (integration)' {
    AfterAll {
        if ($global:GitTicketTest_TicketRepo -and (Test-Path -LiteralPath $global:GitTicketTest_TicketRepo)) {
            Remove-Item -LiteralPath $global:GitTicketTest_TicketRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ($global:GitTicketTest_InstallRepo -and (Test-Path -LiteralPath $global:GitTicketTest_InstallRepo)) {
            Remove-Item -LiteralPath $global:GitTicketTest_InstallRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Variable -Name GitTicketTest_TicketRepo -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name GitTicketTest_MsgFile -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name GitTicketTest_InstallRepo -Scope Global -ErrorAction SilentlyContinue
    }

    Describe 'Invoke-GitCommitMsgTicketHook' {
        It 'accepts message containing ticket id (case-insensitive)' -Skip:(-not $global:GitTicketTest_HasGit) {
            Initialize-GitTicketTestRepositories
            Push-Location -LiteralPath $global:GitTicketTest_TicketRepo
            try {
                & git checkout -b 'feature/PROJ-456-desc' 2>$null | Out-Null
                'proj-456: fix' | Set-Content -LiteralPath $global:GitTicketTest_MsgFile -Encoding utf8
                { Invoke-GitCommitMsgTicketHook -CommitMessagePath $global:GitTicketTest_MsgFile -GitRepositoryPath $global:GitTicketTest_TicketRepo } | Should -Not -Throw
            }
            finally {
                Pop-Location
            }
        }

        It 'throws when ticket from branch slug is missing in message' -Skip:(-not $global:GitTicketTest_HasGit) {
            Initialize-GitTicketTestRepositories
            Push-Location -LiteralPath $global:GitTicketTest_TicketRepo
            try {
                & git checkout -b 'bugfix/Test-1234-beschreibung' 2>$null | Out-Null
                'no ticket here' | Set-Content -LiteralPath $global:GitTicketTest_MsgFile -Encoding utf8
                { Invoke-GitCommitMsgTicketHook -CommitMessagePath $global:GitTicketTest_MsgFile -GitRepositoryPath $global:GitTicketTest_TicketRepo } | Should -Throw
            }
            finally {
                Pop-Location
            }
        }

        It 'uses last path segment for ticket (nested branch)' -Skip:(-not $global:GitTicketTest_HasGit) {
            Initialize-GitTicketTestRepositories
            Push-Location -LiteralPath $global:GitTicketTest_TicketRepo
            try {
                & git checkout -b 'feature/foo/Test-1234-x' 2>$null | Out-Null
                'Test-1234 nested' | Set-Content -LiteralPath $global:GitTicketTest_MsgFile -Encoding utf8
                { Invoke-GitCommitMsgTicketHook -CommitMessagePath $global:GitTicketTest_MsgFile -GitRepositoryPath $global:GitTicketTest_TicketRepo } | Should -Not -Throw
            }
            finally {
                Pop-Location
            }
        }

        It 'does not require ticket on exempt branch (master)' -Skip:(-not $global:GitTicketTest_HasGit) {
            Initialize-GitTicketTestRepositories
            Push-Location -LiteralPath $global:GitTicketTest_TicketRepo
            try {
                & git checkout master 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    & git checkout main 2>$null | Out-Null
                }
                'plain message' | Set-Content -LiteralPath $global:GitTicketTest_MsgFile -Encoding utf8
                { Invoke-GitCommitMsgTicketHook -CommitMessagePath $global:GitTicketTest_MsgFile -GitRepositoryPath $global:GitTicketTest_TicketRepo } | Should -Not -Throw
            }
            finally {
                Pop-Location
            }
        }

        It 'skips validation when SKIP_TICKET_HOOK is set' -Skip:(-not $global:GitTicketTest_HasGit) {
            Initialize-GitTicketTestRepositories
            Push-Location -LiteralPath $global:GitTicketTest_TicketRepo
            try {
                & git checkout -b 'feature/ABC-1-x' 2>$null | Out-Null
                'no ticket' | Set-Content -LiteralPath $global:GitTicketTest_MsgFile -Encoding utf8
                $prev = $env:SKIP_TICKET_HOOK
                $env:SKIP_TICKET_HOOK = '1'
                try {
                    { Invoke-GitCommitMsgTicketHook -CommitMessagePath $global:GitTicketTest_MsgFile -GitRepositoryPath $global:GitTicketTest_TicketRepo } | Should -Not -Throw
                }
                finally {
                    if ($null -eq $prev) {
                        Remove-Item Env:\SKIP_TICKET_HOOK -ErrorAction SilentlyContinue
                    }
                    else {
                        $env:SKIP_TICKET_HOOK = $prev
                    }
                }
            }
            finally {
                Pop-Location
            }
        }
    }

    Describe 'Install-GitCommitMsgTicketHook' {
        It 'writes commit-msg and runner under .git/hooks' -Skip:(-not $global:GitTicketTest_HasGit) {
            Initialize-GitTicketTestRepositories
            Install-GitCommitMsgTicketHook -GitRepositoryPath $global:GitTicketTest_InstallRepo
            $hook = Join-Path $global:GitTicketTest_InstallRepo '.git\hooks\commit-msg'
            $runner = Join-Path $global:GitTicketTest_InstallRepo '.git\hooks\commit-msg-ticket-runner.ps1'
            Test-Path -LiteralPath $hook -PathType Leaf | Should -Be $true
            Test-Path -LiteralPath $runner -PathType Leaf | Should -Be $true
            $first = [System.IO.File]::ReadAllLines($hook)[0]
            $first | Should -Be '#!/bin/sh'
            ([System.IO.File]::ReadAllText($hook)) | Should -Match 'wdsh-tools:git-commit-msg-ticket-hook'
        }

        It 'replaces hooks on a second install' -Skip:(-not $global:GitTicketTest_HasGit) {
            Initialize-GitTicketTestRepositories
            $hook = Join-Path $global:GitTicketTest_InstallRepo '.git\hooks\commit-msg'
            [System.IO.File]::WriteAllText($hook, 'stale', (New-Object System.Text.UTF8Encoding $false))
            { Install-GitCommitMsgTicketHook -GitRepositoryPath $global:GitTicketTest_InstallRepo } | Should -Not -Throw
            [System.IO.File]::ReadAllLines($hook)[0] | Should -Be '#!/bin/sh'
        }

        It 'removes hooks via Uninstall-GitCommitMsgTicketHook' -Skip:(-not $global:GitTicketTest_HasGit) {
            Initialize-GitTicketTestRepositories
            Install-GitCommitMsgTicketHook -GitRepositoryPath $global:GitTicketTest_InstallRepo
            Uninstall-GitCommitMsgTicketHook -GitRepositoryPath $global:GitTicketTest_InstallRepo
            $hook = Join-Path $global:GitTicketTest_InstallRepo '.git\hooks\commit-msg'
            $runner = Join-Path $global:GitTicketTest_InstallRepo '.git\hooks\commit-msg-ticket-runner.ps1'
            Test-Path -LiteralPath $hook -PathType Leaf | Should -Be $false
            Test-Path -LiteralPath $runner -PathType Leaf | Should -Be $false
        }
    }
}
