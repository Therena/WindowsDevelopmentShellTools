. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-FileDetails' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        $script:FileDetailsTarget = Join-Path $TestDrive 'filedetails-copy.exe'
        $src = $null
        foreach ($name in @('notepad.exe', 'cmd.exe', 'explorer.exe')) {
            $p = Join-Path $env:SystemRoot "System32\$name"
            if (Test-Path -LiteralPath $p) {
                $src = $p
                break
            }
        }
        if (-not $src) {
            throw 'No suitable System32 executable found to copy for Get-FileDetails test.'
        }
        Copy-Item -LiteralPath $src -Destination $script:FileDetailsTarget -Force
        $script:FileDetailsTarget = (Resolve-Path -LiteralPath $script:FileDetailsTarget).Path
    }

    It 'returns version metadata for a copied System32 executable' {
        $t = Get-ModuleDataTableResult -Name 'Get-FileDetails' -Parameters @{ File = $script:FileDetailsTarget }
        $t.Rows.Count | Should -BeGreaterThan 0
        $t.Rows[0]['File'] | Should -Be $script:FileDetailsTarget
        $t.Rows[0]['CompanyName'] | Should -Not -BeNullOrEmpty
    }
}


