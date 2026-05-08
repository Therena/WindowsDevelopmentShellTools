. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-AuthenticodeDetails integration' -Skip:(-not $script:IsWindowsOs) {
    It 'Get-AuthenticodeSignerInfosForFile returns PKCS signers for a common system PE' {
        $picked = $null
        foreach ($rel in @(
                'System32\ntdll.dll',
                'System32\kernel32.dll',
                'System32\win32u.dll',
                'SysWOW64\ntdll.dll'
            )) {
            $full = Join-Path $env:SystemRoot $rel
            if (-not (Test-Path -LiteralPath $full)) {
                continue
            }
            $list = InModuleScope $script:ModuleName -ArgumentList $full -ScriptBlock {
                param($FilePath)
                Get-AuthenticodeSignerInfosForFile -FilePath $FilePath
            }
            if ($null -ne $list -and @($list).Count -gt 0) {
                $picked = $full
                break
            }
        }
        $picked | Should -Not -BeNullOrEmpty
    }

    It 'Get-AuthenticodeDetails returns certificate rows for a system file with embedded PKCS' {
        $picked = $null
        $table = $null
        foreach ($rel in @('System32\ntdll.dll', 'System32\kernel32.dll', 'System32\win32u.dll')) {
            $full = Join-Path $env:SystemRoot $rel
            if (-not (Test-Path -LiteralPath $full)) {
                continue
            }
            $t = Get-ModuleDataTableResult -Name 'Get-AuthenticodeDetails' -Parameters @{ File = $full }
            if ($t.Rows.Count -gt 0) {
                $picked = $full
                $table = $t
                break
            }
        }
        $picked | Should -Not -BeNullOrEmpty
        $table.Rows[0]['Subject'] | Should -Not -BeNullOrEmpty
        $table.Rows[0]['Thumbprint'] | Should -Match '^[0-9A-F]{40}$'
    }
}


