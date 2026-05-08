. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-AuthenticodeSignerInfosForFile' -Skip:(-not $script:IsWindowsOs) {
    It 'returns signer infos for a known signed system binary' {
        $picked = $null
        foreach ($rel in @('System32\ntdll.dll','System32\kernel32.dll','System32\win32u.dll')) {
            $full = Join-Path $env:SystemRoot $rel
            if (-not (Test-Path -LiteralPath $full)) { continue }
            $signers = InModuleScope $script:ModuleName -ArgumentList $full -ScriptBlock {
                param($FilePath)
                Get-AuthenticodeSignerInfosForFile -FilePath $FilePath
            }
            if ($null -ne $signers -and @($signers).Count -gt 0) {
                $picked = $full
                break
            }
        }
        $picked | Should -Not -BeNullOrEmpty
    }

    It 'returns an empty signer list for an unsigned file' {
        $unsigned = Join-Path $TestDrive 'unsigned.bin'
        [System.IO.File]::WriteAllBytes($unsigned, [byte[]](1,2,3,4))
        $list = InModuleScope $script:ModuleName -ArgumentList $unsigned -ScriptBlock {
            param($FilePath)
            Get-AuthenticodeSignerInfosForFile -FilePath $FilePath
        }
        @($list).Count | Should -Be 0
    }
}
