. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-HexDump' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        $script:HexFile = Join-Path $TestDrive 'hex.bin'
        [System.IO.File]::WriteAllBytes($script:HexFile, [byte[]](0x4D, 0x5A, 0x90, 0x00))
    }

    It 'returns a hex string starting with an offset line' {
        $out = Get-HexDump -File $script:HexFile -Width 2
        $out | Should -Match '0000:'
        $out | Should -Match '4d 5a'
    }
}


