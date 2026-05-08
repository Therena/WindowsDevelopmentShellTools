. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-OperatingSystemBitness' {
    It 'returns one of the supported Windows Kit Debuggers subdirectory names' {
        $table = Get-ModuleDataTableResult -Name 'Get-OperatingSystemBitness'
        $type = Get-TestDataTableValue -Table $table -RowIndex 0 -ColumnName 'Type'
        $type | Should -BeIn @('arm64', 'arm', 'x64', 'x86')
    }
}


