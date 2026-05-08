. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-EicarSignature' {
    It 'returns the EICAR test string' {
        $table = Get-ModuleDataTableResult -Name 'Get-EicarSignature'
        $signature = Get-TestDataTableValue -Table $table -RowIndex 0 -ColumnName 'Signature'
        $signature | Should -Match 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'
    }
}


