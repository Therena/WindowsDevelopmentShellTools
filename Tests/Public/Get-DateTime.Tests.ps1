. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-DateTime' {
    It 'returns four time formats' {
        $table = Get-ModuleDataTableResult -Name 'Get-DateTime'
        # DataTable is IEnumerable; piping it to Should enumerates rows Ã¢â‚¬â€ use unary comma.
        ,$table | Should -BeOfType [System.Data.DataTable]
        $table.Rows.Count | Should -Be 4
        $formats = foreach ($row in $table.Rows) { $row['Format'] }
        $formats | Should -Contain 'Unix Time'
        $formats | Should -Contain 'ISO Date'
    }
}



