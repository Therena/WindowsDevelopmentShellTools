. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-GlobalAssemblyCache' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        Mock -ModuleName $script:ModuleName Get-ItemProperty {
            [pscustomobject]@{
                'System.Runtime,4.0.0.0,,,MSIL' = $null
            }
        } -ParameterFilter {
            # Provider-qualified paths also appear as e.g. Microsoft.PowerShell.Core\Registry::...
            "$Path" -like '*Fusion*GACChangeNotification*Default*'
        }
    }

    It 'returns a DataTable with expected columns and parses Fusion-style value names' {
        $t = Get-ModuleDataTableResult -Name 'Get-GlobalAssemblyCache'
        @('Assembly', 'Version', 'ProcessorArchitecture') | ForEach-Object {
            $t.Columns[$_].ColumnName | Should -Be $_
        }
        $t.Rows.Count | Should -BeGreaterThan 0
        $t.Rows[0]['Assembly'] | Should -Be 'System.Runtime'
        $t.Rows[0]['ProcessorArchitecture'] | Should -Be 'MSIL'
    }
}

