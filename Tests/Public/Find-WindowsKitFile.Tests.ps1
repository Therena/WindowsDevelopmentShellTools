. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Find-WindowsKitFile' {
    BeforeAll {
        Mock Get-ChildItem {
            $dir = [pscustomobject]@{
                Name     = 'x64'
                Parent   = [pscustomobject]@{
                    Name   = 'Debuggers'
                    Parent = [pscustomobject]@{ Name = '10' }
                }
            }
            [pscustomobject]@{
                FullName  = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe'
                Directory = $dir
            }
        } -ParameterFilter {
            $Path -like '*Windows Kits*' -and $Recurse -and $Filter -eq 'windbg.exe' -and $File
        }
    }

    It 'returns a DataTable with Path, WDK, and Bitness columns' {
        $table = Get-ModuleDataTableResult -Name 'Find-WindowsKitFile' -Parameters @{ File = 'windbg.exe' }
        @('Path', 'WDK', 'Bitness') | ForEach-Object { $table.Columns[$_].ColumnName | Should -Be $_ }
    }

    It 'maps directory layout into at least one row' {
        $table = Get-ModuleDataTableResult -Name 'Find-WindowsKitFile' -Parameters @{ File = 'windbg.exe' }
        $table.Rows.Count | Should -BeGreaterThan 0
        $row = $table.Rows[0]
        $row.Path | Should -Match 'windbg\.exe$'
        $row.WDK | Should -Not -BeNullOrEmpty
        $row.Bitness | Should -Match '^(x64|x86|arm|arm64)$'
    }
}


