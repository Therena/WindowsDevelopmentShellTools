. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-DebuggerPath, Get-KernelDebuggerPath, Get-SymbolCheck' {
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
                FullName  = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\$Filter"
                Directory = $dir
            }
        } -ParameterFilter {
            $Path -like '*Windows Kits*' -and $Recurse -and $Filter -and $File
        }
    }

    It 'Get-DebuggerPath searches for windbg.exe' {
        $t = Get-ModuleDataTableResult -Name 'Get-DebuggerPath'
        (Get-TestDataTableValue -Table $t -RowIndex 0 -ColumnName 'Path') | Should -Match 'windbg\.exe$'
    }

    It 'Get-KernelDebuggerPath searches for kd.exe' {
        $t = Get-ModuleDataTableResult -Name 'Get-KernelDebuggerPath'
        (Get-TestDataTableValue -Table $t -RowIndex 0 -ColumnName 'Path') | Should -Match 'kd\.exe$'
    }

    It 'Get-SymbolCheck searches for symchk.exe' {
        $t = Get-ModuleDataTableResult -Name 'Get-SymbolCheck'
        (Get-TestDataTableValue -Table $t -RowIndex 0 -ColumnName 'Path') | Should -Match 'symchk\.exe$'
    }
}


