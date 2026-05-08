. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Select-WindowsKitFileForOs' {
    It 'selects newest matching WDK for x64' {
        InModuleScope $script:ModuleName {
            $dt = New-Object System.Data.DataTable
            [void]$dt.Columns.Add('Path', [string])
            [void]$dt.Columns.Add('WDK', [string])
            [void]$dt.Columns.Add('Bitness', [string])

            foreach ($rowData in @(
                    @{ Path = 'C:\Kits\10\x64\symchk.exe'; WDK = '10'; Bitness = 'x64' },
                    @{ Path = 'C:\Kits\11\x64\symchk.exe'; WDK = '11'; Bitness = 'x64' }
                )) {
                $r = $dt.NewRow(); $r.Path = $rowData.Path; $r.WDK = $rowData.WDK; $r.Bitness = $rowData.Bitness
                [void]$dt.Rows.Add($r)
            }

            Mock Get-OperatingSystemBitness {
                $t = New-Object System.Data.DataTable
                [void]$t.Columns.Add('Type', [string])
                $x = $t.NewRow(); $x.Type = 'x64'; [void]$t.Rows.Add($x)
                return ,$t
            }

            $selected = Select-WindowsKitFileForOs -KitTable $dt
            $selected.Path | Should -Be 'C:\Kits\11\x64\symchk.exe'
        }
    }

    It 'falls back from arm64 to x64 when arm64 is unavailable' {
        InModuleScope $script:ModuleName {
            $dt = New-Object System.Data.DataTable
            [void]$dt.Columns.Add('Path', [string])
            [void]$dt.Columns.Add('WDK', [string])
            [void]$dt.Columns.Add('Bitness', [string])
            $r = $dt.NewRow(); $r.Path = 'C:\Kits\11\x64\symchk.exe'; $r.WDK = '11'; $r.Bitness = 'x64'; [void]$dt.Rows.Add($r)

            Mock Get-OperatingSystemBitness {
                $t = New-Object System.Data.DataTable
                [void]$t.Columns.Add('Type', [string])
                $x = $t.NewRow(); $x.Type = 'arm64'; [void]$t.Rows.Add($x)
                return ,$t
            }

            $selected = Select-WindowsKitFileForOs -KitTable $dt
            $selected.Bitness | Should -Be 'x64'
        }
    }

    It 'returns null when no candidate matches the OS preference order' {
        InModuleScope $script:ModuleName {
            $dt = New-Object System.Data.DataTable
            [void]$dt.Columns.Add('Path', [string])
            [void]$dt.Columns.Add('WDK', [string])
            [void]$dt.Columns.Add('Bitness', [string])
            $r = $dt.NewRow(); $r.Path = 'C:\Kits\10\arm\symchk.exe'; $r.WDK = '10'; $r.Bitness = 'arm'; [void]$dt.Rows.Add($r)

            Mock Get-OperatingSystemBitness {
                $t = New-Object System.Data.DataTable
                [void]$t.Columns.Add('Type', [string])
                $x = $t.NewRow(); $x.Type = 'x64'; [void]$t.Rows.Add($x)
                return ,$t
            }

            $selected = Select-WindowsKitFileForOs -KitTable $dt
            $selected | Should -BeNullOrEmpty
        }
    }
}
