. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Find-Symbols' {
    It 'throws when the path does not exist' {
        $missing = Join-Path $TestDrive 'missing.dll'
        { Find-Symbols -Path $missing } | Should -Throw
    }

    Context 'invokes symchk with the expected switches' -Skip:(-not $script:IsWindowsOs) {
        BeforeEach {
            $script:SymTarget = Join-Path $TestDrive 'sym-target.dll'
            [System.IO.File]::WriteAllBytes($script:SymTarget, [byte[]](0x4D, 0x5A))
            $script:SymTarget = (Resolve-Path -LiteralPath $script:SymTarget).Path
            $script:SymOutDir = Join-Path $TestDrive 'sym-download'
            New-Item -ItemType Directory -Path $script:SymOutDir -Force | Out-Null
            $script:SymOutDir = (Resolve-Path -LiteralPath $script:SymOutDir).Path

            Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Type', [string])
                $r = $dt.NewRow()
                $r.Type = 'x64'
                [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Get-SymbolCheck {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Path', [string])
                [void]$dt.Columns.Add('WDK', [string])
                [void]$dt.Columns.Add('Bitness', [string])
                $r = $dt.NewRow()
                $r.Path = 'C:\FakeKits\10\Debuggers\x64\symchk.exe'
                $r.WDK = '10'
                $r.Bitness = 'x64'
                [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Invoke-SymChkArguments { }
        }

        It 'runs symchk with /r only by default' {
            Find-Symbols -Path $script:SymTarget
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $SymChkExecutable -eq 'C:\FakeKits\10\Debuggers\x64\symchk.exe' -and
                    $TargetPath -eq $script:SymTarget -and
                    -not $DownloadTo -and
                    -not $Detailed
            }
        }

        It 'runs symchk once per path when multiple paths are passed' {
            $second = Join-Path $TestDrive 'sym-target2.dll'
            [System.IO.File]::WriteAllBytes($second, [byte[]](0x4D, 0x5A))
            $secondResolved = (Resolve-Path -LiteralPath $second).Path
            Find-Symbols -Path @($script:SymTarget, $secondResolved)
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 2
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter { $TargetPath -eq $script:SymTarget }
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter { $TargetPath -eq $secondResolved }
        }

        It 'accumulates FullName paths from pipeline input' {
            $second = Join-Path $TestDrive 'sym-target2.dll'
            [System.IO.File]::WriteAllBytes($second, [byte[]](0x4D, 0x5A))
            $secondResolved = (Resolve-Path -LiteralPath $second).Path
            Get-Item -LiteralPath $script:SymTarget, $secondResolved | Find-Symbols
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 2
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter { $TargetPath -eq $script:SymTarget }
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter { $TargetPath -eq $secondResolved }
        }

        It 'passes -DownloadTo to every symchk run when piping multiple paths' {
            $second = Join-Path $TestDrive 'sym-target2.dll'
            [System.IO.File]::WriteAllBytes($second, [byte[]](0x4D, 0x5A))
            $secondResolved = (Resolve-Path -LiteralPath $second).Path
            Get-Item -LiteralPath $script:SymTarget, $secondResolved | Find-Symbols -DownloadTo $script:SymOutDir
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 2 -ParameterFilter {
                $DownloadTo -eq $script:SymOutDir -and -not $Detailed
            }
        }

        It 'adds /v when -Detailed is set' {
            Find-Symbols -Path $script:SymTarget -Detailed
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $Detailed -eq $true -and $TargetPath -eq $script:SymTarget -and -not $DownloadTo
            }
        }

        It 'adds /oc when -DownloadTo is set' {
            Find-Symbols -Path $script:SymTarget -DownloadTo $script:SymOutDir
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $DownloadTo -eq $script:SymOutDir -and -not $Detailed
            }
        }

        It 'combines /v and /oc when both switches are used' {
            Find-Symbols -Path $script:SymTarget -Detailed -DownloadTo $script:SymOutDir
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $Detailed -eq $true -and $DownloadTo -eq $script:SymOutDir
            }
        }
    }

    Context 'selects the symchk that matches the current OS architecture' -Skip:(-not $script:IsWindowsOs) {
        BeforeEach {
            $script:SymTarget = Join-Path $TestDrive 'arch-target.dll'
            [System.IO.File]::WriteAllBytes($script:SymTarget, [byte[]](0x4D, 0x5A))
            $script:SymTarget = (Resolve-Path -LiteralPath $script:SymTarget).Path

            Mock -ModuleName $script:ModuleName Get-SymbolCheck {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Path', [string])
                [void]$dt.Columns.Add('WDK', [string])
                [void]$dt.Columns.Add('Bitness', [string])
                foreach ($pair in @(
                        @{ Bitness = 'arm64'; Path = 'C:\FakeKits\10\Debuggers\arm64\symchk.exe' },
                        @{ Bitness = 'x64';   Path = 'C:\FakeKits\10\Debuggers\x64\symchk.exe' },
                        @{ Bitness = 'x86';   Path = 'C:\FakeKits\10\Debuggers\x86\symchk.exe' }
                    )) {
                    $r = $dt.NewRow()
                    $r.Path = $pair.Path
                    $r.WDK = '10'
                    $r.Bitness = $pair.Bitness
                    [void]$dt.Rows.Add($r)
                }
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Invoke-SymChkArguments { }
        }

        It 'picks the x64 symchk on x64 Windows even when arm64 sorts first alphabetically' {
            Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Type', [string])
                $r = $dt.NewRow(); $r.Type = 'x64'; [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Find-Symbols -Path $script:SymTarget
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $SymChkExecutable -eq 'C:\FakeKits\10\Debuggers\x64\symchk.exe'
            }
        }

        It 'picks the x86 symchk on x86 Windows' {
            Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Type', [string])
                $r = $dt.NewRow(); $r.Type = 'x86'; [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Find-Symbols -Path $script:SymTarget
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $SymChkExecutable -eq 'C:\FakeKits\10\Debuggers\x86\symchk.exe'
            }
        }

        It 'picks the arm64 symchk on arm64 Windows' {
            Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Type', [string])
                $r = $dt.NewRow(); $r.Type = 'arm64'; [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Find-Symbols -Path $script:SymTarget
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $SymChkExecutable -eq 'C:\FakeKits\10\Debuggers\arm64\symchk.exe'
            }
        }

        It 'falls back to x64 symchk on arm64 Windows when no native arm64 symchk is installed' {
            Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Type', [string])
                $r = $dt.NewRow(); $r.Type = 'arm64'; [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Get-SymbolCheck {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Path', [string])
                [void]$dt.Columns.Add('WDK', [string])
                [void]$dt.Columns.Add('Bitness', [string])
                $r = $dt.NewRow()
                $r.Path = 'C:\FakeKits\10\Debuggers\x64\symchk.exe'
                $r.WDK = '10'
                $r.Bitness = 'x64'
                [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Find-Symbols -Path $script:SymTarget
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $SymChkExecutable -eq 'C:\FakeKits\10\Debuggers\x64\symchk.exe'
            }
        }

        It 'prefers the newest WDK when multiple kits ship the same architecture' {
            Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Type', [string])
                $r = $dt.NewRow(); $r.Type = 'x64'; [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Get-SymbolCheck {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Path', [string])
                [void]$dt.Columns.Add('WDK', [string])
                [void]$dt.Columns.Add('Bitness', [string])
                foreach ($pair in @(
                        @{ Wdk = '10'; Path = 'C:\FakeKits\10\Debuggers\x64\symchk.exe' },
                        @{ Wdk = '11'; Path = 'C:\FakeKits\11\Debuggers\x64\symchk.exe' }
                    )) {
                    $r = $dt.NewRow()
                    $r.Path = $pair.Path
                    $r.WDK = $pair.Wdk
                    $r.Bitness = 'x64'
                    [void]$dt.Rows.Add($r)
                }
                return ,$dt
            }
            Find-Symbols -Path $script:SymTarget
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $SymChkExecutable -eq 'C:\FakeKits\11\Debuggers\x64\symchk.exe'
            }
        }

        It 'throws when no symchk row matches the current OS architecture' {
            Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Type', [string])
                $r = $dt.NewRow(); $r.Type = 'x64'; [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Get-SymbolCheck {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Path', [string])
                [void]$dt.Columns.Add('WDK', [string])
                [void]$dt.Columns.Add('Bitness', [string])
                $r = $dt.NewRow()
                $r.Path = 'C:\FakeKits\10\Debuggers\arm\symchk.exe'
                $r.WDK = '10'
                $r.Bitness = 'arm'
                [void]$dt.Rows.Add($r)
                return ,$dt
            }
            { Find-Symbols -Path $script:SymTarget } | Should -Throw -ExpectedMessage '*matching the current OS architecture*'
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 0
        }
    }
}


