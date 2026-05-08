. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-DumpAnalysis and Open-DumpAnalysis' {
    It 'Get-DumpAnalysis throws when the dump file is missing' {
        $missing = Join-Path $TestDrive 'nope.dmp'
        { Get-DumpAnalysis -File $missing } | Should -Throw
    }

    It 'Open-DumpAnalysis throws when the dump file is missing' {
        $missing = Join-Path $TestDrive 'nope.dmp'
        { Open-DumpAnalysis -File $missing } | Should -Throw
    }

    Context 'invokes the kernel debugger shim when a matching debugger row exists' -Skip:(-not $script:IsWindowsOs) {
        BeforeEach {
            $script:DumpTestFile = Join-Path $TestDrive 'minimal.dmp'
            [System.IO.File]::WriteAllBytes($script:DumpTestFile, [byte[]](0x4D, 0x44, 0x4D, 0x50))
            $script:DumpTestFile = (Resolve-Path -LiteralPath $script:DumpTestFile).Path

            Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Type', [string])
                $r = $dt.NewRow()
                $r.Type = 'x64'
                [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Get-KernelDebuggerPath {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Path', [string])
                [void]$dt.Columns.Add('WDK', [string])
                [void]$dt.Columns.Add('Bitness', [string])
                $r = $dt.NewRow()
                $r.Path = 'C:\FakeKits\10\Debuggers\x64\kd.exe'
                $r.WDK = '10'
                $r.Bitness = 'x64'
                [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Invoke-KernelDebuggerDumpAnalysis { }
        }

        It 'Get-DumpAnalysis requests AnalyzeThenQuit' {
            Get-DumpAnalysis -File $script:DumpTestFile
            Should -Invoke -CommandName Invoke-KernelDebuggerDumpAnalysis -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $DebuggerExecutable -eq 'C:\FakeKits\10\Debuggers\x64\kd.exe' -and
                    $DumpFile -eq $script:DumpTestFile -and
                    $InitialCommandMode -eq 'AnalyzeThenQuit'
            }
        }

        It 'Open-DumpAnalysis requests AnalyzeStayOpen' {
            Open-DumpAnalysis -File $script:DumpTestFile
            Should -Invoke -CommandName Invoke-KernelDebuggerDumpAnalysis -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $DebuggerExecutable -eq 'C:\FakeKits\10\Debuggers\x64\kd.exe' -and
                    $DumpFile -eq $script:DumpTestFile -and
                    $InitialCommandMode -eq 'AnalyzeStayOpen'
            }
        }
    }
}


