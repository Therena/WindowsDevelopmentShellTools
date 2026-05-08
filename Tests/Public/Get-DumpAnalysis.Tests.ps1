. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-DumpAnalysis' {
    It 'throws when the dump file is missing' {
        $missing = Join-Path $TestDrive 'nope.dmp'
        { Get-DumpAnalysis -File $missing } | Should -Throw
    }

    It 'requests AnalyzeThenQuit when debugger path is resolved' -Skip:(-not $script:IsWindowsOs) {
        $dump = Join-Path $TestDrive 'minimal.dmp'
        [System.IO.File]::WriteAllBytes($dump, [byte[]](0x4D,0x44,0x4D,0x50))
        $dump = (Resolve-Path -LiteralPath $dump).Path

        Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
            $dt = New-Object System.Data.DataTable; [void]$dt.Columns.Add('Type',[string]); $r=$dt.NewRow(); $r.Type='x64'; [void]$dt.Rows.Add($r); return ,$dt
        }
        Mock -ModuleName $script:ModuleName Get-KernelDebuggerPath {
            $dt = New-Object System.Data.DataTable
            [void]$dt.Columns.Add('Path',[string]); [void]$dt.Columns.Add('WDK',[string]); [void]$dt.Columns.Add('Bitness',[string])
            $r=$dt.NewRow(); $r.Path='C:\FakeKits\10\Debuggers\x64\kd.exe'; $r.WDK='10'; $r.Bitness='x64'; [void]$dt.Rows.Add($r); return ,$dt
        }
        Mock -ModuleName $script:ModuleName Invoke-KernelDebuggerDumpAnalysis { }

        Get-DumpAnalysis -File $dump
        Should -Invoke -CommandName Invoke-KernelDebuggerDumpAnalysis -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
            $InitialCommandMode -eq 'AnalyzeThenQuit' -and $DumpFile -eq $dump
        }
    }
}
