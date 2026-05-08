. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Invoke-KernelDebuggerDumpAnalysis' -Skip:(-not $script:HasArgvProbe) {
    BeforeAll {
        $candidatePaths = @(
            "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework64\v3.5\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework\v3.5\csc.exe"
        )
        $cscExe = $candidatePaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        $script:ProbeExe = Join-Path $TestDrive 'argv-probe-kd.exe'
        $null = New-ArgvProbeExecutable -DestinationPath $script:ProbeExe -CscPath $cscExe
    }

    It 'AnalyzeThenQuit includes !analyze -v;q and dump path' {
        $output = InModuleScope $script:ModuleName -ArgumentList $script:ProbeExe -ScriptBlock {
            param($Exe)
            Invoke-KernelDebuggerDumpAnalysis -DebuggerExecutable $Exe -DumpFile 'C:\Dumps With Space\crash.dmp' -InitialCommandMode AnalyzeThenQuit
        }
        $output[0] | Should -Be '[0]={-c}'
        $output[1] | Should -Be '[1]={!analyze -v;q}'
        $output[3] | Should -Be '[3]={C:\Dumps With Space\crash.dmp}'
    }

    It 'AnalyzeStayOpen includes !analyze -v; and dump path' {
        $output = InModuleScope $script:ModuleName -ArgumentList $script:ProbeExe -ScriptBlock {
            param($Exe)
            Invoke-KernelDebuggerDumpAnalysis -DebuggerExecutable $Exe -DumpFile 'C:\Dumps With Space\crash.dmp' -InitialCommandMode AnalyzeStayOpen
        }
        $output[1] | Should -Be '[1]={!analyze -v;}'
        $output[3] | Should -Be '[3]={C:\Dumps With Space\crash.dmp}'
    }
}
