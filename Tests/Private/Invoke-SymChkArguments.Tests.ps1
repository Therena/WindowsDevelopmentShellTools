. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Native command argument forwarding' -Skip:(-not $script:HasArgvProbe) {
    BeforeAll {
        $candidatePaths = @(
            "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework64\v3.5\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework\v3.5\csc.exe"
        )
        $cscExe = $candidatePaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        $script:ProbeExe = Join-Path $TestDrive 'argv-probe.exe'
        $null = New-ArgvProbeExecutable -DestinationPath $script:ProbeExe -CscPath $cscExe
    }

    Context 'Invoke-SymChkArguments forwards paths verbatim (no embedded quotes)' {
        It 'passes only the target path with /r when no extras are set' {
            $output = InModuleScope $script:ModuleName -ArgumentList $script:ProbeExe -ScriptBlock {
                param($Exe)
                Invoke-SymChkArguments -SymChkExecutable $Exe -TargetPath 'C:\Path With Spaces\foo.dll'
            }
            $output | Should -Contain '[0]={C:\Path With Spaces\foo.dll}'
            $output | Should -Contain '[1]={/r}'
            ($output | Where-Object { $_ -match '/v|/oc' }) | Should -BeNullOrEmpty
            ($output -join "`n") | Should -Not -Match '"'
        }

        It 'adds /v and /oc <download> when -Detailed and -DownloadTo are set' {
            $output = InModuleScope $script:ModuleName -ArgumentList $script:ProbeExe -ScriptBlock {
                param($Exe)
                Invoke-SymChkArguments -SymChkExecutable $Exe -TargetPath 'C:\Path With Spaces\foo.dll' -DownloadTo '.\sym out' -Detailed
            }
            $output[0] | Should -Be '[0]={C:\Path With Spaces\foo.dll}'
            $output[1] | Should -Be '[1]={/r}'
            $output[2] | Should -Be '[2]={/v}'
            $output[3] | Should -Be '[3]={/oc}'
            $output[4] | Should -Be '[4]={.\sym out}'
            ($output -join "`n") | Should -Not -Match '"'
        }
    }

    Context 'Invoke-KernelDebuggerDumpAnalysis forwards paths verbatim (no embedded quotes)' {
        It 'AnalyzeThenQuit produces -c !analyze -v;q -z <path>' {
            $output = InModuleScope $script:ModuleName -ArgumentList $script:ProbeExe -ScriptBlock {
                param($Exe)
                Invoke-KernelDebuggerDumpAnalysis -DebuggerExecutable $Exe -DumpFile 'C:\Dumps With Space\crash.dmp' -InitialCommandMode AnalyzeThenQuit
            }
            $output[0] | Should -Be '[0]={-c}'
            $output[1] | Should -Be '[1]={!analyze -v;q}'
            $output[2] | Should -Be '[2]={-z}'
            $output[3] | Should -Be '[3]={C:\Dumps With Space\crash.dmp}'
            ($output -join "`n") | Should -Not -Match '"'
        }

        It 'AnalyzeStayOpen produces -c !analyze -v; -z <path>' {
            $output = InModuleScope $script:ModuleName -ArgumentList $script:ProbeExe -ScriptBlock {
                param($Exe)
                Invoke-KernelDebuggerDumpAnalysis -DebuggerExecutable $Exe -DumpFile 'C:\Dumps With Space\crash.dmp' -InitialCommandMode AnalyzeStayOpen
            }
            $output[1] | Should -Be '[1]={!analyze -v;}'
            $output[3] | Should -Be '[3]={C:\Dumps With Space\crash.dmp}'
            ($output -join "`n") | Should -Not -Match '"'
        }
    }
}


