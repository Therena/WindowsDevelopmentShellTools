. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Invoke-SymChkArguments' -Skip:(-not $script:HasArgvProbe) {
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

    It 'passes target path and /r by default' {
        $output = InModuleScope $script:ModuleName -ArgumentList $script:ProbeExe -ScriptBlock {
            param($Exe)
            Invoke-SymChkArguments -SymChkExecutable $Exe -TargetPath 'C:\Path With Spaces\foo.dll'
        }
        $output | Should -Contain '[0]={C:\Path With Spaces\foo.dll}'
        $output | Should -Contain '[1]={/r}'
    }

    It 'adds /v and /oc arguments when Detailed and DownloadTo are set' {
        $output = InModuleScope $script:ModuleName -ArgumentList $script:ProbeExe -ScriptBlock {
            param($Exe)
            Invoke-SymChkArguments -SymChkExecutable $Exe -TargetPath 'C:\Path With Spaces\foo.dll' -DownloadTo '.\sym out' -Detailed
        }
        $output[2] | Should -Be '[2]={/v}'
        $output[3] | Should -Be '[3]={/oc}'
        $output[4] | Should -Be '[4]={.\sym out}'
    }
}
