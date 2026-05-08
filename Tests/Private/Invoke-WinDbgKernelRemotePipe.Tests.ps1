. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Invoke-WinDbgKernelRemotePipe' -Skip:(-not $script:HasArgvProbe) {
    BeforeAll {
        $candidatePaths = @(
            "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework64\v3.5\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework\v3.5\csc.exe"
        )
        $cscExe = $candidatePaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        $script:ProbeExe = Join-Path $TestDrive 'argv-probe-windbg.exe'
        $null = New-ArgvProbeExecutable -DestinationPath $script:ProbeExe -CscPath $cscExe
    }

    It 'forwards -n and -k with remote pipe parameters' {
        $output = InModuleScope $script:ModuleName -ArgumentList $script:ProbeExe -ScriptBlock {
            param($Exe)
            Invoke-WinDbgKernelRemotePipe -DebuggerExecutable $Exe -RemoteHost 'srv01' -PipeName 'MYPIPE'
        }
        $output[0] | Should -Be '[0]={-n}'
        $output[1] | Should -Be '[1]={-k}'
        $output[2] | Should -Match '^\[2\]=\{com:pipe,port=\\\\srv01\\pipe\\MYPIPE,resets=0,reconnect\}$'
    }
}
