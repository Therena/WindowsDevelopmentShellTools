. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Connect-KernelDebugger' {
    It 'does not throw when no debugger is found (no-op)' {
        Mock -ModuleName $script:ModuleName Get-DebuggerPath {
            $dt = New-Object System.Data.DataTable
            [void]$dt.Columns.Add('Path', [string])
            [void]$dt.Columns.Add('WDK', [string])
            [void]$dt.Columns.Add('Bitness', [string])
            return ,$dt
        }
        Mock -ModuleName $script:ModuleName Invoke-WinDbgKernelRemotePipe { throw 'should not be called' }
        { Connect-KernelDebugger -Host 'localhost' -Port 'test-pipe' } | Should -Not -Throw
        Should -Invoke -CommandName Invoke-WinDbgKernelRemotePipe -ModuleName $script:ModuleName -Times 0
    }

    It 'starts WinDbg with the kernel pipe when a debugger row exists' -Skip:(-not $script:IsWindowsOs) {
        Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
            $dt = New-Object System.Data.DataTable
            [void]$dt.Columns.Add('Type', [string])
            $r = $dt.NewRow()
            $r.Type = 'x64'
            [void]$dt.Rows.Add($r)
            return ,$dt
        }
        Mock -ModuleName $script:ModuleName Get-DebuggerPath {
            $dt = New-Object System.Data.DataTable
            [void]$dt.Columns.Add('Path', [string])
            [void]$dt.Columns.Add('WDK', [string])
            [void]$dt.Columns.Add('Bitness', [string])
            $r = $dt.NewRow()
            $r.Path = 'C:\FakeKits\10\Debuggers\x64\windbg.exe'
            $r.WDK = '10'
            $r.Bitness = 'x64'
            [void]$dt.Rows.Add($r)
            return ,$dt
        }
        Mock -ModuleName $script:ModuleName Invoke-WinDbgKernelRemotePipe { }

        Connect-KernelDebugger -Host 'srv01' -Port 'MYPIPE'

        Should -Invoke -CommandName Invoke-WinDbgKernelRemotePipe -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
            $DebuggerExecutable -eq 'C:\FakeKits\10\Debuggers\x64\windbg.exe' -and
                $RemoteHost -eq 'srv01' -and
                $PipeName -eq 'MYPIPE'
        }
    }
}


