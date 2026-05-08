function Connect-KernelDebugger {
<#

.SYNOPSIS
Connects WinDbg to a remote kernel debugging pipe.

.DESCRIPTION
Selects windbg.exe for the current OS bitness from the newest Windows Kit, then starts it with kernel debug over a COM-named pipe to \\Host\pipe\Port (pipe name is supplied via the Port parameter).

.PARAMETER Host
Remote computer name or address that exposes the debugging pipe.

.PARAMETER Port
Named pipe name on the host (not a TCP port).

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Connect-KernelDebugger -Host wtth0002 -Port DR-TEST-10

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$Host,

        [parameter(Mandatory=$true)]
        [string]$Port        
    )
    

    $BestSelectionDebugger = Select-WindowsKitFileForOs -KitTable (Get-DebuggerPath)

    if ($null -ne $BestSelectionDebugger) {
        Invoke-WinDbgKernelRemotePipe -DebuggerExecutable $BestSelectionDebugger.Path -RemoteHost $Host -PipeName $Port
    }
}
