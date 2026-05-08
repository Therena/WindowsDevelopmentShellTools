function Invoke-WinDbgKernelRemotePipe {
<#

.SYNOPSIS
Starts WinDbg-style kernel debugging over a named pipe to a remote host.

.DESCRIPTION
Launches the debugger with -n and -k com:pipe targeting \\RemoteHost\pipe\PipeName. Used by Connect-KernelDebugger. This command is not exported from the module.

.PARAMETER DebuggerExecutable
Full path to windbg.exe (or compatible).

.PARAMETER RemoteHost
Remote machine name or address hosting the kernel debug pipe.

.PARAMETER PipeName
Named pipe segment (combined with the host to form the full pipe path).

#>
    param(
        [Parameter(Mandatory)]
        [string]$DebuggerExecutable,
        [Parameter(Mandatory)]
        [string]$RemoteHost,
        [Parameter(Mandatory)]
        [string]$PipeName
    )
    $kernelPipeArg = "com:pipe,port=\\$RemoteHost\pipe\$PipeName,resets=0,reconnect"
    & $DebuggerExecutable -n -k $kernelPipeArg
}
