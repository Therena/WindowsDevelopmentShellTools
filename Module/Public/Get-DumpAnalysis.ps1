function Get-DumpAnalysis {
<#

.SYNOPSIS
Runs crash dump analysis through the installed kernel debugger.

.DESCRIPTION
Resolves kd.exe (or equivalent) for the current OS bitness from the newest installed Windows Kit, then runs !analyze -v on the dump and quits the debugger when finished. Output is whatever the debugger writes to the console.

.PARAMETER File
Path to the crash dump file (.dmp).

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-DumpAnalysis -File "dwm.exe.1168.dmp"

Microsoft (R) Windows Debugger Version 10.0.17134.1 AMD64
Copyright (c) Microsoft Corporation. All rights reserved.


Loading Dump File [dwm.exe.1168.dmp]
User Mini Dump File with Full Memory: Only application data is available


************* Path validation summary **************
Response                         Time (ms)     Location
Deferred                                       srv*http://msdl.microsoft.com/download/symbols
Executable search path is: 
Windows 10 Version 16299 MP (4 procs) Free x86 compatible
Product: WinNt, suite: SingleUserTS
16299.15.x86fre.rs3_release.170928-1534
Machine Name:
Debug session time: Wed Oct 24 05:51:28.000 2018 (UTC + 2:00)
System Uptime: 0 days 0:26:30.274
Process Uptime: 0 days 0:26:16.000
.......................................................
Loading unloaded module list
...........................................
This dump file has an exception of interest stored in it.
The stored exception information can be accessed via .ecxr.
(490.530): Unknown exception - code 8898008d (first/second chance not available)
eax=03e5f270 ebx=00000000 ecx=00000000 edx=00000000 esi=03e5f580 edi=03e5f270
eip=725fb99e esp=03e5f554 ebp=03e5f5dc iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200212
dwmcore!CComposition::ProcessComposition+0xa0830:
725fb99e e9fcf8f5ff      jmp     dwmcore!CComposition::ProcessComposition+0x131 (7255b29f)
0:002> kd: Reading initial command '!analyze -v;~* k;q'
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************
...

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [string]$File  
    )

    if (-Not (Test-Path $File)) {
       throw "Unable to find the given dump file: $File"
    }

    $BestSelectionDebugger = Select-WindowsKitFileForOs -KitTable (Get-KernelDebuggerPath)

    if ($null -ne $BestSelectionDebugger) {
        Invoke-KernelDebuggerDumpAnalysis -DebuggerExecutable $BestSelectionDebugger.Path -DumpFile $File -InitialCommandMode AnalyzeThenQuit
    }
}
