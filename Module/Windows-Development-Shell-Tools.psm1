<#

.SYNOPSIS
PowerShell cmdlets for software development on the Microsoft Windows operating system

.DESCRIPTION
These functions wrap common Windows development tools (debuggers, symbol check, Authenticode, and related utilities) so you can drive them from PowerShell. They return structured results (typically DataTable objects) where that helps automation.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.LICENSE
Copyright 2018 David Roller 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

#>

function Find-WindowsKitFile {
<#

.SYNOPSIS
Gets the full path to a file under installed Windows Kits.

.DESCRIPTION
Searches the default Windows Kits installation directory (for example, under Program Files (x86)) for a file name you specify. Returns a DataTable with Path, WDK version folder, and debugger architecture (Bitness). Install at least one Windows SDK or WDK before using this function.

.PARAMETER File
The file name which has to be located within the Windows Kit installations

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

.EXAMPLE
Find-WindowsKitFile -File windbg.exe

Path                                                            WDK Bitness
----                                                            --- -------
C:\Program Files (x86)\Windows Kits\10\Debuggers\arm\windbg.exe 10  arm    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe 10  x64    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe 10  x86 

.EXAMPLE
Find-WindowsKitFile -File kd.exe  

Path                                                        WDK Bitness
----                                                        --- -------
C:\Program Files (x86)\Windows Kits\10\Debuggers\arm\kd.exe 10  arm    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe 10  x64    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\kd.exe 10  x86    

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [string]$File      
    )
    
    $Table = New-Object System.Data.DataTable "WindowsKit"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Path, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn WDK, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Bitness, ([string])))

    $FoundFiles = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits" -Filter $File -File -Recurse

    foreach($FileEntry in $FoundFiles) {
        $Row = $Table.NewRow()
        
        $Row.Path = $FileEntry.FullName
        $Row.WDK = $FileEntry.Directory.Parent.Parent.Name
        $Row.Bitness = $FileEntry.Directory.Name
        
        [void]$Table.Rows.Add($Row)
    }

    return ,$Table
}

function Get-DebuggerPath {
<#

.SYNOPSIS
Gets paths to WinDbg executables from installed Windows Kits.

.DESCRIPTION
Returns the same table shape as Find-WindowsKitFile for windbg.exe. Requires a Windows SDK or WDK installation.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

.EXAMPLE
Get-DebuggerPath

Path                                                            WDK Bitness
----                                                            --- -------
C:\Program Files (x86)\Windows Kits\10\Debuggers\arm\windbg.exe 10  arm    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe 10  x64    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe 10  x86   

#>
    return Find-WindowsKitFile -File "windbg.exe"
}

function Get-KernelDebuggerPath {
<#

.SYNOPSIS
Gets paths to kd.exe (kernel debugger) from installed Windows Kits.

.DESCRIPTION
Returns the same table shape as Find-WindowsKitFile for kd.exe. Requires a Windows SDK or WDK installation.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

.EXAMPLE
Get-KernelDebuggerPath

Path                                                        WDK Bitness
----                                                        --- -------
C:\Program Files (x86)\Windows Kits\10\Debuggers\arm\kd.exe 10  arm    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe 10  x64    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\kd.exe 10  x86     

#>
    return Find-WindowsKitFile -File "kd.exe"
}

function Get-SymbolCheck {
<#

.SYNOPSIS
Gets paths to symchk.exe from installed Windows Kits.

.DESCRIPTION
Returns the same table shape as Find-WindowsKitFile for symchk.exe. Requires a Windows SDK or WDK installation.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

.EXAMPLE
Get-SymbolCheck    

#>
    return Find-WindowsKitFile -File "symchk.exe"
}

function Get-EicarSignature {
<#

.SYNOPSIS
Returns the EICAR anti-malware test file string.

.DESCRIPTION
Returns the standard EICAR test string (European Institute for Computer Antivirus Research) in a DataTable. The payload is built in fragments in code so static scanners are less likely to flag the module file. The example output is truncated for the same reason.

.LINK
http://www.eicar.org
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-EicarSignature

Signature                                                           
---------                                                           
...EICAR-STANDARD-ANTIVIRUS-TEST-FILE!...
  

#>
    $Table = New-Object System.Data.DataTable "EicarSignature"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Signature, ([string])))
    
    $Row = $Table.NewRow()
    $Row.Signature = "X5O!P%@AP[4\PZX54(P^)7CC)7}"
    $Row.Signature += "`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*"
    [void]$Table.Rows.Add($Row)

    return ,$Table
}

function Get-OperatingSystemBitness {
<#

.SYNOPSIS
Gets the processor architecture class (x64 or x86) of the installed Windows OS.

.DESCRIPTION
Returns a one-row DataTable with column Type set to x64 or x86, based on whether the OS reports a 64-bit address space for the current process view. Other functions use this to pick matching debugger or symchk binaries.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-OperatingSystemBitness

Type
----
x64  

#>
    $Table = New-Object System.Data.DataTable "Bitness"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Type, ([string])))

    $Row = $Table.NewRow()
    if ([Environment]::Is64BitProcess -ne [Environment]::Is64BitOperatingSystem) {
        $Row.Type = 'x86'
    } else {
        $Row.Type = 'x64'
    }
    [void]$Table.Rows.Add($Row)

    return ,$Table
}

function Invoke-KernelDebuggerDumpAnalysis {
<#

.SYNOPSIS
Runs the kernel debugger against a dump with a standard !analyze command.

.DESCRIPTION
Starts the debugger executable with -z pointing at the dump file and -c running !analyze -v. AnalyzeThenQuit adds q so the debugger exits after analysis; AnalyzeStayOpen omits q so the session stays open. Used by Get-DumpAnalysis and Open-DumpAnalysis. This command is not exported from the module.

.PARAMETER DebuggerExecutable
Full path to kd.exe or a compatible debugger.

.PARAMETER DumpFile
Full path to the crash dump file.

.PARAMETER InitialCommandMode
AnalyzeThenQuit or AnalyzeStayOpen.

#>
    param(
        [Parameter(Mandatory)]
        [string]$DebuggerExecutable,
        [Parameter(Mandatory)]
        [string]$DumpFile,
        [Parameter(Mandatory)]
        [ValidateSet('AnalyzeThenQuit', 'AnalyzeStayOpen')]
        [string]$InitialCommandMode
    )
    if ($InitialCommandMode -eq 'AnalyzeThenQuit') {
        & $DebuggerExecutable -c """!analyze -v;q""" -z """$DumpFile"""
    } else {
        & $DebuggerExecutable -c """!analyze -v;""" -z """$DumpFile"""
    }
}

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
    & $DebuggerExecutable -n -k com:pipe,port=\\$RemoteHost\pipe\$PipeName,resets=0,reconnect
}

function Invoke-SymChkArguments {
<#

.SYNOPSIS
Invokes symchk with recursive symbol resolution options.

.DESCRIPTION
Runs symchk with /r on the target path, optionally /v for verbose output and /oc with a download directory when DownloadTo is set. Used by Find-Symbols. This command is not exported from the module.

.PARAMETER SymChkExecutable
Full path to symchk.exe.

.PARAMETER TargetPath
File or folder to check.

.PARAMETER DownloadTo
Optional output directory for downloaded symbols (/oc).

.PARAMETER Detailed
If set, adds /v for verbose symchk output.

#>
    param(
        [Parameter(Mandatory)]
        [string]$SymChkExecutable,
        [Parameter(Mandatory)]
        [string]$TargetPath,
        [string]$DownloadTo,
        [switch]$Detailed
    )
    if ($DownloadTo) {
        if ($Detailed) {
            & $SymChkExecutable """$TargetPath""" /r /v /oc """$DownloadTo"""
        } else {
            & $SymChkExecutable """$TargetPath""" /r /oc """$DownloadTo"""
        }
    } else {
        if ($Detailed) {
            & $SymChkExecutable """$TargetPath""" /r /v
        } else {
            & $SymChkExecutable """$TargetPath""" /r
        }
    }
}

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

    $OSBitness = Get-OperatingSystemBitness

    $Debugger = Get-KernelDebuggerPath | Where-Object {
        $_.Bitness -eq $OSBitness.Type
    } 
    
    $BestSelectionDebugger = $Debugger | Sort-Object -Property WDK | Select-Object -first 1

    $BestSelectionDebugger | ForEach-Object {
        Invoke-KernelDebuggerDumpAnalysis -DebuggerExecutable $_.Path -DumpFile $File -InitialCommandMode AnalyzeThenQuit
    }
}


function Open-DumpAnalysis {
<#

.SYNOPSIS
Opens a crash dump in the kernel debugger for interactive analysis.

.DESCRIPTION
Same debugger resolution as Get-DumpAnalysis, but runs !analyze -v without quitting so you can continue in the debugger session.

.PARAMETER File
Path to the crash dump file (.dmp).

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Open-DumpAnalysis -File "dwm.exe.1168.dmp"

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

    $OSBitness = Get-OperatingSystemBitness

    $Debugger = Get-KernelDebuggerPath | Where-Object {
        $_.Bitness -eq $OSBitness.Type
    } 
    
    $BestSelectionDebugger = $Debugger | Sort-Object -Property WDK | Select-Object -first 1

    $BestSelectionDebugger | ForEach-Object {
        Invoke-KernelDebuggerDumpAnalysis -DebuggerExecutable $_.Path -DumpFile $File -InitialCommandMode AnalyzeStayOpen
    }
}

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
    

    $OSBitness = Get-OperatingSystemBitness

    $Debugger = Get-DebuggerPath | Where-Object {
        $_.Bitness -eq $OSBitness.Type
    } 
    
    $BestSelectionDebugger = $Debugger | Sort-Object -Property WDK | Select-Object -first 1

    $BestSelectionDebugger | ForEach-Object {
        Invoke-WinDbgKernelRemotePipe -DebuggerExecutable $_.Path -RemoteHost $Host -PipeName $Port
    }
}

function Get-LinesOfCode {
<#

.SYNOPSIS
Counts text lines in files under a path.

.DESCRIPTION
Uses Select-String to count non-empty lines. By default returns one row for the path you pass. With -FileBased and optionally -Recursive, returns one row per file. Extension filtering uses Get-ChildItem -Include.

.PARAMETER Path
File or directory to analyze.

.PARAMETER Extensions
Wildcard list passed to Get-ChildItem -Include (default *.*).

.PARAMETER Recursive
When set, searches subfolders (Get-ChildItem -Recurse).

.PARAMETER FileBased
When set, emits one line-count row per file instead of a single aggregate for the path.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-LinesOfCode -Path C:\ConsoleApplication1\ConsoleApplication1\ConsoleApplication1.cpp

Path                                                                                            Count
----                                                                                            -----
C:\ConsoleApplication1\ConsoleApplication1\ConsoleApplication1.cpp                              17

.EXAMPLE
Get-LinesOfCode -Path C:\ConsoleApplication1 -Recursive

Path                                                Count
----                                                -----
C:\ConsoleApplication1                              263

.EXAMPLE
Get-LinesOfCode -Path C:\ConsoleApplication1 -Recursive -FileBased

Path                                                                                                        Count
----                                                                                                        -----
C:\ConsoleApplication1\ConsoleApplication1\ConsoleApplication1.cpp                                           17
C:\ConsoleApplication1\ConsoleApplication1\ConsoleApplication1.vcxproj                                      168
C:\ConsoleApplication1\ConsoleApplication1\ConsoleApplication1.vcxproj.filters                               30
C:\ConsoleApplication1\ConsoleApplication1\ConsoleApplication1.vcxproj.user                                   4
C:\ConsoleApplication1\ConsoleApplication1\pch.cpp                                                            3
C:\ConsoleApplication1\ConsoleApplication1\pch.h                                                             11
C:\ConsoleApplication1\ConsoleApplication1.sln                                                               30

.EXAMPLE
Get-LinesOfCode -Path C:\ConsoleApplication1 -Recursive -FileBased -Extensions *.cpp,*.h

Path                                                                                            Count
----                                                                                            -----
C:\ConsoleApplication1\ConsoleApplication1\ConsoleApplication1.cpp                              17
C:\ConsoleApplication1\ConsoleApplication1\pch.cpp                                               3
C:\ConsoleApplication1\ConsoleApplication1\pch.h                                                11

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [string]$Path,

        [string[]]$Extensions = "*.*",
        
        [switch]$Recursive,
        
        [switch]$FileBased
    )

    $Table = New-Object System.Data.DataTable "LineCount"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Path, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Count, ([long])))
        
    if ($Recursive) {
        $SelectedItems = Get-ChildItem $Path -Include $Extensions -Recurse
    } else {
        $SelectedItems = Get-ChildItem $Path -Include $Extensions
    }
    
    if($FileBased) {
        $SelectedItems | ForEach-Object {
            $Row = $Table.NewRow()
            $Row.Path = $_.FullName
            $Row.Count = ($_ | Select-String .).Count
            [void]$Table.Rows.Add($Row)
        }
    } else {
        $Row = $Table.NewRow()
        $Row.Path = $Path
        $Row.Count = ($SelectedItems | Select-String .).Count
        [void]$Table.Rows.Add($Row)
    }

    return ,$Table
}

function Find-Symbols {
<#

.SYNOPSIS
Runs symchk to resolve or download symbols for a binary or tree.

.DESCRIPTION
Picks symchk.exe for the current OS bitness from the newest Windows Kit, then runs it with /r against your path. Use -Detailed for symchk verbose output and -DownloadTo to pass /oc and cache symbols under that folder.

.PARAMETER Path
One or more existing files or directories to pass to symchk. Each path is checked recursively (/r). Supply multiple paths as an array, comma-separated arguments, or pipe objects with a Path or FullName property.

.PARAMETER DownloadTo
Directory for symchk /oc (optional).

.PARAMETER Detailed
Adds symchk /v for verbose logging.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Find-Symbols api-ms-win-core-debug-l1-1-0.dll

SYMCHK: FAILED files = 0
SYMCHK: PASSED + IGNORED files = 1

.EXAMPLE
Find-Symbols api-ms-win-core-debug-l1-1-0.dll -Detailed

[SYMCHK] Searching for symbols to C:\api-ms-win-core-debug-l1-1-0.dll in path srv*http://msdl.microsoft.com/download/symbols
DBGHELP: No header for C:\api-ms-win-core-debug-l1-1-0.dll.  Searching for image on disk
DBGHELP: C:\api-ms-win-core-debug-l1-1-0.dll - OK
SYMSRV:  BYINDEX: 0x1
         http://msdl.microsoft.com/download/symbols
         api-ms-win-core-debug-l1-1-0.pdb
         C5046A8FD17643C6D382F009429704681
SYMSRV:  PATH: C:\ProgramData\dbg\sym\api-ms-win-core-debug-l1-1-0.pdb\C5046A8FD17643C6D382F009429704681\api-ms-win-core-debug-l1-1-0.pdb
SYMSRV:  RESULT: 0x00000000
DBGHELP: api-ms-win-core-debug-l1-1-0 - public symbols
        C:\ProgramData\dbg\sym\api-ms-win-core-debug-l1-1-0.pdb\C5046A8FD17643C6D382F009429704681\api-ms-win-core-debug-l1-1-0.pdb
[SYMCHK] MODULE64 Info ----------------------
[SYMCHK] Struct size: 1680 bytes
[SYMCHK] Base: 0x0000000010000000
[SYMCHK] Image size: 12288 bytes
[SYMCHK] Date: 0x12f4f5c9
[SYMCHK] Checksum: 0x00014647
[SYMCHK] NumSyms: 0
[SYMCHK] SymType: SymPDB
[SYMCHK] ModName: api-ms-win-core-debug-l1-1-0
[SYMCHK] ImageName: C:\api-ms-win-core-debug-l1-1-0.dll
[SYMCHK] LoadedImage: C:\api-ms-win-core-debug-l1-1-0.dll
[SYMCHK] PDB: "C:\ProgramData\dbg\sym\api-ms-win-core-debug-l1-1-0.pdb\C5046A8FD17643C6D382F009429704681\api-ms-win-core-debug-l1-1-0.pdb"
[SYMCHK] CV: RSDS
[SYMCHK] CV DWORD: 0x53445352
[SYMCHK] CV Data:  api-ms-win-core-debug-l1-1-0.pdb
[SYMCHK] PDB Sig:  0
[SYMCHK] PDB7 Sig: {C5046A8F-D176-43C6-D382-F00942970468}
[SYMCHK] Age: 1
[SYMCHK] PDB Matched:  TRUE
[SYMCHK] DBG Matched:  TRUE
[SYMCHK] Line nubmers: FALSE
[SYMCHK] Global syms:  FALSE
[SYMCHK] Type Info:    FALSE
[SYMCHK] ------------------------------------
SymbolCheckVersion  0x00000002
Result              0x00030001
DbgFilename
DbgTimeDateStamp    0x12f4f5c9
DbgSizeOfImage      0x00003000
DbgChecksum         0x00014647
PdbFilename         C:\ProgramData\dbg\sym\api-ms-win-core-debug-l1-1-0.pdb\C5046A8FD17643C6D382F009429704681\api-ms-win-core-debug-l1-1-0.pdb
PdbSignature        {C5046A8F-D176-43C6-D382-F00942970468}
PdbDbiAge           0x00000001
[SYMCHK] [ 0x00000000 - 0x00030001 ] Checked "C:\api-ms-win-core-debug-l1-1-0.dll"

SYMCHK: FAILED files = 0
SYMCHK: PASSED + IGNORED files = 1

.EXAMPLE
Find-Symbols -Path C:\Bin\Release, D:\Drop\Plugins

Runs symchk /r once per root so symbols are resolved for each tree.

.EXAMPLE
Get-ChildItem C:\MyBuild\Release -File -Recurse | Find-Symbols

Objects from Get-ChildItem bind via FullName. symchk runs once per piped item; for large trees, passing a few folder paths to -Path is usually faster than piping every file.

.EXAMPLE
Get-ChildItem D:\Drop -Filter *.dll -Recurse | Find-Symbols -DownloadTo C:\SymCache -Detailed

-DownloadTo and -Detailed apply to every symchk invocation. All downloads use the same /oc directory (shared symbol cache).

.EXAMPLE
Get-ChildItem C:\Projects\*\bin -Directory | Find-Symbols

Each directory is passed as its own symchk /r root.

.EXAMPLE
Find-Symbols C:\api-ms-win-core-debug-l1-1-0.dll -Detailed -DownloadTo C:\out

[SYMCHK] Searching for symbols to C:\api-ms-win-core-debug-l1-1-0.dll in path srv*http://msdl.microsoft.com/download/symbols
DBGHELP: No header for C:\api-ms-win-core-debug-l1-1-0.dll.  Searching for image on disk
DBGHELP: C:\api-ms-win-core-debug-l1-1-0.dll - OK
SYMSRV:  BYINDEX: 0x1
         http://msdl.microsoft.com/download/symbols
         api-ms-win-core-debug-l1-1-0.pdb
         C5046A8FD17643C6D382F009429704681
SYMSRV:  PATH: C:\ProgramData\dbg\sym\api-ms-win-core-debug-l1-1-0.pdb\C5046A8FD17643C6D382F009429704681\api-ms-win-core-debug-l1-1-0.pdb
SYMSRV:  RESULT: 0x00000000
DBGHELP: api-ms-win-core-debug-l1-1-0 - public symbols
        C:\ProgramData\dbg\sym\api-ms-win-core-debug-l1-1-0.pdb\C5046A8FD17643C6D382F009429704681\api-ms-win-core-debug-l1-1-0.pdb
[SYMCHK] MODULE64 Info ----------------------
[SYMCHK] Struct size: 1680 bytes
[SYMCHK] Base: 0x0000000010000000
[SYMCHK] Image size: 12288 bytes
[SYMCHK] Date: 0x12f4f5c9
[SYMCHK] Checksum: 0x00014647
[SYMCHK] NumSyms: 0
[SYMCHK] SymType: SymPDB
[SYMCHK] ModName: api-ms-win-core-debug-l1-1-0
[SYMCHK] ImageName: C:\api-ms-win-core-debug-l1-1-0.dll
[SYMCHK] LoadedImage: C:\api-ms-win-core-debug-l1-1-0.dll
[SYMCHK] PDB: "C:\ProgramData\dbg\sym\api-ms-win-core-debug-l1-1-0.pdb\C5046A8FD17643C6D382F009429704681\api-ms-win-core-debug-l1-1-0.pdb"
[SYMCHK] CV: RSDS
[SYMCHK] CV DWORD: 0x53445352
[SYMCHK] CV Data:  api-ms-win-core-debug-l1-1-0.pdb
[SYMCHK] PDB Sig:  0
[SYMCHK] PDB7 Sig: {C5046A8F-D176-43C6-D382-F00942970468}
[SYMCHK] Age: 1
[SYMCHK] PDB Matched:  TRUE
[SYMCHK] DBG Matched:  TRUE
[SYMCHK] Line nubmers: FALSE
[SYMCHK] Global syms:  FALSE
[SYMCHK] Type Info:    FALSE
[SYMCHK] ------------------------------------
SymbolCheckVersion  0x00000002
Result              0x00030001
DbgFilename
DbgTimeDateStamp    0x12f4f5c9
DbgSizeOfImage      0x00003000
DbgChecksum         0x00014647
PdbFilename         C:\ProgramData\dbg\sym\api-ms-win-core-debug-l1-1-0.pdb\C5046A8FD17643C6D382F009429704681\api-ms-win-core-debug-l1-1-0.pdb
PdbSignature        {C5046A8F-D176-43C6-D382-F00942970468}
PdbDbiAge           0x00000001
[SYMCHK] [ 0x00000000 - 0x00030001 ] Checked "C:\api-ms-win-core-debug-l1-1-0.dll"

SYMCHK: FAILED files = 0
SYMCHK: PASSED + IGNORED files = 1

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [Alias('FullName')]
        [string[]]$Path,
        
        [string]$DownloadTo,

        [switch]$Detailed
    )

    begin {
        $pathAccumulator = [System.Collections.Generic.List[string]]::new()
    }
    process {
        if ($null -eq $Path) {
            return
        }
        foreach ($p in $Path) {
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                [void]$pathAccumulator.Add($p)
            }
        }
    }
    end {
        if ($pathAccumulator.Count -eq 0) {
            throw 'No paths were supplied to Find-Symbols.'
        }

        foreach ($singlePath in $pathAccumulator) {
            if (-not (Test-Path -LiteralPath $singlePath)) {
                throw "Unable to find the given file or folder: $singlePath"
            }
        }

        $OSBitness = Get-OperatingSystemBitness

        $SymbolCheck = Get-SymbolCheck | Where-Object {
            $_.Bitness -eq $OSBitness.Type
        } 
        
        $BestSelectionSymbolCheck = $SymbolCheck | Sort-Object -Property WDK | Select-Object -first 1

        foreach ($symRow in $BestSelectionSymbolCheck) {
            foreach ($singlePath in $pathAccumulator) {
                Invoke-SymChkArguments -SymChkExecutable $symRow.Path -TargetPath $singlePath -DownloadTo $DownloadTo -Detailed:$Detailed
            }
        }
    }
}

function Get-FileDetails {
<#

.SYNOPSIS
Reads file version metadata from PE files.

.DESCRIPTION
Enumerates files with Get-ChildItem, then fills a DataTable from System.Diagnostics.FileVersionInfo (version strings, company, description, and related fields).

.PARAMETER File
File or directory to scan.

.PARAMETER Filter
Get-ChildItem -Filter pattern when enumerating under a directory (default *.*).

.PARAMETER Recursive
When set, includes subdirectories when File is a folder.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-FileDetails C:\Windows\regedit.exe


File            : C:\Windows\regedit.exe
FileVersion     : 10.0.17134.346 (WinBuild.160101.0800)
ProductVersion  : 10.0.17134.346
FileDescription : Registrierungs-Editor
CompanyName     : Microsoft Corporation
InternalName    : REGEDIT
LegalCopyright  : � Microsoft Corporation. Alle Rechte vorbehalten.
ProductName     : Betriebssystem Microsoft� Windows�

.EXAMPLE
Get-FileDetails C:\Windows | Format-Table

File                            FileVersion                           ProductVersion FileDescription                                       CompanyName                InternalName   
----                            -----------                           -------------- ---------------                                       -----------                ------------   
C:\Windows\bfsvc.exe            10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Startdatei-Wartungshilfsprogramm                      Microsoft Corporation      bfsvc.exe      
C:\Windows\bootstat.dat                                                                                                                                                              
C:\Windows\comsetup.log                                                                                                                                                              
C:\Windows\diagerr.xml                                                                                                                                                               
C:\Windows\diagwrn.xml                                                                                                                                                               
C:\Windows\DtcInstall.log                                                                                                                                                            
C:\Windows\explorer.exe         10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Windows-Explorer                                      Microsoft Corporation      explorer       
C:\Windows\HelpPane.exe         10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Microsoft-Hilfe und Support                           Microsoft Corporation      HelpPane.exe   
C:\Windows\hh.exe               10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Ausf�hrbare Microsoft�-HTML-Hilfsdatei                Microsoft Corporation      HH 1.41        
C:\Windows\mib.bin                                                                                                                                                                   
C:\Windows\notepad.exe          10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Editor                                                Microsoft Corporation      Notepad        
C:\Windows\PFRO.log                                                                                                                                                                  
C:\Windows\Professional.xml                                                                                                                                                          
C:\Windows\py.exe               3.6.6                                 3.6.6          Python                                                Python Software Foundation Python Launcher
C:\Windows\pyshellext.amd64.dll 3.6.6                                 3.6.6          Python                                                Python Software Foundation Python Launc...
C:\Windows\pyw.exe              3.6.6                                 3.6.6          Python                                                Python Software Foundation Python Launcher
C:\Windows\regedit.exe          10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Registrierungs-Editor                                 Microsoft Corporation      REGEDIT        
C:\Windows\setupact.log                                                                                                                                                              
C:\Windows\setuperr.log                                                                                                                                                              
C:\Windows\splwow64.exe         10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Print driver host for applications                    Microsoft Corporation      splwow64.exe   
C:\Windows\system.ini                                                                                                                                                                
C:\Windows\twain_32.dll         1,7,1,3                               1,7,1,0        Twain_32 Source-Manager (Image Acquisition Interface) Twain Working Group        DSM            
C:\Windows\win.ini                                                                                                                                                                   
C:\Windows\WindowsUpdate.log                                                                                                                                                         
C:\Windows\winhlp32.exe         10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Windows Winhlp32-Stub                                 Microsoft Corporation      WINHSTB        
C:\Windows\WMSysPr9.prx                                                                                                                                                              
C:\Windows\write.exe            10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Windows Write                                         Microsoft Corporation      write  

.EXAMPLE
Get-FileDetails C:\Windows -Filter *.exe | Format-Table

File                    FileVersion                           ProductVersion FileDescription                        CompanyName                InternalName    LegalCopyright        
----                    -----------                           -------------- ---------------                        -----------                ------------    --------------        
C:\Windows\bfsvc.exe    10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Startdatei-Wartungshilfsprogramm       Microsoft Corporation      bfsvc.exe       � Microsoft Corpora...
C:\Windows\explorer.exe 10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Windows-Explorer                       Microsoft Corporation      explorer        � Microsoft Corpora...
C:\Windows\HelpPane.exe 10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Microsoft-Hilfe und Support            Microsoft Corporation      HelpPane.exe    � Microsoft Corpora...
C:\Windows\hh.exe       10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Ausf�hrbare Microsoft�-HTML-Hilfsdatei Microsoft Corporation      HH 1.41         � Microsoft Corpora...
C:\Windows\notepad.exe  10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Editor                                 Microsoft Corporation      Notepad         � Microsoft Corpora...
C:\Windows\py.exe       3.6.6                                 3.6.6          Python                                 Python Software Foundation Python Launcher Copyright � 2001-20...
C:\Windows\pyw.exe      3.6.6                                 3.6.6          Python                                 Python Software Foundation Python Launcher Copyright � 2001-20...
C:\Windows\regedit.exe  10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Registrierungs-Editor                  Microsoft Corporation      REGEDIT         � Microsoft Corpora...
C:\Windows\splwow64.exe 10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Print driver host for applications     Microsoft Corporation      splwow64.exe    � Microsoft Corpora...
C:\Windows\winhlp32.exe 10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Windows Winhlp32-Stub                  Microsoft Corporation      WINHSTB         � Microsoft Corpora...
C:\Windows\write.exe    10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Windows Write                          Microsoft Corporation      write           � Microsoft Corpora...

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [string]$File,

        [string]$Filter = "*.*",
        
        [switch]$Recursive    
    )
    
    $Table = New-Object System.Data.DataTable "File Details"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn File, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn FileVersion, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn ProductVersion, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn FileDescription, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn CompanyName, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn InternalName, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn LegalCopyright, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn ProductName, ([string])))
     
    if ($Recursive) {
        $FoundFiles = Get-ChildItem -Path $File -File -Filter $Filter -Recurse
    } else {
        $FoundFiles = Get-ChildItem -Path $File -File -Filter $Filter
    }

    foreach($FileEntry in $FoundFiles) {
        $VersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FileEntry.FullName)

        $Row = $Table.NewRow()
    
        $Row.File = $FileEntry.FullName
        $Row.FileVersion = $VersionInfo.FileVersion
        $Row.ProductVersion = $VersionInfo.ProductVersion
        $Row.FileDescription = $VersionInfo.FileDescription
        $Row.CompanyName = $VersionInfo.CompanyName
        $Row.InternalName = $VersionInfo.InternalName
        $Row.LegalCopyright = $VersionInfo.LegalCopyright
        $Row.ProductName = $VersionInfo.ProductName

        [void]$Table.Rows.Add($Row)
    }

    return ,$Table
}

# Full .NET Framework: PKCS types ship in System.Security. .NET Core / modern PowerShell: separate PKCS assembly.
if ($PSVersionTable.PSEdition -eq 'Core') {
    $coreLib = [object].Assembly.Location
    $pkcsPath = Join-Path $PSHOME 'System.Security.Cryptography.Pkcs.dll'
    if (-not (Test-Path -LiteralPath $pkcsPath)) {
        $pkcsPath = Join-Path (Split-Path -Parent $coreLib) 'System.Security.Cryptography.Pkcs.dll'
    }
    if (-not (Test-Path -LiteralPath $pkcsPath)) {
        throw "Could not find System.Security.Cryptography.Pkcs.dll next to the PowerShell runtime. PKCS certificate helpers require PowerShell 7 on Windows with a standard install."
    }
    $CertificateAssemblies = @($coreLib, $pkcsPath)
} else {
    $CertificateAssemblies = @(
        'System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'
    )
}

$CertificateSource = @"
    namespace Therena.Encryption
    {
        using System;
        using System.IO;
        using System.Runtime.InteropServices;
        using System.Security.Cryptography.Pkcs;

        public static class Certificate  
        { 
            private const int CERT_QUERY_OBJECT_FILE = 0x1;
            private const int CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x400;
            private const int CERT_QUERY_FORMAT_FLAG_BINARY = 0x2;

            [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern bool CryptQueryObject(
                int dwObjectType,
                [MarshalAs(UnmanagedType.LPWStr)]
                string pvObject,
                int dwExpectedContentTypeFlags,
                int dwExpectedFormatTypeFlags,
                int dwFlags,
                ref int pdwMsgAndCertEncodingType,
                ref int pdwContentType,
                ref int pdwFormatType,
                ref IntPtr phCertStore,
                ref IntPtr phMsg,
                ref IntPtr ppvContext
            );
    
            private const int CMSG_ENCODED_MESSAGE = 29;

            [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern bool CryptMsgGetParam(
                IntPtr hCryptMsg,
                int dwParamType,
                int dwIndex,
                byte[] pvData,
                ref int pcbData
            );
    
            public static System.Security.Cryptography.Pkcs.SignerInfo[] DecodeCertificateData(byte[] pvData)
            {
                var cms = new SignedCms();
                cms.Decode(pvData);
                var infos = cms.SignerInfos;
                var certs = new System.Security.Cryptography.Pkcs.SignerInfo[infos.Count];
                for (int i = 0; i < infos.Count; i++)
                {
                    certs[i] = infos[i];
                }
                return certs;
            }

            public static System.Security.Cryptography.Pkcs.SignerInfo[] GetCertificates(string filePath)
            {
                var file = new FileInfo(filePath);

                int pdwMsgAndCertEncodingType = 0;
                int pdwContentType = 0;
                int pdwFormatType = 0;
                IntPtr phCertStore = IntPtr.Zero;
                IntPtr phMsg = IntPtr.Zero;
                IntPtr ppvContext = IntPtr.Zero;

                var result = CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    file.FullName,
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    ref pdwMsgAndCertEncodingType,
                    ref pdwContentType,
                    ref pdwFormatType,
                    ref phCertStore,
                    ref phMsg,
                    ref ppvContext);

                if (result == false)
                {
                    return new System.Security.Cryptography.Pkcs.SignerInfo[0];
                }

                int pcbData = 0;
                CryptMsgGetParam(phMsg, CMSG_ENCODED_MESSAGE, 0, null, ref pcbData);

                var pvData = new byte[pcbData];
                CryptMsgGetParam(phMsg, CMSG_ENCODED_MESSAGE, 0, pvData, ref pcbData);

                return DecodeCertificateData(pvData);
            }
        }
    }
"@

$encryptionTypeLoaded = $false
try {
    [void][Therena.Encryption.Certificate]
    $encryptionTypeLoaded = $true
} catch {
}
if (-not $encryptionTypeLoaded) {
    Add-Type -ReferencedAssemblies $CertificateAssemblies -TypeDefinition $CertificateSource -Language CSharp
}

function Get-NestedAuthenticodeDetails {
<#

.SYNOPSIS
Recursively expands nested Authenticode signatures into the certificate table.

.DESCRIPTION
Looks for PKCS signer unsigned attributes with OID 1.3.6.1.4.1.311.2.4.1 (nested signature). Each attribute value is decoded as a CMS signed message; nested signers are appended to the DataTable and processed recursively. This command is not exported from the module.

.PARAMETER Certificate
A System.Security.Cryptography.Pkcs.SignerInfo from the outer or parent signature.

.PARAMETER Table
DataTable with Subject, Issuer, DigestAlgorithm, Thumbprint, and PublicKey columns (same shape as Get-AuthenticodeDetails).

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://www.sysadmins.lv/blog-en/reading-multiple-signatures-from-signed-file-with-powershell.aspx

.EXAMPLE
Get-NestedAuthenticodeDetails -Certificate $Cert -Table $Table

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [System.Security.Cryptography.Pkcs.SignerInfo]$Certificate,
        
        [parameter(Mandatory=$true)]
        [System.Data.DataTable]$Table  
    )

    $NestedCerts = $Certificate.UnsignedAttributes | Where-Object {$_.Oid.Value -eq "1.3.6.1.4.1.311.2.4.1"}
    $DnsName = [System.Security.Cryptography.X509Certificates.X509NameType]::DnsName;
    
    foreach($RawSubCert in $NestedCerts) {
        $CertificateList = [Therena.Encryption.Certificate]::DecodeCertificateData($RawSubCert.Values[0].RawData)
        
        foreach($Cert in $CertificateList) {
            $Row = $Table.NewRow()
    
            $Row.Subject = $Cert.Certificate.Subject;
            $Row.Issuer = $Cert.Certificate.Issuer;
            $Row.DigestAlgorithm = $Cert.DigestAlgorithm.FriendlyName;
            $Row.Thumbprint = $Cert.Certificate.Thumbprint;
            $Row.PublicKey = [System.BitConverter]::ToString($Cert.Certificate.PublicKey.EncodedKeyValue.RawData).Replace("-", " ")

            [void]$Table.Rows.Add($Row)
            
            Get-NestedAuthenticodeDetails -Certificate $Cert -Table $Table
        }
    }
}

function Get-AuthenticodeSignerInfosForFile {
<#

.SYNOPSIS
Reads embedded PKCS#7 signer information from a PE file on disk.

.DESCRIPTION
Calls CryptQueryObject to extract an embedded CMS signature and returns SignerInfo objects. Used by Get-AuthenticodeDetails. This command is not exported from the module.

.PARAMETER FilePath
Path to a signed portable executable or other file Authenticode can query.

#>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )
    return [Therena.Encryption.Certificate]::GetCertificates($FilePath)
}

function Get-AuthenticodeDetails {
<#

.SYNOPSIS
Lists Authenticode certificates and public key material for a file.

.DESCRIPTION
Loads PKCS signer infos from the file, fills a DataTable with subject, issuer, digest algorithm, thumbprint, and public key (hex), then walks Microsoft nested-signature attributes (OID 1.3.6.1.4.1.311.2.4.1) when present.

.PARAMETER File
Path to the file to inspect (typically a signed PE).

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://www.sysadmins.lv/blog-en/reading-multiple-signatures-from-signed-file-with-powershell.aspx

.EXAMPLE
Get-AuthenticodeDetails C:\Windows\System32\drivers\dumpfve.sys


Subject         : CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
Issuer          : CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
DigestAlgorithm : sha256
Thumbprint      : 419E77AED546A1A6CF4DC23C1F977542FE289CF7
PublicKey       : 30 82 01 0A 02 82 01 01 00 CA E0 A8 0C CC D6 94 D5 42 FA F8 60 DD 5F BA 35 7E 90 B8 A2 C0 8D 92 6E 5F 10 DD A0 62 75 7A 8F 19 65 3B 65 87 98 38 EB 62 D5 D0 B4 75 B7 C9 9B 41 01 39 89 4D D0
                  86 D7 52 AD E4 2F 57 D3 92 7D 02 8B 2C 17 E0 3D DF D2 F0 92 AC 03 98 66 A5 00 7B F8 64 E2 06 32 39 F7 F5 B6 4F 70 0D 76 96 EC CD 82 7B 47 B5 A3 1D C0 43 BC 24 4A FB 69 B8 74 53 A3 4B 8E 4E
                  CB 32 2C 12 9A 78 D7 50 5C 59 B3 96 06 93 81 8A E9 45 3A CA AF 3E 16 94 5A 76 8C 7E FD EE F7 93 70 73 54 67 14 D2 64 48 F3 DA FF 9D 20 0F 86 1E 83 60 66 7D AE DC DD D0 D0 AF DA 54 E9 82 72
                  BE AE D6 86 76 25 F6 0D FE AA B2 CD FD EE F5 5C 77 3D BE 32 44 90 83 33 7E 9E B9 E1 AD C4 80 CD 5F BD F7 1F 46 85 E7 07 C8 30 00 51 81 5B 08 20 0E EC 58 23 B2 22 89 3A B4 DA B7 E4 C4 A1 65
                  C9 90 26 B8 9A 86 ED AB DC 92 60 6B 43 02 03 01 00 01

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [string]$File   
    )
        
    $Table = New-Object System.Data.DataTable "File Certificates"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Subject, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Issuer, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn DigestAlgorithm, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Thumbprint, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn PublicKey, ([string])))
    
    $CertificateList = Get-AuthenticodeSignerInfosForFile -FilePath $File
    $DnsName = [System.Security.Cryptography.X509Certificates.X509NameType]::DnsName;
    
    foreach($Cert in $CertificateList) {
        $Row = $Table.NewRow()
    
        $Row.Subject = $Cert.Certificate.Subject;
        $Row.Issuer = $Cert.Certificate.Issuer;
        $Row.DigestAlgorithm = $Cert.DigestAlgorithm.FriendlyName;
        $Row.Thumbprint = $Cert.Certificate.Thumbprint;
        $Row.PublicKey = [System.BitConverter]::ToString($Cert.Certificate.PublicKey.EncodedKeyValue.RawData).Replace("-", " ")

        [void]$Table.Rows.Add($Row)
        
        Get-NestedAuthenticodeDetails -Certificate $Cert -Table $Table
    }

    return ,$Table
}

$HexDumpSource = @"
    namespace Therena.Conversion
    {
        using System;
        using System.IO;
        using System.Text;

        
        public static class HexDump  
        {
            private const int ELEMANTPERSECTION = 8;

            public static string GetHexDump(FileInfo file, int sectionCount)
            {
                if(sectionCount <= 0)
                {
                    sectionCount = 2;
                }

                int bufferSize = ELEMANTPERSECTION * sectionCount;

                var builder = new StringBuilder();
                using (Stream fileStream = file.OpenRead())
                {
                    int position = 0;
                    var buffer = new byte[bufferSize];
                    while(position < fileStream.Length)
                    {
                        var read = fileStream.Read(buffer, 0, buffer.Length);
                        if(read > 0)
                        {
                            builder.Append(String.Format("{0:x4}: ", position));
                            position += read;

                            for(uint i = 0; i < bufferSize; ++i)
                            {
                                if(i < read)
                                {
                                    string hex = String.Format("{0:x2}", (byte)buffer[i]);
                                    builder.Append(hex + " ");
                                }
                                else
                                {
                                    builder.Append("   ");
                                }

                                if(((i + 1) % ELEMANTPERSECTION) == 0)
                                {
                                    builder.Append("-- ");
                                }

                                if(buffer[i] < 32 || buffer[i] > 250)
                                {
                                    buffer[i] = (byte)'.';
                                }
                            }

                            string bufferContent = Encoding.Default.GetString(buffer);
                            if(bufferContent.Length > read)
                            {
                                bufferContent = bufferContent.Substring(0, read);
                            }
                            builder.Append(bufferContent + Environment.NewLine);
                        }
                    }
                }
                return builder.ToString();
            }
        }
    }
"@

Add-Type -TypeDefinition $HexDumpSource -Language CSharp

function Get-HexDump {
<#

.SYNOPSIS
Formats the beginning of a file as a hex dump.

.DESCRIPTION
Returns a string with offset lines, space-separated hex bytes (8 bytes per group), and an ASCII column. Uses a small helper type compiled into the module.

.PARAMETER File
Path to the file to read.

.PARAMETER Width
Number of 8-byte groups per row (each group is 8 bytes). When omitted, a default is derived from the host buffer width.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-HexDump "C:\Windows\regedit.exe"
0000: 4d 5a 90 00 03 00 00 00 -- 04 00 00 00 ff ff 00 00    MZ�.............
0010: b8 00 00 00 00 00 00 00 -- 40 00 00 00 00 00 00 00    �.......@.......
0020: 00 00 00 00 00 00 00 00 -- 00 00 00 00 00 00 00 00    ................
0030: 00 00 00 00 00 00 00 00 -- 00 00 00 00 f0 00 00 00    ............�...
0040: 0e 1f ba 0e 00 b4 09 cd -- 21 b8 01 4c cd 21 54 68    ..�..�.�!�.L�!Th
0050: 69 73 20 70 72 6f 67 72 -- 61 6d 20 63 61 6e 6e 6f    is program canno
0060: 74 20 62 65 20 72 75 6e -- 20 69 6e 20 44 4f 53 20    t be run in DOS 
0070: 6d 6f 64 65 2e 0d 0d 0a -- 24 00 00 00 00 00 00 00    mode....$.......
0080: e4 16 38 77 a0 77 56 24 -- a0 77 56 24 a0 77 56 24    �.8w�wV$�wV$�wV$
0090: a9 0f c5 24 a2 77 56 24 -- 82 17 53 25 a1 77 56 24    �.�$�wV$�.S%�wV$
00a0: 82 17 55 25 a4 77 56 24 -- 82 17 52 25 b3 77 56 24    �.U%�wV$�.R%�wV$
00b0: 82 17 57 25 81 77 56 24 -- a0 77 57 24 c5 76 56 24    �.W%�wV$�wW$�vV$
00c0: 82 17 5f 25 be 77 56 24 -- 82 17 a9 24 a1 77 56 24    �._%�wV$�.�$�wV$
00d0: 82 17 54 25 a1 77 56 24 -- 52 69 63 68 a0 77 56 24    �.T%�wV$Rich�wV$
...

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [string]$File,
        
        [int]$Width
    )
    
    if(-Not $PSBoundParameters.ContainsKey("Width")) {
        $Width = ((Get-Host).UI.RawUI.WindowSize.Width / 100) + 2
    }
    return [Therena.Conversion.HexDump]::GetHexDump($File, $Width) 
}

function Get-GlobalAssemblyCache {
<#

.SYNOPSIS
Lists GAC-related assembly entries from the Fusion registry view.

.DESCRIPTION
Reads value names under HKLM:\SOFTWARE\Microsoft\Fusion\GACChangeNotification\Default, parses comma-separated assembly identity strings, and returns a DataTable with assembly name, version, and processor architecture when the string has enough fields.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-GlobalAssemblyCache

Assembly                                                                         Version      ProcessorArchitecture
--------                                                                         -------      ---------------------
System.Runtime                                                                   4.0.0.0      MSIL
System.IdentityModel.Selectors                                                   4.0.0.0      MSIL
System.AddIn.Contract                                                            4.0.0.0      MSIL
PresentationFramework-SystemDrawing                                              4.0.0.0      MSIL
System.Runtime.Extensions                                                        4.0.0.0      MSIL
System.Linq                                                                      4.0.0.0      MSIL

#>
    [CmdletBinding()]
    param ()
    
    $Table = New-Object System.Data.DataTable "Global Assembly Cache"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Assembly, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Version, ([System.Version])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn ProcessorArchitecture, ([string])))

    $GlobalAssemblyCache = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Fusion\GACChangeNotification\Default"
    $GlobalAssemblyCache = $GlobalAssemblyCache.PSObject.Properties.Name;

    foreach($AssemblyDescription in $GlobalAssemblyCache) {
        $Row = $Table.NewRow()

        $AssemblyDescriptionParts = $AssemblyDescription.Split(',');
    
        if($AssemblyDescriptionParts.Length -gt 4) {
        
            $Row.Assembly = $AssemblyDescriptionParts[0]
            $Row.Version = [System.Version]$AssemblyDescriptionParts[1]
            $Row.ProcessorArchitecture = $AssemblyDescriptionParts[4].ToUpper()

            [void]$Table.Rows.Add($Row)
        }
    }

    return ,$Table
}

if (-not ([System.Management.Automation.PSTypeName]'Therena.WindowsDevelopmentShellTools.WindowsErrorInteropWds4').Type) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Therena.WindowsDevelopmentShellTools
{
    internal static class NativeMethods
    {
        internal const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
        internal const uint FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
        internal const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint FormatMessage(
            uint dwFlags,
            IntPtr lpSource,
            uint dwMessageId,
            uint dwLanguageId,
            StringBuilder lpBuffer,
            uint nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("ntdll.dll")]
        internal static extern uint RtlNtStatusToDosError(int status);
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate int RtlDosErrorToNtStatusDelegate(uint dosError);

    public static class WindowsErrorInteropWds4
    {
        private static readonly IntPtr NtdllModule = NativeMethods.LoadLibrary("ntdll.dll");
        private static readonly RtlDosErrorToNtStatusDelegate RtlDosErrorToNtStatusFn = InitRtlDosErrorToNtStatus();

        private static RtlDosErrorToNtStatusDelegate InitRtlDosErrorToNtStatus()
        {
            if (NtdllModule == IntPtr.Zero)
            {
                return null;
            }
            IntPtr p = NativeMethods.GetProcAddress(NtdllModule, "RtlDosErrorToNtStatus");
            if (p == IntPtr.Zero)
            {
                return null;
            }
            return Marshal.GetDelegateForFunctionPointer<RtlDosErrorToNtStatusDelegate>(p);
        }

// Win32->NTSTATUS table reconstruction (see https://gist.github.com/alastorid/9a71ace47e590ab8237c133eaec4ef60 ); candidates are filtered with RtlNtStatusToDosError and prefer 0xC… NTSTATUS shape.
        private static readonly ushort[] RtlpStatusTableDosToNt = new ushort[]
{
            
0x0000, 0x03e5, 0x00ea, 0x0514, 0x0515, 0x03fe, 0x0516, 0x2009, 0x0057, 0x0517, 0x0460, 0x03f6, 0x0461, 0x0518, 0x20ac, 0x0720, 0x0779, 0x19d3, 0x0001, 0x8000, 0x03e6, 0x0000, 0x0003, 0x8000, 0x0004, 0x8000, 0x00ea, 0x0000, 0x0012, 0x0000, 0x056f, 0x012b, 0x001c, 0x0015, 0x0015, 0x00aa, 0x0103, 0x00fe, 0x00ff, 0x00ff, 0x0456, 0x0103, 0x044d, 0x0456, 0x0457, 0x044c, 0x044e, 0x044f, 0x0450, 0x0962, 0x10f4, 0x048d, 0x048e, 0x05aa, 0x0006, 0x0001, 0x0035, 0x054f, 0x0554, 0x0120, 0x0554, 0x0057, 0x0057, 0x0032, 0x0558, 0x052e, 0x0057, 0x0520, 0x0005, 0x0005, 0x051f, 0x0554, 0x078b, 0x06f8, 0x0057, 0x007a, 0x0574, 0x06fe, 0x0057, 0x0057, 0x0532, 0x1770, 0x1771, 0x0001, 0x0558, 0x0545, 0x0575, 0x0575, 0x0575, 0x0575, 0x13c5, 0x13c6, 0x13c7, 0x13c8, 0x13c9, 0x19e5, 0x001f, 0x0001, 0x0057, 0x0018, 0x03e6, 0x03e7, 0x05ae, 0x0006, 0x03e9, 0x00c1, 0x0057, 0x0057, 0x0000, 0x0002, 0x0000, 0x0002, 0x0000, 0x0001, 0x0000, 0x0026, 0x0000, 0x0022, 0x0000, 0x0015, 0x0000, 0x06f9, 0x0000, 0x001b, 0x0000, 0x00ea, 0x0000, 0x0008, 0x0000, 0x01e7, 0x0000, 0x01e7, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x0001, 0x0000, 0x001d, 0xc000, 0x0005, 0x0000, 0x0005, 0x0000, 0x00c1, 0x0000, 0x0005, 0x0000, 0x0005, 0x0000, 0x007a, 0x0000, 0x0006, 0x0000, 0x0025, 0xc000, 0x0026, 0xc000, 0x009e, 0x0000, 0x002b, 0xc000, 0x01e7, 0x0000, 0x01e7, 0x0000, 0x0057, 0x0571, 0x007b, 0x0002, 0x00b7, 0x0006, 0x00a1, 0x0000, 0x0003, 0x0000, 0x00a1, 0x0000, 0x045d, 0x0000, 0x045d, 0x0000, 0x0017, 0x0000, 0x0017, 0x0000, 0x0008, 0x0000, 0x0005, 0x0000, 0x0006, 0x0000, 0x0020, 0x0000, 0x0718, 0x0000, 0x0057, 0x0000, 0x0120, 0x0000, 0x012a, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x009c, 0x0000, 0x0005, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x011a, 0x0000, 0x00ff, 0x0000, 0x0570, 0x0000, 0x0570, 0x0000, 0x0570, 0x0000, 0x0021, 0x0000, 0x0021, 0x0000, 0x0005, 0x0000, 0x0032, 0x0000, 0x0519, 0x0000, 0x051a, 0x0000, 0x051b, 0x0000, 0x051c, 0x0000, 0x051d, 0x0000, 0x051e, 0x0000, 0x051f, 0x0000, 0x0520, 0x0000, 0x0521, 0x0000, 0x0522, 0x0000, 0x0523, 0x0000, 0x0524, 0x0000, 0x0525, 0x0000, 0x0526, 0x0000, 0x0527, 0x0000, 0x0528, 0x0000, 0x0529, 0x0000, 0x052a, 0x0000, 0x0056, 0x0000, 0x052c, 0x0000, 0x052d, 0x0000, 0x052e, 0x0000, 0x052f, 0x0000, 0x0530, 0x0000, 0x0531, 0x0000, 0x0532, 0x0000, 0x0533, 0x0000, 0x0534, 0x0000, 0x0535, 0x0000, 0x0536, 0x0000, 0x0537, 0x0000, 0x0538, 0x0000, 0x0539, 0x0000, 0x053a, 0x0000, 0x007f, 0x0000, 0x00c1, 0x0000, 0x03f0, 0x0000, 0x053c, 0x0000, 0x009e, 0x0000, 0x0070, 0x0000, 0x053d, 0x0000, 0x053e, 0x0000, 0x0044, 0x0000, 0x0103, 0x0000, 0x053f, 0x0000, 0x0103, 0x0000, 0x009a, 0x0000, 0x000e, 0x0000, 0x01e7, 0x0000, 0x0714, 0x0000, 0x0715, 0x0000, 0x0716, 0x0000, 0x008c, 0xc000, 0x008d, 0xc000, 0x008e, 0xc000, 0x008f, 0xc000, 0x0090, 0xc000, 0x0091, 0xc000, 0x0092, 0xc000, 0x0093, 0xc000, 0x0094, 0xc000, 0x0216, 0x0000, 0x0096, 0xc000, 0x0008, 0x0000, 0x03ee, 0x0000, 0x0540, 0x0000, 0x05aa, 0x0000, 0x0003, 0x0000, 0x0017, 0x0000, 0x048f, 0x0000, 0x0015, 0x0000, 0x01e7, 0x0000, 0x01e7, 0x0000, 0x05ad, 0x0000, 0x0013, 0x0000, 0x0015, 0x0000, 0x0541, 0x0000, 0x0542, 0x0000, 0x0543, 0x0000, 0x0544, 0x0000, 0x0545, 0x0000, 0x0057, 0x0000, 0x00e7, 0x00e7, 0x00e6, 0x00e7, 0x0001, 0x00e9, 0x00e8, 0x0217, 0x0218, 0x00e6, 0x0079, 0x0026, 0x0005, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f, 0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048, 0x0058, 0x0011, 0x0005, 0x00f0, 0x0546, 0x00e8, 0x0547, 0x0548, 0x0549, 0x054a, 0x054b, 0x054c, 0x054d, 0x012c, 0x012d, 0x054e, 0x054f, 0x0550, 0x0551, 0x06f8, 0x045d, 0x0552, 0x0553, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0003, 0x0420, 0x03e9, 0x0554, 0x00cb, 0x0091, 0x0570, 0x010b, 0x0555, 0x0556, 0x00ce, 0x0961, 0x0964, 0x013d, 0x0005, 0x0557, 0x0558, 0x0420, 0x05a4, 0x00c1, 0x0559, 0x055a, 0x03ee, 0x0004, 0x03e3, 0x0005, 0x04ba, 0x0005, 0x055b, 0x055c, 0x055d, 0x055e, 0x0006, 0x055f, 0x05af, 0x00c1, 0x00c1, 0x00c1, 0x00c1, 0x0576, 0x007e, 0x00b6, 0x007f, 0x0040, 0x0040, 0x0033, 0x003b, 0x003b, 0x003b, 0x003b, 0x045a, 0x007c, 0x0056, 0x006d, 0x03f1, 0x03f8, 0x03ed, 0x045e, 0x0560, 0x0561, 0x0562, 0x0563, 0x0564, 0x0565, 0x0566, 0x0567, 0x03ef, 0x0568, 0x0569, 0x03f9, 0x056a, 0x045d, 0x04db, 0x0459, 0x0462, 0x0463, 0x0464, 0x0465, 0x0466, 0x0467, 0x0468, 0x045f, 0x045d, 0x0451, 0x0452, 0x0453, 0x0454, 0x0455, 0x0469, 0x0458, 0x056b, 0x056c, 0x03fa, 0x03fb, 0x056d, 0x056e, 0x03fc, 0x03fd, 0x0057, 0x045d, 0x0016, 0x045d, 0x045d, 0x05de, 0x0013, 0x06fa, 0x06fb, 0x06fc, 0x06fd, 0x05dc, 0x05dd, 0x06fe, 0x0700, 0x0701, 0x046b, 0x04c3, 0x04c4, 0x05df, 0x070f, 0x0710, 0x0711, 0x0712, 0x0572, 0x003b, 0x003b, 0x0717, 0x046a, 0x06f8, 0x04be, 0x04be, 0x0044, 0x0034, 0x0040, 0x0040, 0x0040, 0x0044, 0x003b, 0x003b, 0x003b, 0x003b, 0x003b, 0x003b, 0x003b, 0x0032, 0x0032, 0x17e6, 0x046c, 0x00c1, 0x0773, 0x0490, 0x04ff, 0x0057, 0x0000, 0x022a, 0xc000, 0x022b, 0xc000, 0x04d5, 0x0492, 0x0774, 0x0775, 0x0006, 0x04c9, 0x04ca, 0x04cb, 0x04cc, 0x04cd, 0x04ce, 0x04cf, 0x04d0, 0x04d1, 0x04d2, 0x04d3, 0x04d4, 0x04c8, 0x04d6, 0x04d7, 0x04d8, 0x00c1, 0x04d4, 0x054f, 0x04d0, 0x0573, 0x0422, 0x00b6, 0x007f, 0x0120, 0x0476, 0x10fe, 0x1b8e, 0x07d1, 0x04b1, 0x0015, 0x0491, 0x1126, 0x1129, 0x112a, 0x1128, 0x0780, 0x0781, 0x00a1, 0x0488, 0x0489, 0x048a, 0x048b, 0x048c, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x1777, 0x1778, 0x1772, 0x1068, 0x1069, 0x106a, 0x106b, 0x201a, 0x201b, 0x201c, 0x0001, 0x10ff, 0x1100, 0x0494, 0x200a, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2016, 0x2017, 0x2018, 0x2019, 0x211e, 0x1127, 0x0651, 0x049a, 0x049b, 0x2024, 0x0575, 0x03e6, 0x1075, 0x1076, 0x04ed, 0x10e8, 0x2138, 0x04e3, 0x2139, 0x049d, 0x213a, 0x2141, 0x2142, 0x2143, 0x2144, 0x2145, 0x2146, 0x2147, 0x2148, 0x2149, 0x0032, 0x2151, 0x2152, 0x2153, 0x2154, 0x215d, 0x2163, 0x2164, 0x2165, 0x216d, 0x0577, 0x0052, 0x2171, 0x0000, 0x2172, 0x0000, 0x0333, 0x8009, 0x0334, 0x8009, 0x0002, 0x0000, 0x0335, 0x8009, 0x0336, 0x8009, 0x0337, 0x8009, 0x0338, 0x8009, 0x0339, 0x8009, 0x033a, 0x8009, 0x033b, 0x8009, 0x033c, 0x8009, 0x033d, 0x8009, 0x033e, 0x8009, 0x0340, 0x8009, 0x0341, 0x8009, 0x0342, 0x8009, 0x045b, 0x0000, 0x04e7, 0x0000, 0x04e6, 0x0000, 0x106f, 0x0000, 0x1074, 0x0000, 0x106e, 0x0000, 0x012e, 0x0000, 0x0305, 0x8003, 0x0306, 0x8003, 0x0307, 0x8003, 0x0308, 0x8003, 0x0309, 0x8003, 0x030a, 0x8003, 0x030b, 0x8003, 0x04ef, 0x0000, 0x04f0, 0x0000, 0x0348, 0x8009, 0x04e8, 0x0000, 0x0343, 0x8009, 0x177d, 0x0000, 0x0504, 0x0001, 0xc009, 0x217c, 0x0000, 0x2182, 0x0000, 0x00c1, 0x0000, 0x00c1, 0x0000, 0x0346, 0x8009, 0x0572, 0x0000, 0x04ec, 0x04ec, 0x04ec, 0x04ec, 0x04fb, 0x04fb, 0x04fc, 0x006b, 0x8010, 0x006c, 0x8010, 0x006f, 0x8010, 0x000c, 0x8010, 0x000d, 0x8009, 0x002c, 0x8010, 0x0016, 0x8009, 0x002f, 0x8010, 0x04f1, 0x0000, 0x0351, 0x8009, 0x0352, 0x8009, 0x0353, 0x8009, 0x0354, 0x8009, 0x0355, 0x8009, 0x0022, 0x8009, 0x078c, 0x078d, 0x078e, 0x217b, 0x219d, 0x219f, 0x052e, 0x0000, 0x0502, 0x0000, 0x0356, 0x8009, 0x0357, 0x8009, 0x0358, 0x8009, 0x0359, 0x8009, 0x035a, 0x8009, 0x035b, 0x8009, 0x0503, 0x0000, 0x0505, 0x078f, 0x0506, 0x06a4, 0x06a5, 0x0006, 0x06a7, 0x06a8, 0x06a9, 0x06aa, 0x06ab, 0x06ac, 0x06ad, 0x06ae, 0x06af, 0x06b0, 0x06b1, 0x06b2, 0x06b3, 0x06b4, 0x06b5, 0x06b6, 0x06b7, 0x06b8, 0x06b9, 0x06ba, 0x06bb, 0x06bc, 0x06bd, 0x06be, 0x06bf, 0x06c0, 0x06c2, 0x06c4, 0x06c5, 0x06c6, 0x06c7, 0x06c8, 0x06c9, 0x06cb, 0x06cc, 0x06cd, 0x06ce, 0x06cf, 0x06d0, 0x06d1, 0x06d2, 0x06d3, 0x06d4, 0x06d5, 0x06d6, 0x06d7, 0x06d8, 0x06d9, 0x06da, 0x06db, 0x06dc, 0x06dd, 0x06de, 0x06df, 0x06e0, 0x06e1, 0x06e2, 0x06e3, 0x06e4, 0x06e5, 0x06e6, 0x06e7, 0x06e8, 0x06e9, 0x06ea, 0x06eb, 0x06ff, 0x070e, 0x076a, 0x076b, 0x076c, 0x0719, 0x071a, 0x071b, 0x071c, 0x071d, 0x071e, 0x071f, 0x0721, 0x0722, 0x077a, 0x077b, 0x06ec, 0x06ed, 0x06ee, 0x0006, 0x0006, 0x06f1, 0x06f2, 0x06f3, 0x06f4, 0x06f5, 0x06f6, 0x06f7, 0x0723, 0x0724, 0x0725, 0x0726, 0x0727, 0x0728, 0x077c, 0x077d, 0x077e, 0x1b59, 0x1b5a, 0x1b5b, 0x1b5f, 0x1b60, 0x1b61, 0x1b62, 0x1b63, 0x1b64, 0x1b65, 0x1b66, 0x1b67, 0x1b68, 0x1b69, 0x1b8f, 0x1b8e, 0x1b90, 0x1b6e, 0x1b6f, 0x1b70, 0x1b71, 0x1b7b, 0x1b7e, 0x1b80, 0x1b81, 0x1b82, 0x1b84, 0x1b85, 0x1b89, 0x1b5c, 0x1b8a, 0x1b8b, 0x1b8d, 0x1b8c, 0x1b92, 0x1b91, 0x13af, 0x13b0, 0x13b1, 0x13b2, 0x13b3, 0x13b4, 0x13b5, 0x13b6, 0x13b7, 0x13b8, 0x13b9, 0x13ba, 0x13bb, 0x13bc, 0x13bd, 0x13be, 0x13c0, 0x13ce, 0x13c2, 0x13c3, 0x13c4, 0x36b0, 0x36b1, 0x36b2, 0x36b3, 0x36b4, 0x36b5, 0x36b6, 0x36b7, 0x36b9, 0x36ba, 0x36bb, 0x19c8, 0x19c9, 0x19ca, 0x19cb, 0x19cc, 0x19cd, 0x19ce, 0x19cf, 0x19d0, 0x19d1, 0x19d2, 0x19d4, 0x19d5, 0x19d6, 0x19d7, 0x19d8, 0x19d9, 0x19da, 0x19db, 0x19dc, 0x19dd, 0x19de, 0x19df, 0x19e0, 0x19e1, 0x19e2, 0x19e3, 0x19e4, 0x19e6, 0x19e7, 0x19e8, 0x19e9, 0x19ea, 0x19eb, 0x19ec, 0x19ed, 0x19ee, 0x19ef, 0x19f0, 0x19f1, 0x19f2, 0x19f3, 0x19f4, 0x19f5, 0x19f6, 0x0037, 0x0037, 0x0037, 0x0000, 0x0,
        };

        private struct RunEntryDosToNt
        {
            public RunEntryDosToNt(uint baseCode, ushort runLength, ushort codeSize)
            {
                BaseCode = baseCode;
                RunLength = runLength;
                CodeSize = codeSize;
            }
            public readonly uint BaseCode;
            public readonly ushort RunLength;
            public readonly ushort CodeSize;
        }

        private static readonly RunEntryDosToNt[] RtlpRunTableDosToNt = new RunEntryDosToNt[]
        {
            new RunEntryDosToNt(0x00000000u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x00000103u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x00000105u, 0x0003, 0x0001),
            new RunEntryDosToNt(0x0000010cu, 0x0002, 0x0001),
            new RunEntryDosToNt(0x00000121u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x40000002u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x40000006u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x40000008u, 0x0002, 0x0001),
            new RunEntryDosToNt(0x4000000cu, 0x0002, 0x0001),
            new RunEntryDosToNt(0x40000370u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x40020056u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x400200afu, 0x0001, 0x0001),
            new RunEntryDosToNt(0x401a000cu, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80000001u, 0x0006, 0x0002),
            new RunEntryDosToNt(0x8000000bu, 0x0001, 0x0001),
            new RunEntryDosToNt(0x8000000du, 0x000a, 0x0001),
            new RunEntryDosToNt(0x8000001au, 0x0006, 0x0001),
            new RunEntryDosToNt(0x80000021u, 0x0002, 0x0001),
            new RunEntryDosToNt(0x80000025u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80000027u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80000288u, 0x0002, 0x0001),
            new RunEntryDosToNt(0x80090300u, 0x0012, 0x0001),
            new RunEntryDosToNt(0x80090316u, 0x0003, 0x0001),
            new RunEntryDosToNt(0x80090320u, 0x0003, 0x0001),
            new RunEntryDosToNt(0x80090325u, 0x0005, 0x0001),
            new RunEntryDosToNt(0x80090330u, 0x0002, 0x0001),
            new RunEntryDosToNt(0x80090347u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80090349u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80092010u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80092012u, 0x0002, 0x0001),
            new RunEntryDosToNt(0x80096004u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80130001u, 0x0005, 0x0001),
            new RunEntryDosToNt(0x80190009u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000001u, 0x000b, 0x0001),
            new RunEntryDosToNt(0xc000000du, 0x001a, 0x0002),
            new RunEntryDosToNt(0xc000002au, 0x0004, 0x0002),
            new RunEntryDosToNt(0xc0000030u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000032u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc0000037u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000039u, 0x0071, 0x0002),
            new RunEntryDosToNt(0xc00000abu, 0x000c, 0x0001),
            new RunEntryDosToNt(0xc00000bau, 0x0019, 0x0001),
            new RunEntryDosToNt(0xc00000d4u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc00000d9u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc00000dcu, 0x000e, 0x0001),
            new RunEntryDosToNt(0xc00000edu, 0x0012, 0x0001),
            new RunEntryDosToNt(0xc0000100u, 0x000c, 0x0001),
            new RunEntryDosToNt(0xc000010du, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000117u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc000011bu, 0x000e, 0x0001),
            new RunEntryDosToNt(0xc000012bu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc000012du, 0x0005, 0x0001),
            new RunEntryDosToNt(0xc0000133u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000135u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000138u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc000013bu, 0x0008, 0x0001),
            new RunEntryDosToNt(0xc0000148u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc000014bu, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc000014fu, 0x000f, 0x0001),
            new RunEntryDosToNt(0xc000015fu, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000162u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000165u, 0x0009, 0x0001),
            new RunEntryDosToNt(0xc0000172u, 0x0007, 0x0001),
            new RunEntryDosToNt(0xc000017au, 0x000d, 0x0001),
            new RunEntryDosToNt(0xc0000188u, 0x0009, 0x0001),
            new RunEntryDosToNt(0xc0000192u, 0x000a, 0x0001),
            new RunEntryDosToNt(0xc0000202u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000203u, 0x0015, 0x0001),
            new RunEntryDosToNt(0xc000021cu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000220u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000224u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000227u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000229u, 0x0003, 0x0002),
            new RunEntryDosToNt(0xc000022du, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000230u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000233u, 0x000f, 0x0001),
            new RunEntryDosToNt(0xc0000243u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000246u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc0000253u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000253u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000257u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000259u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc000025eu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000262u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc0000267u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc000026au, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc000026cu, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc0000272u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000275u, 0x0005, 0x0001),
            new RunEntryDosToNt(0xc0000280u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000283u, 0x0005, 0x0001),
            new RunEntryDosToNt(0xc000028au, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc000028du, 0x0007, 0x0001),
            new RunEntryDosToNt(0xc0000295u, 0x000b, 0x0001),
            new RunEntryDosToNt(0xc00002a1u, 0x0012, 0x0001),
            new RunEntryDosToNt(0xc00002b6u, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc00002c1u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc00002c3u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc00002c5u, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc00002c9u, 0x0005, 0x0001),
            new RunEntryDosToNt(0xc00002cfu, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc00002d4u, 0x000a, 0x0001),
            new RunEntryDosToNt(0xc00002dfu, 0x0009, 0x0001),
            new RunEntryDosToNt(0xc00002e9u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc00002ecu, 0x0020, 0x0002),
            new RunEntryDosToNt(0xc0000320u, 0x0003, 0x0002),
            new RunEntryDosToNt(0xc0000350u, 0x0003, 0x0002),
            new RunEntryDosToNt(0xc0000354u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000356u, 0x0007, 0x0002),
            new RunEntryDosToNt(0xc0000361u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc000036bu, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc000036fu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000380u, 0x000e, 0x0002),
            new RunEntryDosToNt(0xc000038fu, 0x0001, 0x0002),
            new RunEntryDosToNt(0xc0000401u, 0x0006, 0x0001),
            new RunEntryDosToNt(0xc0000408u, 0x0009, 0x0002),
            new RunEntryDosToNt(0xc0000412u, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc0020001u, 0x001d, 0x0001),
            new RunEntryDosToNt(0xc002001fu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0020021u, 0x0006, 0x0001),
            new RunEntryDosToNt(0xc0020028u, 0x0026, 0x0001),
            new RunEntryDosToNt(0xc002004fu, 0x0007, 0x0001),
            new RunEntryDosToNt(0xc0020057u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0020062u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0030001u, 0x000c, 0x0001),
            new RunEntryDosToNt(0xc0030059u, 0x0009, 0x0001),
            new RunEntryDosToNt(0xc00a0001u, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc00a0006u, 0x000b, 0x0001),
            new RunEntryDosToNt(0xc00a0012u, 0x0007, 0x0001),
            new RunEntryDosToNt(0xc00a0022u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc00a0024u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc00a0026u, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc00a002au, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc00a002eu, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc00a0033u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc0130001u, 0x0010, 0x0001),
            new RunEntryDosToNt(0xc0130012u, 0x0005, 0x0001),
            new RunEntryDosToNt(0xc0150001u, 0x0008, 0x0001),
            new RunEntryDosToNt(0xc015000au, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc015000eu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc01a0001u, 0x000b, 0x0001),
            new RunEntryDosToNt(0xc01a000du, 0x0022, 0x0001),
            new RunEntryDosToNt(0xc0980001u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0980008u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xffffffffu, 0x0001, 0x0001),
            new RunEntryDosToNt(0x0u, 0x0, 0x0),
        };

private static int RtlDosErrorToNtStatusMaybeInternal(uint dosErrorLow16, int candidate)
        {
            int last_err = unchecked((int)(dosErrorLow16 & 0xFFFFu));
            int index = -1;
            int number = 0;
            for (int i = 0; i < RtlpStatusTableDosToNt.Length; ++i)
            {
                if ((int)RtlpStatusTableDosToNt[i] == last_err)
                {
                    index = i;
                    if (number++ >= candidate)
                    {
                        break;
                    }
                }
            }
            if (number <= candidate)
            {
                return -1;
            }
            int baseIdx = 0;
            int status = -1;
            for (int i = 0; i < RtlpRunTableDosToNt.Length; ++i)
            {
                int next = baseIdx + RtlpRunTableDosToNt[i].RunLength * RtlpRunTableDosToNt[i].CodeSize;
                if (baseIdx <= index && index < next)
                {
                    int offset = (index - baseIdx) / RtlpRunTableDosToNt[i].CodeSize;
                    status = unchecked((int)(RtlpRunTableDosToNt[i].BaseCode + (uint)offset));
                    break;
                }
                baseIdx = next;
            }
            return status;
        }

        private static void TryAddNtStatusForDosError(uint dos, int status, System.Collections.Generic.HashSet<int> seen, System.Collections.Generic.List<int> outList)
        {
            if (status == -1) { return; }
            if (status == 0) { return; }
            uint rt = NativeMethods.RtlNtStatusToDosError(status);
            if (rt != dos) { return; }
            if (seen.Add(status)) { outList.Add(status); }
        }

        public static string FormatDosErrorToNtStatusBestEffort(uint dosErrorLow16)
        {
            uint dos = dosErrorLow16 & 0xFFFFu;
            var set = new System.Collections.Generic.HashSet<int>();
            var list = new System.Collections.Generic.List<int>();

            if (RtlDosErrorToNtStatusFn != null)
            {
                try { TryAddNtStatusForDosError(dos, RtlDosErrorToNtStatusFn(dos), set, list); } catch { }
            }

            for (int cand = 0; cand < 512; cand++)
            {
                int st = RtlDosErrorToNtStatusMaybeInternal(dos, cand);
                if (st == -1) { break; }
                TryAddNtStatusForDosError(dos, st, set, list);
            }

            var filtered = new System.Collections.Generic.List<int>();
            for (int i = 0; i < list.Count; i++)
            {
                uint u = unchecked((uint)list[i]);
                if ((u & 0xC0000000u) == 0xC0000000u)
                {
                    filtered.Add(list[i]);
                }
            }
            if (filtered.Count > 0)
            {
                list = filtered;
            }

            if (list.Count == 0)
            {
                return "(no NTSTATUS mapping found for this Win32 code)";
            }

            var sb = new StringBuilder();
            for (int i = 0; i < list.Count; i++)
            {
                if (i > 0) { sb.Append("; "); }
                uint u = unchecked((uint)list[i]);
                sb.AppendFormat(System.Globalization.CultureInfo.InvariantCulture, "0x{0:X8} ({1})", u, AsSignedInt32(u));
            }
            return sb.ToString();
        }
        public static uint HRESULT_FROM_WIN32(uint win32ErrorLow16)
        {
            return 0x80070000u | (win32ErrorLow16 & 0xFFFFu);
        }

        public static int AsSignedInt32(uint u)
        {
            return unchecked((int)u);
        }

        public static uint RtlNtStatusToDosErrorUInt(int ntStatus)
        {
            return NativeMethods.RtlNtStatusToDosError(ntStatus);
        }

        public static int RtlDosErrorToNtStatusInt(uint dosError)
        {
            if (RtlDosErrorToNtStatusFn == null)
            {
                return 0;
            }
            return RtlDosErrorToNtStatusFn(dosError);
        }

        public static bool IsRtlDosErrorToNtStatusAvailable
        {
            get { return RtlDosErrorToNtStatusFn != null; }
        }

        public static uint Low32BitsFromSignedValue(long value)
        {
            unchecked
            {
                return (uint)(value & 0xFFFFFFFFL);
            }
        }

        public static uint Low32BitsFromUnsignedValue(ulong value)
        {
            unchecked
            {
                return (uint)(value & 0xFFFFFFFFUL);
            }
        }

        public static uint Low16OfUInt32(uint value)
        {
            return value & 0xFFFFu;
        }

        public static string TryFormatWin32(uint code)
        {
            var sb = new StringBuilder(2048);
            uint len = NativeMethods.FormatMessage(
                NativeMethods.FORMAT_MESSAGE_FROM_SYSTEM | NativeMethods.FORMAT_MESSAGE_IGNORE_INSERTS,
                IntPtr.Zero,
                code,
                0,
                sb,
                (uint)sb.Capacity,
                IntPtr.Zero);
            if (len == 0)
            {
                return null;
            }
            return sb.ToString().TrimEnd();
        }

        public static string TryFormatNtStatus(uint ntStatus)
        {
            if (NtdllModule == IntPtr.Zero)
            {
                return null;
            }
            var sb = new StringBuilder(2048);
            uint len = NativeMethods.FormatMessage(
                NativeMethods.FORMAT_MESSAGE_FROM_HMODULE | NativeMethods.FORMAT_MESSAGE_IGNORE_INSERTS,
                NtdllModule,
                ntStatus,
                0,
                sb,
                (uint)sb.Capacity,
                IntPtr.Zero);
            if (len == 0)
            {
                return null;
            }
            return sb.ToString().TrimEnd();
        }

        public static string TryGetHResultMessage(int hr)
        {
            try
            {
                var ex = Marshal.GetExceptionForHR(hr);
                if (ex != null)
                {
                    return ex.Message.Trim();
                }
            }
            catch
            {
            }
            return null;
        }
    }
}
'@
}

function Get-WindowsErrorInfo {
<#

.SYNOPSIS
Interprets a raw 32-bit Windows error value as Win32, HRESULT, and NTSTATUS in parallel.

.DESCRIPTION
Takes one or more integer or hexadecimal codes (for example from logs or APIs) and returns a DataTable row per input with best-effort text for each interpretation, plus derived cross-conversions where applicable:
- Raw value as a Win32 system error (FormatMessage from system).
- Raw value as an HRESULT (Marshal.GetExceptionForHR message when available).
- Raw value as an NTSTATUS (FormatMessage from ntdll).
- DerivedFromWin32_HResult: HRESULT_FROM_WIN32(low 16 bits of the input).
- DerivedFromWin32_NtStatus: NTSTATUS candidates for the Win32 low 16 bits (ntdll RtlDosErrorToNtStatus when exported, plus gist-based ntdll table reconstruction filtered with RtlNtStatusToDosError).
- DerivedFromNtStatus_Win32: RtlNtStatusToDosError when the input is treated as an NTSTATUS.

Messages depend on installed language packs; unknown codes return a short placeholder instead of failing.

.PARAMETER Code
One or more 32-bit values: integers, unsigned integers, or strings such as 0xC0000005 or -2147024891.

.INPUTS
System.Object
You can pipe integers or numeric strings.

.OUTPUTS
System.Data.DataTable

.EXAMPLE
Get-WindowsErrorInfo -Code 5

.EXAMPLE
Get-WindowsErrorInfo -Code 0x80070005, 0xC0000005

.EXAMPLE
0xC0000005 | Get-WindowsErrorInfo

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Value')]
        [object[]]$Code
    )

    begin {
        $codeList = [System.Collections.Generic.List[object]]::new()
    }
    process {
        if ($null -eq $Code) {
            return
        }
        foreach ($c in $Code) {
            if ($null -ne $c) {
                [void]$codeList.Add($c)
            }
        }
    }
    end {
        if ($codeList.Count -eq 0) {
            throw 'No values were supplied to Get-WindowsErrorInfo.'
        }

        $Table = New-Object System.Data.DataTable 'WindowsErrorInfo'
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn InputCode, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn InputCodeHex, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn Win32Interpretation, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn Win32Description, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn HResultInterpretation, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn HResultDescription, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn NtStatusInterpretation, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn NtStatusDescription, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn DerivedFromWin32_HResult, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn DerivedFromWin32_NtStatus, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn DerivedFromNtStatus_Win32, ([string])))

        foreach ($raw in $codeList) {
            $u = $null
            if ($raw -is [uint32]) {
                $u = $raw
            }
            elseif ($raw -is [uint64]) {
                $u = [Therena.WindowsDevelopmentShellTools.WindowsErrorInteropWds4]::Low32BitsFromUnsignedValue([uint64]$raw)
            }
            elseif ($raw -is [uint16]) {
                $u = [uint32]$raw
            }
            elseif ($raw -is [byte]) {
                $u = [uint32]$raw
            }
            elseif ($raw -is [int] -or $raw -is [int32] -or $raw -is [long] -or $raw -is [int64] -or
                $raw -is [int16] -or $raw -is [short] -or $raw -is [sbyte]) {
                $u = [Therena.WindowsDevelopmentShellTools.WindowsErrorInteropWds4]::Low32BitsFromSignedValue([int64]$raw)
            }
            elseif ($raw -is [string]) {
                $s = $raw.Trim()
                if ([string]::IsNullOrWhiteSpace($s)) {
                    throw "Get-WindowsErrorInfo: empty string is not a valid code."
                }
                $parsed = $null
                $parsed64 = $null
                if ($s.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
                    if (-not [uint32]::TryParse($s.Substring(2), [System.Globalization.NumberStyles]::AllowHexSpecifier, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
                        throw "Get-WindowsErrorInfo: could not parse hex string '$s'."
                    }
                    $u = $parsed
                }
                else {
                    if (-not [int64]::TryParse($s, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed64)) {
                        throw "Get-WindowsErrorInfo: could not parse string '$s'."
                    }
                    $u = [Therena.WindowsDevelopmentShellTools.WindowsErrorInteropWds4]::Low32BitsFromSignedValue($parsed64)
                }
            }
            else {
                throw "Get-WindowsErrorInfo: unsupported type '$($raw.GetType().FullName)'. Use integer or string."
            }

            $interop = [Therena.WindowsDevelopmentShellTools.WindowsErrorInteropWds4]
            $i = $interop::AsSignedInt32([uint32]$u)
            $low16 = $interop::Low16OfUInt32($u)

            $win32Desc = $interop::TryFormatWin32($u)
            if ([string]::IsNullOrWhiteSpace($win32Desc)) {
                $win32Desc = $interop::TryFormatWin32($low16)
            }
            if ([string]::IsNullOrWhiteSpace($win32Desc)) {
                $win32Desc = '(no Win32 system message for this value)'
            }

            $hrDesc = $interop::TryGetHResultMessage($i)
            if ([string]::IsNullOrWhiteSpace($hrDesc)) {
                $hrSys = $interop::TryFormatWin32($u)
                if (-not [string]::IsNullOrWhiteSpace($hrSys)) {
                    $hrDesc = $hrSys
                }
                else {
                    $hrDesc = '(no HRESULT message for this value)'
                }
            }

            $ntDesc = $interop::TryFormatNtStatus($u)
            if ([string]::IsNullOrWhiteSpace($ntDesc)) {
                $ntDesc = '(no NTSTATUS message in ntdll for this value)'
            }

            $hrFromWin32 = $interop::HRESULT_FROM_WIN32($low16)
            $win32FromNt = $interop::RtlNtStatusToDosErrorUInt($i)
            $hrFromWin32Signed = $interop::AsSignedInt32([uint32]$hrFromWin32)
            $derivedNtFromWin32Text = $interop::FormatDosErrorToNtStatusBestEffort($low16)

            $Row = $Table.NewRow()
            $Row.InputCode = $u.ToString([System.Globalization.CultureInfo]::InvariantCulture)
            $Row.InputCodeHex = ('0x{0:X8}' -f $u)
            $Row.Win32Interpretation = ('Win32 {0} ({1})' -f $u, ('0x{0:X8}' -f $u))
            $Row.Win32Description = $win32Desc
            $Row.HResultInterpretation = ('HRESULT 0x{0:X8} (signed: {1})' -f $u, $i)
            $Row.HResultDescription = $hrDesc
            $Row.NtStatusInterpretation = ('NTSTATUS 0x{0:X8} (signed: {1})' -f $u, $i)
            $Row.NtStatusDescription = $ntDesc
            $Row.DerivedFromWin32_HResult = ('0x{0:X8} ({1})' -f $hrFromWin32, $hrFromWin32Signed)
            $Row.DerivedFromWin32_NtStatus = $derivedNtFromWin32Text
            $Row.DerivedFromNtStatus_Win32 = ('{0} (0x{1:X8})' -f $win32FromNt, $win32FromNt)
            [void]$Table.Rows.Add($Row)
        }

        return ,$Table
    }
}

function Get-DateTime {
<#

.SYNOPSIS
Returns the current date and time in several string formats.

.DESCRIPTION
Outputs a DataTable with four rows: local time, Unix seconds, Windows file time, and ISO 8601 (sortable invariant string). 

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-DateTime

Format    Time
------    ----
Time      13.11.2018 21:02:58
Unix Time 1542142978
File Time 131866129788272588
ISO Date  2018-11-13T21:02:58

#>
    [CmdletBinding()]
    param ()
    
    $Table = New-Object System.Data.DataTable "Time"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Format, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Time, ([string])))

    $Time = [System.DateTime]::Now
    $Time1970 = New-Object System.DateTime 1970, 1, 1

    $Row = $Table.NewRow()
    $Row.Format = "Time"
    $Row.Time = $Time
    [void]$Table.Rows.Add($Row)

    $Row = $Table.NewRow()
    $Row.Format = "Unix Time"
    $Row.Time = [System.Math]::Floor(($Time - $Time1970).TotalSeconds)
    [void]$Table.Rows.Add($Row)
    
    $Row = $Table.NewRow()
    $Row.Format = "File Time"
    $Row.Time = $Time.ToFileTime()
    [void]$Table.Rows.Add($Row)
    
    $Row = $Table.NewRow()
    $Row.Format = "ISO Date"
    $Row.Time = $Time.ToString("s", [System.Globalization.CultureInfo]::InvariantCulture);
    [void]$Table.Rows.Add($Row)

    return ,$Table
}