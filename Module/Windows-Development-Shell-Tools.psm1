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