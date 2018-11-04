<#

.SYNOPSIS
Powershell module with helper function for my daily software development

.DESCRIPTION
All the tooling which is needed for my daily software develpment work.
There is everything from debugging, dump analysis to coding etc.

.LINK
https://github.com/Therena/PowerShellTools

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
Get the full path to a file in the installed Windows kits 

.DESCRIPTION
This function searches for the files in the installed windows kit (SDK, WDK).
Please install at least one Windows kit (SDK, WDK) version before using this function.

.PARAMETER File
The file name which has to be located within the Windows Kit installations

.LINK
https://github.com/Therena/PowerShellTools
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
        [parameter(Mandatory=$true)]
        [string]$File      
    )
    
    $Table = New-Object System.Data.DataTable "WindowsKit"
    $Table.Columns.Add($(New-Object system.Data.DataColumn Path, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn WDK, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn Bitness, ([string])))

    $FoundFiles = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits" -Filter $File -File -Recurse

    foreach($FileEntry in $FoundFiles) {
        $Row = $Table.NewRow()
        
        $Row.Path = $FileEntry.FullName
        $Row.WDK = $FileEntry.Directory.Parent.Parent.Name
        $Row.Bitness = $FileEntry.Directory.Name
        
        $Table.Rows.Add($Row)
    }

    return $Table
}

function Get-DebuggerPath {
<#

.SYNOPSIS
Get the paths to the Windows Debug (WinDBG) executables in the installed Windows kits 

.DESCRIPTION
This function searches for the Windows Debug executable files in the installed windows kit (SDK, WDK).
Please install at least one Windows kit (SDK, WDK) version before using this function.

.LINK
https://github.com/Therena/PowerShellTools
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
Get the paths to the Windows Kernel Debug (kd) executables in the installed Windows kits 

.DESCRIPTION
This function searches for the Windows Kernel Debug executable files in the installed windows kit (SDK, WDK).
Please install at least one Windows kit (SDK, WDK) version before using this function.

.LINK
https://github.com/Therena/PowerShellTools
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
Get the paths to the symbol check (symchk) executables in the installed Windows kits 

.DESCRIPTION
This function searches for the symbol check executable files in the installed windows kit (SDK, WDK).
Please install at least one Windows kit (SDK, WDK) version before using this function.

.LINK
https://github.com/Therena/PowerShellTools
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
Prints the eicar (European Expert Group for IT-Security) siganture

.DESCRIPTION
This function prints the eciar (European Expert Group for IT-Security) sigature to the console.
It is splitted into parts in the script itself to avoid virus detection on the script.
For the same reason the signature is not completely added to the example output.

.LINK
http://www.eicar.org
https://github.com/Therena/PowerShellTools

.EXAMPLE
Get-EicarSignature

Signature                                                           
---------                                                           
...EICAR-STANDARD-ANTIVIRUS-TEST-FILE!...
  

#>
    $Table = New-Object System.Data.DataTable "EicarSignature"
    $Table.Columns.Add($(New-Object system.Data.DataColumn Signature, ([string])))
    
    $Row = $Table.NewRow()
    $Row.Signature = "X5O!P%@AP[4\PZX54(P^)7CC)7}"
    $Row.Signature += "`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*"
    $Table.Rows.Add($Row)

    return $Table
}

function Get-OperatingSystemBitness {
<#

.SYNOPSIS
Get bitness of the installed Windows operating system

.DESCRIPTION
This function optains the bitness of the current installed Microsoft Windows operating system

.LINK
https://github.com/Therena/PowerShellTools

.EXAMPLE
Get-OperatingSystemBitness

Type
----
x64  

#>
    $Table = New-Object System.Data.DataTable "Bitness"
    $Table.Columns.Add($(New-Object system.Data.DataColumn Type, ([string])))

    $Row = $Table.NewRow()
    if ([Environment]::Is64BitProcess -ne [Environment]::Is64BitOperatingSystem) {
        $Row.Type = 'x86'
    } else {
        $Row.Type = 'x64'
    }
    $Table.Rows.Add($Row)

    return $Table
}

function Get-DumpAnalysis {
<#

.SYNOPSIS
Runs and prints an analysis of a crash dump file

.DESCRIPTION
Forwards the give the crash dump file to the installed kernel debugger to get otain some details about the issue.

.PARAMETER File
The path to the dump file which needs to be analyzed

.LINK
https://github.com/Therena/PowerShellTools

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
        [parameter(Mandatory=$true, ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [string]$File  
    )

    if (-Not (Test-Path $File)) {
       throw "Unable to find the give dump file: $File"
    }

    $OSBitness = Get-OperatingSystemBitness

    $Debugger = Get-KernelDebuggerPath | Where-Object {
        $_.Bitness -eq $OSBitness.Type
    } 
    
    $BestSelectionDebugger = $Debugger | Sort-Object -Property WDK | Select-Object -first 1

    $BestSelectionDebugger | ForEach-Object {
        & $_.Path -c """!analyze -v;q""" -z """$File"""
    }
}


function Open-DumpAnalysis {
<#

.SYNOPSIS
Opens an analysis of a crash dump file

.DESCRIPTION
Forwards the give the crash dump file to the installed kernel debugger to get otain some details about the issue.

.PARAMETER File
The path to the dump file which needs to be analyzed

.LINK
https://github.com/Therena/PowerShellTools

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
        [parameter(Mandatory=$true, ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
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
        & $_.Path -c """!analyze -v;""" -z """$File"""
    }
}

function Connect-KernelDebugger {
<#

.SYNOPSIS
Connect the kernel debugger (windbg) to the given host system

.DESCRIPTION
Starts the kernel debugger (windbg) and connects it to the provided pipe of an host system.
This initilaizes the Windows kernel debugging session.

.PARAMETER Host
The name of the host system to which the connection should be established

.PARAMETER Port
The port or pipe name which should be used to connect to the host system

.LINK
https://github.com/Therena/PowerShellTools

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
        & $_.Path -n -k com:pipe,port=\\$host\pipe\$port,resets=0,reconnect
    }
}

function Get-LinesOfCode {
<#

.SYNOPSIS
Count the lines of code in all the selected files

.DESCRIPTION
Count the lines of code in the selected files or directories.
Makes it also possible the list the lines of each single file in one directory

.PARAMETER Path
The path to the file(s) which lines should be counted

.PARAMETER Extensions
Filter for the file extensions which should be included in the counting

.PARAMETER Recursive
Defines if the counting should be done recursive for all the subfoders

.PARAMETER FileBased
Defines if the result will be one line count for all files or the that the line count will be listed for each single file

.LINK
https://github.com/Therena/PowerShellTools

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
        [parameter(Mandatory=$true)]
        [string]$Path,

        [string[]]$Extensions = "*.*",
        
        [switch]$Recursive,
        
        [switch]$FileBased
    )

    $Table = New-Object System.Data.DataTable "LineCount"
    $Table.Columns.Add($(New-Object system.Data.DataColumn Path, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn Count, ([long])))
        
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
            $Table.Rows.Add($Row)
        }
    } else {
        $Row = $Table.NewRow()
        $Row.Path = $Path
        $Row.Count = ($SelectedItems | Select-String .).Count
        $Table.Rows.Add($Row)
    }

    return $Table
}

function Find-Symbols {
<#

.SYNOPSIS
Find the symbols (PDBs) for the given path


.DESCRIPTION
Query the symbol server for the symbols of the given path

.PARAMETER Path
Path to the file or folder for which the symbols should be queried

.PARAMETER DownloadTo
Optional download location for the found symbol files

.PARAMETER Detailed
Verbose or detailed output of the symbol query process

.LINK
https://github.com/Therena/PowerShellTools

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
        [parameter(Mandatory=$true, ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [string]$Path,
        
        [string]$DownloadTo,

        [switch]$Detailed
    )

    if (-Not (Test-Path $Path)) {
       throw "Unable to find the given file or folder: $Path"
    }

    $OSBitness = Get-OperatingSystemBitness

    $SymbolCheck = Get-SymbolCheck | Where-Object {
        $_.Bitness -eq $OSBitness.Type
    } 
    
    $BestSelectionSymbolCheck = $SymbolCheck | Sort-Object -Property WDK | Select-Object -first 1

    $BestSelectionSymbolCheck | ForEach-Object {
        if ($DownloadTo) {
            if ($Detailed) {
                & $_.Path """$Path""" /r /v /oc """$DownloadTo"""
            } else {
                & $_.Path """$Path""" /r /oc """$DownloadTo"""
            }
        } else {
            if ($Detailed) {
                & $_.Path """$Path""" /r /v
            } else {
                & $_.Path """$Path""" /r
            }
        }
    }
}

function Get-FileDetails {
<#

.SYNOPSIS
Obtain the details of the given file(s) or directory

.DESCRIPTION
Obtain details about the given file(s) or directories. 
Details like Version numbers, file descriptions, company, etc. will be read from the file.

.PARAMETER File
File(s) or directory for which the details should be obtained 

.PARAMETER Filter
Filter for specific file types

.PARAMETER Recursive
Defines if the the sub directories should be taken into account as well

.EXAMPLE
Get-FileDetails C:\Windows\regedit.exe


File            : C:\Windows\regedit.exe
FileVersion     : 10.0.17134.346 (WinBuild.160101.0800)
ProductVersion  : 10.0.17134.346
FileDescription : Registrierungs-Editor
CompanyName     : Microsoft Corporation
InternalName    : REGEDIT
LegalCopyright  : © Microsoft Corporation. Alle Rechte vorbehalten.
ProductName     : Betriebssystem Microsoft® Windows®

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
C:\Windows\hh.exe               10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Ausführbare Microsoft®-HTML-Hilfsdatei                Microsoft Corporation      HH 1.41        
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
C:\Windows\bfsvc.exe    10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Startdatei-Wartungshilfsprogramm       Microsoft Corporation      bfsvc.exe       © Microsoft Corpora...
C:\Windows\explorer.exe 10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Windows-Explorer                       Microsoft Corporation      explorer        © Microsoft Corpora...
C:\Windows\HelpPane.exe 10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Microsoft-Hilfe und Support            Microsoft Corporation      HelpPane.exe    © Microsoft Corpora...
C:\Windows\hh.exe       10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Ausführbare Microsoft®-HTML-Hilfsdatei Microsoft Corporation      HH 1.41         © Microsoft Corpora...
C:\Windows\notepad.exe  10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Editor                                 Microsoft Corporation      Notepad         © Microsoft Corpora...
C:\Windows\py.exe       3.6.6                                 3.6.6          Python                                 Python Software Foundation Python Launcher Copyright © 2001-20...
C:\Windows\pyw.exe      3.6.6                                 3.6.6          Python                                 Python Software Foundation Python Launcher Copyright © 2001-20...
C:\Windows\regedit.exe  10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Registrierungs-Editor                  Microsoft Corporation      REGEDIT         © Microsoft Corpora...
C:\Windows\splwow64.exe 10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Print driver host for applications     Microsoft Corporation      splwow64.exe    © Microsoft Corpora...
C:\Windows\winhlp32.exe 10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Windows Winhlp32-Stub                  Microsoft Corporation      WINHSTB         © Microsoft Corpora...
C:\Windows\write.exe    10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Windows Write                          Microsoft Corporation      write           © Microsoft Corpora...

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$File,

        [string]$Filter = "*.*",
        
        [switch]$Recursive    
    )
    
    $Table = New-Object System.Data.DataTable "File Details"
    $Table.Columns.Add($(New-Object system.Data.DataColumn File, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn FileVersion, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn ProductVersion, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn FileDescription, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn CompanyName, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn InternalName, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn LegalCopyright, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn ProductName, ([string])))
     
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

        $Table.Rows.Add($Row)
    }

    return $Table
}

#
# Export the members of the module
#
Export-ModuleMember -Function Get-OperatingSystemBitness
Export-ModuleMember -Function Get-DebuggerPath
Export-ModuleMember -Function Get-KernelDebuggerPath
Export-ModuleMember -Function Find-WindowsKitFile
Export-ModuleMember -Function Connect-KernelDebugger
Export-ModuleMember -Function Get-DumpAnalysis
Export-ModuleMember -Function Open-DumpAnalysis
Export-ModuleMember -Function Get-LinesOfCode
Export-ModuleMember -Function Get-EicarSignature
Export-ModuleMember -Function Get-SymbolCheck
Export-ModuleMember -Function Find-Symbols
Export-ModuleMember -Function Get-FileDetails
