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
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
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
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
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
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
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
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
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
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
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

$CertificateAssemblies = (
    "System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
)

$CertificateSource = @"
    namespace Therena.Encryption
    {
        using System;
        using System.IO;
        using System.Collections.Generic;
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
                var certs = new List<System.Security.Cryptography.Pkcs.SignerInfo>();
                
                var cms = new SignedCms();
                cms.Decode(pvData);

                foreach (var signatures in cms.SignerInfos)
                {
                    certs.Add(signatures);
                }
                
                return certs.ToArray();
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

Add-Type -ReferencedAssemblies $CertificateAssemblies -TypeDefinition $CertificateSource -Language CSharp

function Get-NestedAuthenticodeDetails {
<#

.SYNOPSIS
Get recursive all the nested signatures

.DESCRIPTION
Get recursive all the nested signatures from the parent signature

.PARAMETER Certificate
The parent signature to check for nested certificates

.PARAMETER Table
The resulting table of all the certificates attached to the file

.LINK
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

    $NestedCerts = $Cert.UnsignedAttributes | Where-Object {$_.Oid.Value -eq "1.3.6.1.4.1.311.2.4.1"}
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

            $Table.Rows.Add($Row)
            
            Get-NestedAuthenticodeDetails -Certificate $Cert -Table $Table
        }
    }
}

function Get-AuthenticodeDetails {
<#

.SYNOPSIS
Read the certificates from the given file

.DESCRIPTION
Read the authenticode certificates from the given file

.PARAMETER File
The path to the file which should be checked on certificates

.LINK
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
    $Table.Columns.Add($(New-Object system.Data.DataColumn Subject, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn Issuer, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn DigestAlgorithm, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn Thumbprint, ([string])))
    $Table.Columns.Add($(New-Object system.Data.DataColumn PublicKey, ([string])))
    
    $CertificateList = [Therena.Encryption.Certificate]::GetCertificates($File)
    $DnsName = [System.Security.Cryptography.X509Certificates.X509NameType]::DnsName;
    
    foreach($Cert in $CertificateList) {
        $Row = $Table.NewRow()
    
        $Row.Subject = $Cert.Certificate.Subject;
        $Row.Issuer = $Cert.Certificate.Issuer;
        $Row.DigestAlgorithm = $Cert.DigestAlgorithm.FriendlyName;
        $Row.Thumbprint = $Cert.Certificate.Thumbprint;
        $Row.PublicKey = [System.BitConverter]::ToString($Cert.Certificate.PublicKey.EncodedKeyValue.RawData).Replace("-", " ")

        $Table.Rows.Add($Row)
        
        Get-NestedAuthenticodeSignatureDetails -Certificate $Cert -Table $Table
    }

    return $Table
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
Get the content of the file in hexadecimal format

.DESCRIPTION
Get the content of the file in hexadecimal format and print it to the screen

.PARAMETER File
The file to convert into the hexadecimal byte format

.PARAMETER Width
The count of the 8 byte secments to show in one row.
If this parameter is not set it determines the count from the window width of the shell.

.EXAMPLE
Get-HexDump "C:\Windows\regedit.exe"
0000: 4d 5a 90 00 03 00 00 00 -- 04 00 00 00 ff ff 00 00    MZ.............
0010: b8 00 00 00 00 00 00 00 -- 40 00 00 00 00 00 00 00    ¸.......@.......
0020: 00 00 00 00 00 00 00 00 -- 00 00 00 00 00 00 00 00    ................
0030: 00 00 00 00 00 00 00 00 -- 00 00 00 00 f0 00 00 00    ............ð...
0040: 0e 1f ba 0e 00 b4 09 cd -- 21 b8 01 4c cd 21 54 68    ..º..´.Í!¸.LÍ!Th
0050: 69 73 20 70 72 6f 67 72 -- 61 6d 20 63 61 6e 6e 6f    is program canno
0060: 74 20 62 65 20 72 75 6e -- 20 69 6e 20 44 4f 53 20    t be run in DOS 
0070: 6d 6f 64 65 2e 0d 0d 0a -- 24 00 00 00 00 00 00 00    mode....$.......
0080: e4 16 38 77 a0 77 56 24 -- a0 77 56 24 a0 77 56 24    ä.8w wV$ wV$ wV$
0090: a9 0f c5 24 a2 77 56 24 -- 82 17 53 25 a1 77 56 24    ©.Å$¢wV$‚.S%¡wV$
00a0: 82 17 55 25 a4 77 56 24 -- 82 17 52 25 b3 77 56 24    ‚.U%¤wV$‚.R%³wV$
00b0: 82 17 57 25 81 77 56 24 -- a0 77 57 24 c5 76 56 24    ‚.W%wV$ wW$ÅvV$
00c0: 82 17 5f 25 be 77 56 24 -- 82 17 a9 24 a1 77 56 24    ‚._%¾wV$‚.©$¡wV$
00d0: 82 17 54 25 a1 77 56 24 -- 52 69 63 68 a0 77 56 24    ‚.T%¡wV$Rich wV$
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
Export-ModuleMember -Function Get-AuthenticodeDetails
Export-ModuleMember -Function Get-HexDump
