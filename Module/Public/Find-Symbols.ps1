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

        $BestSelectionSymbolCheck = Select-WindowsKitFileForOs -KitTable (Get-SymbolCheck)

        if ($null -eq $BestSelectionSymbolCheck) {
            throw 'Unable to locate a symchk.exe matching the current OS architecture in any installed Windows Kit. Install the Windows SDK or WDK for your architecture.'
        }

        foreach ($singlePath in $pathAccumulator) {
            Invoke-SymChkArguments -SymChkExecutable $BestSelectionSymbolCheck.Path -TargetPath $singlePath -DownloadTo $DownloadTo -Detailed:$Detailed
        }
    }
}
