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
0000: 4d 5a 90 00 03 00 00 00 -- 04 00 00 00 ff ff 00 00    MZï¿½.............
0010: b8 00 00 00 00 00 00 00 -- 40 00 00 00 00 00 00 00    ï¿½.......@.......
0020: 00 00 00 00 00 00 00 00 -- 00 00 00 00 00 00 00 00    ................
0030: 00 00 00 00 00 00 00 00 -- 00 00 00 00 f0 00 00 00    ............ï¿½...
0040: 0e 1f ba 0e 00 b4 09 cd -- 21 b8 01 4c cd 21 54 68    ..ï¿½..ï¿½.ï¿½!ï¿½.Lï¿½!Th
0050: 69 73 20 70 72 6f 67 72 -- 61 6d 20 63 61 6e 6e 6f    is program canno
0060: 74 20 62 65 20 72 75 6e -- 20 69 6e 20 44 4f 53 20    t be run in DOS 
0070: 6d 6f 64 65 2e 0d 0d 0a -- 24 00 00 00 00 00 00 00    mode....$.......
0080: e4 16 38 77 a0 77 56 24 -- a0 77 56 24 a0 77 56 24    ï¿½.8wï¿½wV$ï¿½wV$ï¿½wV$
0090: a9 0f c5 24 a2 77 56 24 -- 82 17 53 25 a1 77 56 24    ï¿½.ï¿½$ï¿½wV$ï¿½.S%ï¿½wV$
00a0: 82 17 55 25 a4 77 56 24 -- 82 17 52 25 b3 77 56 24    ï¿½.U%ï¿½wV$ï¿½.R%ï¿½wV$
00b0: 82 17 57 25 81 77 56 24 -- a0 77 57 24 c5 76 56 24    ï¿½.W%ï¿½wV$ï¿½wW$ï¿½vV$
00c0: 82 17 5f 25 be 77 56 24 -- 82 17 a9 24 a1 77 56 24    ï¿½._%ï¿½wV$ï¿½.ï¿½$ï¿½wV$
00d0: 82 17 54 25 a1 77 56 24 -- 52 69 63 68 a0 77 56 24    ï¿½.T%ï¿½wV$Richï¿½wV$
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
