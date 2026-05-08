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
