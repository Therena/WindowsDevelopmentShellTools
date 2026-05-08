function Expand-Zip {
<#

.SYNOPSIS
Recursively expands a zip archive, including any nested zip files found after extraction.

.DESCRIPTION
Extracts the archive supplied through Path into a destination folder, walks the extracted tree, and extracts any *.zip files it finds, repeating until no zip archives remain (or until MaxDepth is reached). Returns a DataTable with one row per archive that was processed: source archive path, destination folder, the number of file entries written, and the recursion depth (0 for the top-level archive). Uses System.IO.Compression.ZipFile, which ships with PowerShell 5.1 and 7+ on Windows. Entries whose resolved path would escape the destination folder are rejected.

.PARAMETER Path
Path to a .zip archive. Accepts pipeline input and binds Get-ChildItem objects through their FullName property.

.PARAMETER DestinationPath
Optional destination directory for the top-level archive. Defaults to a sibling folder next to the archive named after the archive's base name. The directory is created if it does not exist; existing files inside are overwritten on conflict.

.PARAMETER RemoveArchiveAfterExtraction
When set, deletes nested zip files after their contents have been written. The top-level archive supplied through Path is left in place.

.PARAMETER MaxDepth
Safety limit for recursion depth (default 16). Prevents runaway extraction when an archive contains itself or a very deep chain of zips.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Expand-Zip -Path C:\Drop\Build.zip

Archive                     Destination                 FileCount Depth
-------                     -----------                 --------- -----
C:\Drop\Build.zip           C:\Drop\Build                       42     0
C:\Drop\Build\Symbols.zip   C:\Drop\Build\Symbols                7     1

.EXAMPLE
Expand-Zip -Path C:\Drop\Build.zip -RemoveArchiveAfterExtraction

Same as the example above, but every nested .zip file is deleted once its contents have been written. The top-level archive on disk is preserved.

.EXAMPLE
Get-ChildItem -Path C:\Drop -Filter *.zip | Expand-Zip -DestinationPath C:\Out

Pipes archives from Get-ChildItem (FullName binds to -Path) and extracts each into C:\Out.

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [Alias('FullName')]
        [string]$Path,

        [string]$DestinationPath,

        [switch]$RemoveArchiveAfterExtraction,

        [int]$MaxDepth = 16
    )

    begin {
        try {
            Add-Type -AssemblyName 'System.IO.Compression.FileSystem' -ErrorAction Stop
        } catch {
            # On PowerShell 7 the type is already loaded; ignore the failure.
        }

        $Table = New-Object System.Data.DataTable "Expanded Zips"
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn Archive, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn Destination, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn FileCount, ([long])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn Depth, ([int])))
    }

    process {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Unable to find the given zip file: $Path"
        }
        $resolvedArchive = (Resolve-Path -LiteralPath $Path).Path

        if ($PSBoundParameters.ContainsKey('DestinationPath') -and -not [string]::IsNullOrWhiteSpace($DestinationPath)) {
            $rootDestination = $DestinationPath
        } else {
            $archiveItem = Get-Item -LiteralPath $resolvedArchive
            $rootDestination = Join-Path $archiveItem.DirectoryName $archiveItem.BaseName
        }

        Invoke-ZipExpansion -ArchivePath $resolvedArchive -Destination $rootDestination -Depth 0 -MaxDepth $MaxDepth -RemoveArchiveAfterExtraction:$RemoveArchiveAfterExtraction -Table $Table
    }

    end {
        return ,$Table
    }
}
