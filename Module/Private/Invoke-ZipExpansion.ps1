function Invoke-ZipExpansion {
<#

.SYNOPSIS
Extracts a single zip archive and recurses into nested archives.

.DESCRIPTION
Worker for Expand-Zip. Opens the archive at ArchivePath with System.IO.Compression.ZipFile, walks each entry into Destination (creating parent folders and overwriting existing files), records a row in Table, then enumerates *.zip files under the destination and calls itself for each one. Refuses entries whose resolved path escapes Destination (zip slip protection) and stops recursing once Depth exceeds MaxDepth. This command is not exported from the module.

.PARAMETER ArchivePath
Full path to a .zip archive on disk.

.PARAMETER Destination
Directory the archive contents are written into; created if it does not exist.

.PARAMETER Depth
Current recursion depth. 0 for the top-level archive supplied to Expand-Zip.

.PARAMETER MaxDepth
Maximum recursion depth allowed before extraction stops with a warning.

.PARAMETER RemoveArchiveAfterExtraction
When set, deletes nested zip files after their contents have been written. The top-level archive is preserved by Expand-Zip regardless of this switch.

.PARAMETER Table
DataTable that collects one row per processed archive (Archive, Destination, FileCount, Depth).

#>
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,
        [Parameter(Mandatory)]
        [string]$Destination,
        [Parameter(Mandatory)]
        [int]$Depth,
        [Parameter(Mandatory)]
        [int]$MaxDepth,
        [switch]$RemoveArchiveAfterExtraction,
        [Parameter(Mandatory)]
        [System.Data.DataTable]$Table
    )

    if ($Depth -gt $MaxDepth) {
        Write-Warning "Expand-Zip stopped at depth $Depth for '$ArchivePath' (MaxDepth $MaxDepth)."
        return
    }

    if (-not (Test-Path -LiteralPath $Destination)) {
        [void](New-Item -ItemType Directory -Path $Destination -Force)
    }
    $resolvedDestination = (Resolve-Path -LiteralPath $Destination).Path
    $destinationRoot = $resolvedDestination.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar

    $entryCount = 0
    $zip = $null
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
        foreach ($entry in $zip.Entries) {
            $relative = $entry.FullName -replace '/', [System.IO.Path]::DirectorySeparatorChar
            $entryDest = [System.IO.Path]::Combine($resolvedDestination, $relative)
            $entryFull = [System.IO.Path]::GetFullPath($entryDest)
            if (-not ($entryFull + [System.IO.Path]::DirectorySeparatorChar).StartsWith($destinationRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to extract entry that escapes destination: $($entry.FullName)"
            }

            if ([string]::IsNullOrEmpty($entry.Name)) {
                if (-not (Test-Path -LiteralPath $entryFull)) {
                    [void](New-Item -ItemType Directory -Path $entryFull -Force)
                }
                continue
            }

            $entryParent = [System.IO.Path]::GetDirectoryName($entryFull)
            if ($entryParent -and -not (Test-Path -LiteralPath $entryParent)) {
                [void](New-Item -ItemType Directory -Path $entryParent -Force)
            }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entryFull, $true)
            $entryCount++
        }
    } finally {
        if ($null -ne $zip) {
            $zip.Dispose()
        }
    }

    $Row = $Table.NewRow()
    $Row.Archive = $ArchivePath
    $Row.Destination = $resolvedDestination
    $Row.FileCount = [long]$entryCount
    $Row.Depth = $Depth
    [void]$Table.Rows.Add($Row)

    $nestedZips = @(Get-ChildItem -LiteralPath $resolvedDestination -Filter '*.zip' -File -Recurse -ErrorAction SilentlyContinue)
    foreach ($inner in $nestedZips) {
        $innerArchive = $inner.FullName
        $innerDestination = Join-Path $inner.DirectoryName $inner.BaseName
        Invoke-ZipExpansion -ArchivePath $innerArchive -Destination $innerDestination -Depth ($Depth + 1) -MaxDepth $MaxDepth -RemoveArchiveAfterExtraction:$RemoveArchiveAfterExtraction -Table $Table
        if ($RemoveArchiveAfterExtraction) {
            Remove-Item -LiteralPath $innerArchive -Force -ErrorAction SilentlyContinue
        }
    }
}
