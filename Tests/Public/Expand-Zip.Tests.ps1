. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Expand-Zip' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        Add-Type -AssemblyName 'System.IO.Compression' -ErrorAction SilentlyContinue
        Add-Type -AssemblyName 'System.IO.Compression.FileSystem' -ErrorAction SilentlyContinue

        function Global:New-TestZipArchive {
            param(
                [Parameter(Mandatory)]
                [string]$ArchivePath,
                [Parameter(Mandatory)]
                [hashtable]$Entries
            )
            if (Test-Path -LiteralPath $ArchivePath) {
                Remove-Item -LiteralPath $ArchivePath -Force
            }
            $stream = [System.IO.File]::Open($ArchivePath, [System.IO.FileMode]::Create)
            try {
                $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
                try {
                    foreach ($key in $Entries.Keys) {
                        $entry = $zip.CreateEntry($key)
                        $value = $Entries[$key]
                        $bytes = $null
                        if ($value -is [byte[]]) {
                            $bytes = $value
                        } elseif ($value -is [string]) {
                            $bytes = [System.Text.Encoding]::UTF8.GetBytes($value)
                        } else {
                            $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$value)
                        }
                        $entryStream = $entry.Open()
                        try {
                            $entryStream.Write($bytes, 0, $bytes.Length)
                        } finally {
                            $entryStream.Dispose()
                        }
                    }
                } finally {
                    $zip.Dispose()
                }
            } finally {
                $stream.Dispose()
            }
        }
    }

    AfterAll {
        Remove-Item -Path Function:\New-TestZipArchive -ErrorAction SilentlyContinue
    }

    It 'throws when the archive does not exist' {
        $missing = Join-Path $TestDrive 'no-such-archive.zip'
        { Expand-Zip -Path $missing } | Should -Throw
    }

    It 'extracts a flat archive to the default sibling folder' {
        $work = Join-Path $TestDrive 'flat'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $archive = Join-Path $work 'flat.zip'
        New-TestZipArchive -ArchivePath $archive -Entries @{
            'readme.txt' = 'hello'
            'sub/data.bin' = [byte[]](1, 2, 3, 4)
        }

        $table = Get-ModuleDataTableResult -Name 'Expand-Zip' -Parameters @{ Path = $archive }
        ,$table | Should -BeOfType [System.Data.DataTable]
        @('Archive', 'Destination', 'FileCount', 'Depth') | ForEach-Object {
            $table.Columns[$_].ColumnName | Should -Be $_
        }
        $table.Rows.Count | Should -Be 1
        $table.Rows[0]['Depth'] | Should -Be 0
        [long]$table.Rows[0]['FileCount'] | Should -Be 2

        $expectedDest = Join-Path $work 'flat'
        Test-Path -LiteralPath (Join-Path $expectedDest 'readme.txt') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $expectedDest 'sub\data.bin') | Should -BeTrue
        Get-Content -LiteralPath (Join-Path $expectedDest 'readme.txt') -Raw | Should -Match 'hello'
    }

    It 'recurses into nested zip archives' {
        $work = Join-Path $TestDrive 'nested'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $innerArchive = Join-Path $work 'inner-source.zip'
        New-TestZipArchive -ArchivePath $innerArchive -Entries @{
            'inside.txt' = 'leaf'
        }
        $innerBytes = [System.IO.File]::ReadAllBytes($innerArchive)
        Remove-Item -LiteralPath $innerArchive -Force

        $outerArchive = Join-Path $work 'outer.zip'
        New-TestZipArchive -ArchivePath $outerArchive -Entries @{
            'top.txt' = 'top'
            'pkg/inner.zip' = $innerBytes
        }

        $table = Get-ModuleDataTableResult -Name 'Expand-Zip' -Parameters @{ Path = $outerArchive }
        $table.Rows.Count | Should -Be 2
        $depths = foreach ($row in $table.Rows) { [int]$row['Depth'] }
        $depths | Should -Contain 0
        $depths | Should -Contain 1

        $outerDest = Join-Path $work 'outer'
        $innerDest = Join-Path $outerDest 'pkg\inner'
        Test-Path -LiteralPath (Join-Path $outerDest 'top.txt') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $outerDest 'pkg\inner.zip') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $innerDest 'inside.txt') | Should -BeTrue
    }

    It 'removes nested archives but keeps the top-level archive when -RemoveArchiveAfterExtraction is set' {
        $work = Join-Path $TestDrive 'remove'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $innerArchive = Join-Path $work 'tmp-inner.zip'
        New-TestZipArchive -ArchivePath $innerArchive -Entries @{ 'inside.txt' = 'leaf' }
        $innerBytes = [System.IO.File]::ReadAllBytes($innerArchive)
        Remove-Item -LiteralPath $innerArchive -Force

        $outerArchive = Join-Path $work 'outer.zip'
        New-TestZipArchive -ArchivePath $outerArchive -Entries @{
            'top.txt' = 'top'
            'inner.zip' = $innerBytes
        }

        $null = Get-ModuleDataTableResult -Name 'Expand-Zip' -Parameters @{
            Path = $outerArchive
            RemoveArchiveAfterExtraction = $true
        }

        $outerDest = Join-Path $work 'outer'
        Test-Path -LiteralPath $outerArchive | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $outerDest 'inner.zip') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $outerDest 'inner\inside.txt') | Should -BeTrue
    }

    It 'honors -DestinationPath for the top-level archive' {
        $work = Join-Path $TestDrive 'destpath'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $archive = Join-Path $work 'archive.zip'
        New-TestZipArchive -ArchivePath $archive -Entries @{ 'a.txt' = 'content' }
        $custom = Join-Path $work 'custom-out'

        $table = Get-ModuleDataTableResult -Name 'Expand-Zip' -Parameters @{
            Path = $archive
            DestinationPath = $custom
        }
        $table.Rows[0]['Destination'] | Should -Be (Resolve-Path -LiteralPath $custom).Path
        Test-Path -LiteralPath (Join-Path $custom 'a.txt') | Should -BeTrue
    }

    It 'rejects archive entries that escape the destination folder' {
        $work = Join-Path $TestDrive 'zip-slip'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $archive = Join-Path $work 'evil.zip'

        $stream = [System.IO.File]::Open($archive, [System.IO.FileMode]::Create)
        try {
            $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                $entry = $zip.CreateEntry('../escape.txt')
                $entryStream = $entry.Open()
                try {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes('nope')
                    $entryStream.Write($bytes, 0, $bytes.Length)
                } finally {
                    $entryStream.Dispose()
                }
            } finally {
                $zip.Dispose()
            }
        } finally {
            $stream.Dispose()
        }

        { Expand-Zip -Path $archive } | Should -Throw -ExpectedMessage '*escapes destination*'
    }
}


