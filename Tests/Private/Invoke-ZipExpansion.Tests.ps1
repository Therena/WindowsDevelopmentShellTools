. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Invoke-ZipExpansion' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        Add-Type -AssemblyName 'System.IO.Compression' -ErrorAction SilentlyContinue
        Add-Type -AssemblyName 'System.IO.Compression.FileSystem' -ErrorAction SilentlyContinue

        function Global:New-TestZipArchive {
            param(
                [Parameter(Mandatory)][string]$ArchivePath,
                [Parameter(Mandatory)][hashtable]$Entries
            )
            if (Test-Path -LiteralPath $ArchivePath) { Remove-Item -LiteralPath $ArchivePath -Force }
            $stream = [System.IO.File]::Open($ArchivePath, [System.IO.FileMode]::Create)
            try {
                $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
                try {
                    foreach ($k in $Entries.Keys) {
                        $entry = $zip.CreateEntry($k)
                        $bytes = if ($Entries[$k] -is [byte[]]) { $Entries[$k] } else { [System.Text.Encoding]::UTF8.GetBytes([string]$Entries[$k]) }
                        $es = $entry.Open(); try { $es.Write($bytes,0,$bytes.Length) } finally { $es.Dispose() }
                    }
                } finally { $zip.Dispose() }
            } finally { $stream.Dispose() }
        }
    }

    AfterAll {
        Remove-Item -Path Function:\New-TestZipArchive -ErrorAction SilentlyContinue
    }

    It 'extracts archive and records one row in the result table' {
        $work = Join-Path $TestDrive 'invoke-zip'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $archive = Join-Path $work 'outer.zip'
        New-TestZipArchive -ArchivePath $archive -Entries @{ 'a.txt' = 'hello'; 'b.bin' = [byte[]](1,2) }

        InModuleScope $script:ModuleName -ArgumentList $archive,$work -ScriptBlock {
            param($Archive,$Root)
            $tbl = New-Object System.Data.DataTable
            [void]$tbl.Columns.Add('Archive',[string])
            [void]$tbl.Columns.Add('Destination',[string])
            [void]$tbl.Columns.Add('FileCount',[long])
            [void]$tbl.Columns.Add('Depth',[int])
            Invoke-ZipExpansion -ArchivePath $Archive -Destination (Join-Path $Root 'out') -Depth 0 -MaxDepth 16 -Table $tbl
            $tbl.Rows.Count | Should -Be 1
            [long]$tbl.Rows[0]['FileCount'] | Should -Be 2
        }
    }

    It 'rejects zip-slip entries that escape destination' {
        $work = Join-Path $TestDrive 'invoke-zip-slip'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $archive = Join-Path $work 'evil.zip'

        $stream = [System.IO.File]::Open($archive, [System.IO.FileMode]::Create)
        try {
            $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                $entry = $zip.CreateEntry('../escape.txt')
                $es = $entry.Open(); try { $bytes = [System.Text.Encoding]::UTF8.GetBytes('x'); $es.Write($bytes,0,$bytes.Length) } finally { $es.Dispose() }
            } finally { $zip.Dispose() }
        } finally { $stream.Dispose() }

        InModuleScope $script:ModuleName -ArgumentList $archive,$work -ScriptBlock {
            param($Archive,$Root)
            $tbl = New-Object System.Data.DataTable
            [void]$tbl.Columns.Add('Archive',[string])
            [void]$tbl.Columns.Add('Destination',[string])
            [void]$tbl.Columns.Add('FileCount',[long])
            [void]$tbl.Columns.Add('Depth',[int])
            { Invoke-ZipExpansion -ArchivePath $Archive -Destination (Join-Path $Root 'out') -Depth 0 -MaxDepth 16 -Table $tbl } | Should -Throw -ExpectedMessage '*escapes destination*'
        }
    }
}
