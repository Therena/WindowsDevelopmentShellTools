. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-LinesOfCode' {
    BeforeAll {
        $script:LocFile = Join-Path $TestDrive 'linecount-sample.txt'
        @('one', 'two', 'three') | Set-Content -LiteralPath $script:LocFile -Encoding utf8
        $script:LocFileResolved = (Resolve-Path -LiteralPath $script:LocFile).Path
        $script:LocFolderResolved = [System.IO.Path]::GetDirectoryName($script:LocFileResolved)
        Mock Get-ChildItem {
            Get-Item -LiteralPath $script:LocFileResolved
        } -ParameterFilter {
            if ([string]::IsNullOrEmpty($Path)) { return $false }
            try {
                $p = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
            } catch {
                return $false
            }
            if ($p -eq $script:LocFileResolved) { return $true }
            if ($Recurse -and $p -eq $script:LocFolderResolved) { return $true }
            return $false
        }
    }

    It 'counts lines for a single file path' {
        $t = Get-ModuleDataTableResult -Name 'Get-LinesOfCode' -Parameters @{ Path = $script:LocFileResolved }
        $t.Rows.Count | Should -Be 1
        Get-TestDataTableValue -Table $t -RowIndex 0 -ColumnName 'Path' | Should -Be $script:LocFileResolved
        [long](Get-TestDataTableValue -Table $t -RowIndex 0 -ColumnName 'Count') | Should -Be 3
    }

    It 'lists per file when -FileBased and -Recursive are set' {
        $folder = $script:LocFolderResolved
        $t = Get-ModuleDataTableResult -Name 'Get-LinesOfCode' -Parameters @{
            Path      = $folder
            Recursive = $true
            FileBased = $true
        }
        $t.Rows.Count | Should -Be 1
        Get-TestDataTableValue -Table $t -RowIndex 0 -ColumnName 'Count' | Should -Be 3
    }
}


