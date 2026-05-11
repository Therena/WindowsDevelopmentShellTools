. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-HlkxDigitalSignature' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        Add-Type -AssemblyName WindowsBase -ErrorAction Stop
        $script:UnsignedOpcPath = Join-Path $TestDrive 'unsigned-opc.zip'
        $pkg = [System.IO.Packaging.Package]::Open(
            $script:UnsignedOpcPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::ReadWrite)
        $pkg.Close()
    }

    It 'returns a DataTable with expected columns' {
        $t = Get-ModuleDataTableResult -Name 'Get-HlkxDigitalSignature' -Parameters @{ Path = $script:UnsignedOpcPath }
        $t.TableName | Should -Be 'HLKX digital signatures'
        @(
            'FilePath', 'ProcessingError', 'PackageIsSigned', 'OpcVerifyResult', 'SignatureCount',
            'SignatureIndex', 'Subject', 'Thumbprint', 'ChainBuilt'
        ) | ForEach-Object {
            $t.Columns.Contains($_) | Should -Be $true
        }
    }

    It 'reports NotSigned for an empty OPC package' {
        $t = Get-ModuleDataTableResult -Name 'Get-HlkxDigitalSignature' -Parameters @{ Path = $script:UnsignedOpcPath }
        $t.Rows.Count | Should -Be 1
        $t.Rows[0]['PackageIsSigned'] | Should -Be $false
        $t.Rows[0]['OpcVerifyResult'] | Should -Be 'NotSigned'
        [string]::IsNullOrEmpty([string]$t.Rows[0]['ProcessingError']) | Should -Be $true
        $t.Rows[0]['SignatureCount'] | Should -Be 0
        $t.Rows[0]['SignatureIndex'] | Should -Be -1
    }

    It 'records ProcessingError for a missing path' {
        $missing = Join-Path $TestDrive 'does-not-exist.hlkx'
        $t = Get-ModuleDataTableResult -Name 'Get-HlkxDigitalSignature' -Parameters @{ Path = $missing }
        $t.Rows.Count | Should -Be 1
        $t.Rows[0]['ProcessingError'] | Should -Not -BeNullOrEmpty
        $t.Rows[0]['OpcVerifyResult'] | Should -Be ([string]::Empty)
        $t.Rows[0]['PackageIsSigned'] | Should -Be $false
    }

    It 'records ProcessingError when the file is not a valid package' {
        $bad = Join-Path $TestDrive 'not-opc.bin'
        [System.IO.File]::WriteAllBytes($bad, [byte[]](0x00, 0x01, 0x02))
        $bad = (Resolve-Path -LiteralPath $bad).Path
        $t = Get-ModuleDataTableResult -Name 'Get-HlkxDigitalSignature' -Parameters @{ Path = $bad }
        $t.Rows.Count | Should -Be 1
        $t.Rows[0]['ProcessingError'] | Should -Not -BeNullOrEmpty
        $t.Rows[0]['OpcVerifyResult'] | Should -Be ([string]::Empty)
        $t.Rows[0]['PackageIsSigned'] | Should -Be $false
    }
}
