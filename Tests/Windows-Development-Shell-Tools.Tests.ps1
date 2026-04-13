BeforeDiscovery {
    $script:IsWindowsOs = ($null -ne $IsWindows -and $IsWindows) -or ($env:OS -eq 'Windows_NT')
}

BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $script:ModuleManifest = Join-Path $repoRoot (Join-Path 'Module' 'Windows-Development-Shell-Tools.psd1')
    Get-Module Windows-Development-Shell-Tools -ErrorAction SilentlyContinue | Remove-Module -Force
    Import-Module $script:ModuleManifest -Force -ErrorAction Stop
    $script:ModuleName = (Get-Module Windows-Development-Shell-Tools).Name
}

function Global:Get-ModuleDataTableResult {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [hashtable]$Parameters = @{}
    )
    $cmd = Get-Command -Name $Name -Module Windows-Development-Shell-Tools -ErrorAction Stop
    $raw = @(& $cmd @Parameters)

    function Resolve-DataTableFromOutput {
        param($o)
        if ($null -eq $o) { return $null }
        # Comma prevents DataTable from being enumerated into DataRows when returned to the caller's assignment.
        if ($o -is [System.Data.DataTable]) { return ,$o }
        if ($o -is [System.Data.DataRow] -and $null -ne $o.Table) { return ,$o.Table }
        foreach ($x in @($o)) {
            $inner = Resolve-DataTableFromOutput $x
            if ($null -ne $inner) { return ,$inner }
        }
        return $null
    }

    $tbl = Resolve-DataTableFromOutput $raw
    if (-not $tbl) {
        throw "No System.Data.DataTable output could be resolved from '$Name'."
    }
    if ($tbl -isnot [System.Data.DataTable]) {
        throw "Resolved value from '$Name' is not a DataTable: $($tbl.GetType().FullName)"
    }
    return ,$tbl
}

function Global:Get-TestDataTableValue {
    param(
        [System.Data.DataTable]$Table,
        [int]$RowIndex,
        [string]$ColumnName
    )
    return $Table.Rows[$RowIndex][$ColumnName]
}

Describe 'Windows-Development-Shell-Tools manifest' {
    It 'passes Test-ModuleManifest' {
        { Test-ModuleManifest $script:ModuleManifest -ErrorAction Stop } | Should -Not -Throw
    }
}

Describe 'Exported commands' {
    It 'exports every function listed in FunctionsToExport' {
        $data = Import-PowerShellDataFile $script:ModuleManifest
        $exported = @((Get-Module Windows-Development-Shell-Tools).ExportedFunctions.Keys)
        foreach ($name in $data.FunctionsToExport) {
            $exported | Should -Contain $name
        }
    }
}

Describe 'Get-DateTime' {
    It 'returns four time formats' {
        $table = Get-ModuleDataTableResult -Name 'Get-DateTime'
        # DataTable is IEnumerable; piping it to Should enumerates rows — use unary comma.
        ,$table | Should -BeOfType [System.Data.DataTable]
        $table.Rows.Count | Should -Be 4
        $formats = foreach ($row in $table.Rows) { $row['Format'] }
        $formats | Should -Contain 'Unix Time'
        $formats | Should -Contain 'ISO Date'
    }
}

Describe 'Get-EicarSignature' {
    It 'returns the EICAR test string' {
        $table = Get-ModuleDataTableResult -Name 'Get-EicarSignature'
        $signature = Get-TestDataTableValue -Table $table -RowIndex 0 -ColumnName 'Signature'
        $signature | Should -Match 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'
    }
}

Describe 'Get-OperatingSystemBitness' {
    It 'returns x64 or x86' {
        $table = Get-ModuleDataTableResult -Name 'Get-OperatingSystemBitness'
        $type = Get-TestDataTableValue -Table $table -RowIndex 0 -ColumnName 'Type'
        $type | Should -BeIn @('x64', 'x86')
    }
}

Describe 'Find-WindowsKitFile' {
    BeforeAll {
        Mock Get-ChildItem {
            $dir = [pscustomobject]@{
                Name     = 'x64'
                Parent   = [pscustomobject]@{
                    Name   = 'Debuggers'
                    Parent = [pscustomobject]@{ Name = '10' }
                }
            }
            [pscustomobject]@{
                FullName  = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe'
                Directory = $dir
            }
        } -ParameterFilter {
            $Path -like '*Windows Kits*' -and $Recurse -and $Filter -eq 'windbg.exe' -and $File
        }
    }

    It 'returns a DataTable with Path, WDK, and Bitness columns' {
        $table = Get-ModuleDataTableResult -Name 'Find-WindowsKitFile' -Parameters @{ File = 'windbg.exe' }
        @('Path', 'WDK', 'Bitness') | ForEach-Object { $table.Columns[$_].ColumnName | Should -Be $_ }
    }

    It 'maps directory layout into at least one row' {
        $table = Get-ModuleDataTableResult -Name 'Find-WindowsKitFile' -Parameters @{ File = 'windbg.exe' }
        $table.Rows.Count | Should -BeGreaterThan 0
        $row = $table.Rows[0]
        $row.Path | Should -Match 'windbg\.exe$'
        $row.WDK | Should -Not -BeNullOrEmpty
        $row.Bitness | Should -Match '^(x64|x86|arm|arm64)$'
    }
}

Describe 'Get-DebuggerPath, Get-KernelDebuggerPath, Get-SymbolCheck' {
    BeforeAll {
        Mock Get-ChildItem {
            $dir = [pscustomobject]@{
                Name     = 'x64'
                Parent   = [pscustomobject]@{
                    Name   = 'Debuggers'
                    Parent = [pscustomobject]@{ Name = '10' }
                }
            }
            [pscustomobject]@{
                FullName  = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\$Filter"
                Directory = $dir
            }
        } -ParameterFilter {
            $Path -like '*Windows Kits*' -and $Recurse -and $Filter -and $File
        }
    }

    It 'Get-DebuggerPath searches for windbg.exe' {
        $t = Get-ModuleDataTableResult -Name 'Get-DebuggerPath'
        (Get-TestDataTableValue -Table $t -RowIndex 0 -ColumnName 'Path') | Should -Match 'windbg\.exe$'
    }

    It 'Get-KernelDebuggerPath searches for kd.exe' {
        $t = Get-ModuleDataTableResult -Name 'Get-KernelDebuggerPath'
        (Get-TestDataTableValue -Table $t -RowIndex 0 -ColumnName 'Path') | Should -Match 'kd\.exe$'
    }

    It 'Get-SymbolCheck searches for symchk.exe' {
        $t = Get-ModuleDataTableResult -Name 'Get-SymbolCheck'
        (Get-TestDataTableValue -Table $t -RowIndex 0 -ColumnName 'Path') | Should -Match 'symchk\.exe$'
    }
}

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

Describe 'Get-DumpAnalysis and Open-DumpAnalysis' {
    It 'Get-DumpAnalysis throws when the dump file is missing' {
        $missing = Join-Path $TestDrive 'nope.dmp'
        { Get-DumpAnalysis -File $missing } | Should -Throw
    }

    It 'Open-DumpAnalysis throws when the dump file is missing' {
        $missing = Join-Path $TestDrive 'nope.dmp'
        { Open-DumpAnalysis -File $missing } | Should -Throw
    }

    Context 'invokes the kernel debugger shim when a matching debugger row exists' -Skip:(-not $script:IsWindowsOs) {
        BeforeEach {
            $script:DumpTestFile = Join-Path $TestDrive 'minimal.dmp'
            [System.IO.File]::WriteAllBytes($script:DumpTestFile, [byte[]](0x4D, 0x44, 0x4D, 0x50))
            $script:DumpTestFile = (Resolve-Path -LiteralPath $script:DumpTestFile).Path

            Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Type', [string])
                $r = $dt.NewRow()
                $r.Type = 'x64'
                [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Get-KernelDebuggerPath {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Path', [string])
                [void]$dt.Columns.Add('WDK', [string])
                [void]$dt.Columns.Add('Bitness', [string])
                $r = $dt.NewRow()
                $r.Path = 'C:\FakeKits\10\Debuggers\x64\kd.exe'
                $r.WDK = '10'
                $r.Bitness = 'x64'
                [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Invoke-KernelDebuggerDumpAnalysis { }
        }

        It 'Get-DumpAnalysis requests AnalyzeThenQuit' {
            Get-DumpAnalysis -File $script:DumpTestFile
            Should -Invoke -CommandName Invoke-KernelDebuggerDumpAnalysis -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $DebuggerExecutable -eq 'C:\FakeKits\10\Debuggers\x64\kd.exe' -and
                    $DumpFile -eq $script:DumpTestFile -and
                    $InitialCommandMode -eq 'AnalyzeThenQuit'
            }
        }

        It 'Open-DumpAnalysis requests AnalyzeStayOpen' {
            Open-DumpAnalysis -File $script:DumpTestFile
            Should -Invoke -CommandName Invoke-KernelDebuggerDumpAnalysis -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $DebuggerExecutable -eq 'C:\FakeKits\10\Debuggers\x64\kd.exe' -and
                    $DumpFile -eq $script:DumpTestFile -and
                    $InitialCommandMode -eq 'AnalyzeStayOpen'
            }
        }
    }
}

Describe 'Find-Symbols' {
    It 'throws when the path does not exist' {
        $missing = Join-Path $TestDrive 'missing.dll'
        { Find-Symbols -Path $missing } | Should -Throw
    }

    Context 'invokes symchk with the expected switches' -Skip:(-not $script:IsWindowsOs) {
        BeforeEach {
            $script:SymTarget = Join-Path $TestDrive 'sym-target.dll'
            [System.IO.File]::WriteAllBytes($script:SymTarget, [byte[]](0x4D, 0x5A))
            $script:SymTarget = (Resolve-Path -LiteralPath $script:SymTarget).Path
            $script:SymOutDir = Join-Path $TestDrive 'sym-download'
            New-Item -ItemType Directory -Path $script:SymOutDir -Force | Out-Null
            $script:SymOutDir = (Resolve-Path -LiteralPath $script:SymOutDir).Path

            Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Type', [string])
                $r = $dt.NewRow()
                $r.Type = 'x64'
                [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Get-SymbolCheck {
                $dt = New-Object System.Data.DataTable
                [void]$dt.Columns.Add('Path', [string])
                [void]$dt.Columns.Add('WDK', [string])
                [void]$dt.Columns.Add('Bitness', [string])
                $r = $dt.NewRow()
                $r.Path = 'C:\FakeKits\10\Debuggers\x64\symchk.exe'
                $r.WDK = '10'
                $r.Bitness = 'x64'
                [void]$dt.Rows.Add($r)
                return ,$dt
            }
            Mock -ModuleName $script:ModuleName Invoke-SymChkArguments { }
        }

        It 'runs symchk with /r only by default' {
            Find-Symbols -Path $script:SymTarget
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $SymChkExecutable -eq 'C:\FakeKits\10\Debuggers\x64\symchk.exe' -and
                    $TargetPath -eq $script:SymTarget -and
                    -not $DownloadTo -and
                    -not $Detailed
            }
        }

        It 'runs symchk once per path when multiple paths are passed' {
            $second = Join-Path $TestDrive 'sym-target2.dll'
            [System.IO.File]::WriteAllBytes($second, [byte[]](0x4D, 0x5A))
            $secondResolved = (Resolve-Path -LiteralPath $second).Path
            Find-Symbols -Path @($script:SymTarget, $secondResolved)
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 2
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter { $TargetPath -eq $script:SymTarget }
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter { $TargetPath -eq $secondResolved }
        }

        It 'accumulates FullName paths from pipeline input' {
            $second = Join-Path $TestDrive 'sym-target2.dll'
            [System.IO.File]::WriteAllBytes($second, [byte[]](0x4D, 0x5A))
            $secondResolved = (Resolve-Path -LiteralPath $second).Path
            Get-Item -LiteralPath $script:SymTarget, $secondResolved | Find-Symbols
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 2
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter { $TargetPath -eq $script:SymTarget }
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter { $TargetPath -eq $secondResolved }
        }

        It 'passes -DownloadTo to every symchk run when piping multiple paths' {
            $second = Join-Path $TestDrive 'sym-target2.dll'
            [System.IO.File]::WriteAllBytes($second, [byte[]](0x4D, 0x5A))
            $secondResolved = (Resolve-Path -LiteralPath $second).Path
            Get-Item -LiteralPath $script:SymTarget, $secondResolved | Find-Symbols -DownloadTo $script:SymOutDir
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 2 -ParameterFilter {
                $DownloadTo -eq $script:SymOutDir -and -not $Detailed
            }
        }

        It 'adds /v when -Detailed is set' {
            Find-Symbols -Path $script:SymTarget -Detailed
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $Detailed -eq $true -and $TargetPath -eq $script:SymTarget -and -not $DownloadTo
            }
        }

        It 'adds /oc when -DownloadTo is set' {
            Find-Symbols -Path $script:SymTarget -DownloadTo $script:SymOutDir
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $DownloadTo -eq $script:SymOutDir -and -not $Detailed
            }
        }

        It 'combines /v and /oc when both switches are used' {
            Find-Symbols -Path $script:SymTarget -Detailed -DownloadTo $script:SymOutDir
            Should -Invoke -CommandName Invoke-SymChkArguments -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
                $Detailed -eq $true -and $DownloadTo -eq $script:SymOutDir
            }
        }
    }
}

Describe 'Connect-KernelDebugger' {
    It 'does not throw when no debugger is found (no-op)' {
        Mock -ModuleName $script:ModuleName Get-DebuggerPath {
            $dt = New-Object System.Data.DataTable
            [void]$dt.Columns.Add('Path', [string])
            [void]$dt.Columns.Add('WDK', [string])
            [void]$dt.Columns.Add('Bitness', [string])
            return ,$dt
        }
        Mock -ModuleName $script:ModuleName Invoke-WinDbgKernelRemotePipe { throw 'should not be called' }
        { Connect-KernelDebugger -Host 'localhost' -Port 'test-pipe' } | Should -Not -Throw
        Should -Invoke -CommandName Invoke-WinDbgKernelRemotePipe -ModuleName $script:ModuleName -Times 0
    }

    It 'starts WinDbg with the kernel pipe when a debugger row exists' -Skip:(-not $script:IsWindowsOs) {
        Mock -ModuleName $script:ModuleName Get-OperatingSystemBitness {
            $dt = New-Object System.Data.DataTable
            [void]$dt.Columns.Add('Type', [string])
            $r = $dt.NewRow()
            $r.Type = 'x64'
            [void]$dt.Rows.Add($r)
            return ,$dt
        }
        Mock -ModuleName $script:ModuleName Get-DebuggerPath {
            $dt = New-Object System.Data.DataTable
            [void]$dt.Columns.Add('Path', [string])
            [void]$dt.Columns.Add('WDK', [string])
            [void]$dt.Columns.Add('Bitness', [string])
            $r = $dt.NewRow()
            $r.Path = 'C:\FakeKits\10\Debuggers\x64\windbg.exe'
            $r.WDK = '10'
            $r.Bitness = 'x64'
            [void]$dt.Rows.Add($r)
            return ,$dt
        }
        Mock -ModuleName $script:ModuleName Invoke-WinDbgKernelRemotePipe { }

        Connect-KernelDebugger -Host 'srv01' -Port 'MYPIPE'

        Should -Invoke -CommandName Invoke-WinDbgKernelRemotePipe -ModuleName $script:ModuleName -Times 1 -ParameterFilter {
            $DebuggerExecutable -eq 'C:\FakeKits\10\Debuggers\x64\windbg.exe' -and
                $RemoteHost -eq 'srv01' -and
                $PipeName -eq 'MYPIPE'
        }
    }
}

Describe 'Get-HexDump' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        $script:HexFile = Join-Path $TestDrive 'hex.bin'
        [System.IO.File]::WriteAllBytes($script:HexFile, [byte[]](0x4D, 0x5A, 0x90, 0x00))
    }

    It 'returns a hex string starting with an offset line' {
        $out = Get-HexDump -File $script:HexFile -Width 2
        $out | Should -Match '0000:'
        $out | Should -Match '4d 5a'
    }
}

Describe 'Get-FileDetails' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        $script:FileDetailsTarget = Join-Path $TestDrive 'filedetails-copy.exe'
        $src = $null
        foreach ($name in @('notepad.exe', 'cmd.exe', 'explorer.exe')) {
            $p = Join-Path $env:SystemRoot "System32\$name"
            if (Test-Path -LiteralPath $p) {
                $src = $p
                break
            }
        }
        if (-not $src) {
            throw 'No suitable System32 executable found to copy for Get-FileDetails test.'
        }
        Copy-Item -LiteralPath $src -Destination $script:FileDetailsTarget -Force
        $script:FileDetailsTarget = (Resolve-Path -LiteralPath $script:FileDetailsTarget).Path
    }

    It 'returns version metadata for a copied System32 executable' {
        $t = Get-ModuleDataTableResult -Name 'Get-FileDetails' -Parameters @{ File = $script:FileDetailsTarget }
        $t.Rows.Count | Should -BeGreaterThan 0
        $t.Rows[0]['File'] | Should -Be $script:FileDetailsTarget
        $t.Rows[0]['CompanyName'] | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-AuthenticodeDetails' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        $signers = $null
        $cert = New-SelfSignedCertificate -Subject 'CN=Test Authenticode Row' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddHours(1)
        try {
            $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,[byte]1)
            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms $content, $false
            $cmsSigner = New-Object System.Security.Cryptography.Pkcs.CmsSigner $cert
            $cms.ComputeSignature($cmsSigner)
            $signers = [Therena.Encryption.Certificate]::DecodeCertificateData($cms.Encode())
        } finally {
            Remove-Item -Path ('Cert:\CurrentUser\My\' + $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
        if ($null -eq $signers -or $signers.Length -lt 1) {
            throw 'Failed to build PKCS signer fixture for Get-AuthenticodeDetails test.'
        }
        $global:__WDS_TestAuthenticodeSigners = $signers
        InModuleScope $script:ModuleName {
            Mock Get-AuthenticodeSignerInfosForFile { return ,$global:__WDS_TestAuthenticodeSigners }
            Mock Get-NestedAuthenticodeDetails { }
        }
    }

    AfterAll {
        Remove-Variable -Name __WDS_TestAuthenticodeSigners -Scope Global -Force -ErrorAction SilentlyContinue
    }

    It 'fills the certificate table from PKCS signer metadata' {
        $path = Join-Path $TestDrive 'auth-dummy.bin'
        [System.IO.File]::WriteAllBytes($path, [byte[]](0))
        $path = (Resolve-Path -LiteralPath $path).Path
        $t = Get-ModuleDataTableResult -Name 'Get-AuthenticodeDetails' -Parameters @{ File = $path }
        $t.Rows.Count | Should -BeGreaterThan 0
        $t.Rows[0]['Subject'] | Should -Match 'Test Authenticode Row'
        $t.Rows[0]['DigestAlgorithm'] | Should -Match 'sha256'
        $t.Rows[0]['Thumbprint'] | Should -Match '^[0-9A-F]{40}$'
    }
}

Describe 'Get-NestedAuthenticodeDetails' -Skip:(-not $script:IsWindowsOs) {
    It 'adds no rows when the signer has no nested PKCS attributes' {
        $signers = $null
        $cert = New-SelfSignedCertificate -Subject 'CN=NestedPath Signer' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddHours(1)
        try {
            $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,[byte]2)
            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms $content, $false
            $cmsSigner = New-Object System.Security.Cryptography.Pkcs.CmsSigner $cert
            $cms.ComputeSignature($cmsSigner)
            $signers = [Therena.Encryption.Certificate]::DecodeCertificateData($cms.Encode())
        } finally {
            Remove-Item -Path ('Cert:\CurrentUser\My\' + $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
        InModuleScope $script:ModuleName -ArgumentList @(, $signers) -ScriptBlock {
            param($SignerArray)
            $tbl = New-Object System.Data.DataTable 'NestedTest'
            [void]$tbl.Columns.Add('Subject', [string])
            [void]$tbl.Columns.Add('Issuer', [string])
            [void]$tbl.Columns.Add('DigestAlgorithm', [string])
            [void]$tbl.Columns.Add('Thumbprint', [string])
            [void]$tbl.Columns.Add('PublicKey', [string])
            Get-NestedAuthenticodeDetails -Certificate $SignerArray[0] -Table $tbl
            $tbl.Rows.Count | Should -Be 0
        }
    }

    It 'expands nested Microsoft OID 1.3.6.1.4.1.311.2.4.1 using checked-in CMS fixture' {
        $fixture = Join-Path $PSScriptRoot 'Fixtures\nested-authenticode-attribute.cms'
        Test-Path -LiteralPath $fixture | Should -BeTrue
        $raw = [System.IO.File]::ReadAllBytes($fixture)
        $outer = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $outer.Decode($raw)
        $signerInfo = $outer.SignerInfos[0]
        InModuleScope $script:ModuleName -ArgumentList $signerInfo -ScriptBlock {
            param($Si)
            $tbl = New-Object System.Data.DataTable 'NestedFixture'
            [void]$tbl.Columns.Add('Subject', [string])
            [void]$tbl.Columns.Add('Issuer', [string])
            [void]$tbl.Columns.Add('DigestAlgorithm', [string])
            [void]$tbl.Columns.Add('Thumbprint', [string])
            [void]$tbl.Columns.Add('PublicKey', [string])
            Get-NestedAuthenticodeDetails -Certificate $Si -Table $tbl
            $tbl.Rows.Count | Should -BeGreaterThan 0
            @($tbl.Rows | Where-Object { $_.Subject -like '*Inner Nested Fixture*' }).Count | Should -Be 1
        }
    }
}

Describe 'Get-AuthenticodeDetails integration' -Skip:(-not $script:IsWindowsOs) {
    It 'Get-AuthenticodeSignerInfosForFile returns PKCS signers for a common system PE' {
        $picked = $null
        foreach ($rel in @(
                'System32\ntdll.dll',
                'System32\kernel32.dll',
                'System32\win32u.dll',
                'SysWOW64\ntdll.dll'
            )) {
            $full = Join-Path $env:SystemRoot $rel
            if (-not (Test-Path -LiteralPath $full)) {
                continue
            }
            $list = InModuleScope $script:ModuleName -ArgumentList $full -ScriptBlock {
                param($FilePath)
                Get-AuthenticodeSignerInfosForFile -FilePath $FilePath
            }
            if ($null -ne $list -and @($list).Count -gt 0) {
                $picked = $full
                break
            }
        }
        $picked | Should -Not -BeNullOrEmpty
    }

    It 'Get-AuthenticodeDetails returns certificate rows for a system file with embedded PKCS' {
        $picked = $null
        $table = $null
        foreach ($rel in @('System32\ntdll.dll', 'System32\kernel32.dll', 'System32\win32u.dll')) {
            $full = Join-Path $env:SystemRoot $rel
            if (-not (Test-Path -LiteralPath $full)) {
                continue
            }
            $t = Get-ModuleDataTableResult -Name 'Get-AuthenticodeDetails' -Parameters @{ File = $full }
            if ($t.Rows.Count -gt 0) {
                $picked = $full
                $table = $t
                break
            }
        }
        $picked | Should -Not -BeNullOrEmpty
        $table.Rows[0]['Subject'] | Should -Not -BeNullOrEmpty
        $table.Rows[0]['Thumbprint'] | Should -Match '^[0-9A-F]{40}$'
    }
}

Describe 'Get-GlobalAssemblyCache' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        Mock -ModuleName $script:ModuleName Get-ItemProperty {
            [pscustomobject]@{
                'System.Runtime,4.0.0.0,,,MSIL' = $null
            }
        } -ParameterFilter {
            # Provider-qualified paths also appear as e.g. Microsoft.PowerShell.Core\Registry::...
            "$Path" -like '*Fusion*GACChangeNotification*Default*'
        }
    }

    It 'returns a DataTable with expected columns and parses Fusion-style value names' {
        $t = Get-ModuleDataTableResult -Name 'Get-GlobalAssemblyCache'
        @('Assembly', 'Version', 'ProcessorArchitecture') | ForEach-Object {
            $t.Columns[$_].ColumnName | Should -Be $_
        }
        $t.Rows.Count | Should -BeGreaterThan 0
        $t.Rows[0]['Assembly'] | Should -Be 'System.Runtime'
        $t.Rows[0]['ProcessorArchitecture'] | Should -Be 'MSIL'
    }
}
