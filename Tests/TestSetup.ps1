BeforeDiscovery {
    $script:IsWindowsOs = ($null -ne $IsWindows -and $IsWindows) -or ($env:OS -eq 'Windows_NT')

    $script:CscExe = $null
    if ($script:IsWindowsOs) {
        # Probe well-known csc.exe locations directly. Avoid Get-ChildItem -Recurse over the
        # .NET Framework tree because it can be very slow (and trigger ACL stalls).
        $candidatePaths = @(
            "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework64\v3.5\csc.exe",
            "$env:WINDIR\Microsoft.NET\Framework\v3.5\csc.exe"
        )
        foreach ($candidate in $candidatePaths) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $script:CscExe = $candidate
                break
            }
        }
    }
    $script:HasArgvProbe = [bool]$script:CscExe
}

BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $moduleManifestCandidates = @(
        (Join-Path $repoRoot 'Windows-Development-Shell-Tools.psd1'),
        (Join-Path $repoRoot (Join-Path 'Module' 'Windows-Development-Shell-Tools.psd1'))
    )
    $script:ModuleManifest = $moduleManifestCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $script:ModuleManifest) {
        throw "Module manifest not found. Checked: $($moduleManifestCandidates -join ', ')"
    }
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

function Global:New-ArgvProbeExecutable {
    param(
        [Parameter(Mandatory)]
        [string]$DestinationPath,
        [Parameter(Mandatory)]
        [string]$CscPath
    )
    $sourceFile = [System.IO.Path]::ChangeExtension($DestinationPath, '.cs')
    @'
using System;
class P {
    static int Main(string[] args) {
        for (int i = 0; i < args.Length; i++) Console.WriteLine("[" + i + "]={" + args[i] + "}");
        return 0;
    }
}
'@ | Set-Content -LiteralPath $sourceFile -Encoding UTF8

    & $CscPath /nologo /target:exe /out:$DestinationPath $sourceFile | Out-Null
    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        return $null
    }
    return $DestinationPath
}

