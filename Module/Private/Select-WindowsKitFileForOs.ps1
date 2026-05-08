function Select-WindowsKitFileForOs {
<#

.SYNOPSIS
Picks the newest Windows Kit row that matches the current OS architecture.

.DESCRIPTION
Helper used by Find-Symbols, Get-DumpAnalysis, Open-DumpAnalysis, and Connect-KernelDebugger to resolve a single Windows Kit binary path for the running OS. Enumerates the supplied DataTable rows explicitly (so the architecture filter actually runs against each row), then sorts by WDK descending so the newest installed kit wins. On ARM64 Windows the function falls back to x64 binaries when no native arm64 row is available, since arm64 Windows can run x64 emulated debuggers. This command is not exported from the module.

.PARAMETER KitTable
DataTable returned by Find-WindowsKitFile (or one of the Get-*Path wrappers) containing Path, WDK, and Bitness columns.

#>
    param(
        [Parameter(Mandatory)]
        [System.Data.DataTable]$KitTable
    )

    $osBitness = (Get-OperatingSystemBitness).Rows[0].Type

    $preferenceOrder = switch ($osBitness) {
        'arm64' { @('arm64', 'x64', 'x86') }
        'arm'   { @('arm', 'x86') }
        'x64'   { @('x64') }
        'x86'   { @('x86') }
        default { @($osBitness) }
    }

    foreach ($candidate in $preferenceOrder) {
        $match = $KitTable.Rows |
            Where-Object { $_.Bitness -eq $candidate } |
            Sort-Object -Property WDK -Descending |
            Select-Object -First 1
        if ($null -ne $match) {
            return $match
        }
    }

    return $null
}
