function Invoke-SymChkArguments {
<#

.SYNOPSIS
Invokes symchk with recursive symbol resolution options.

.DESCRIPTION
Runs symchk with /r on the target path, optionally /v for verbose output and /oc with a download directory when DownloadTo is set. Used by Find-Symbols. This command is not exported from the module.

.PARAMETER SymChkExecutable
Full path to symchk.exe.

.PARAMETER TargetPath
File or folder to check.

.PARAMETER DownloadTo
Optional output directory for downloaded symbols (/oc).

.PARAMETER Detailed
If set, adds /v for verbose symchk output.

#>
    param(
        [Parameter(Mandatory)]
        [string]$SymChkExecutable,
        [Parameter(Mandatory)]
        [string]$TargetPath,
        [string]$DownloadTo,
        [switch]$Detailed
    )
    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add($TargetPath)
    [void]$arguments.Add('/r')
    if ($Detailed) {
        [void]$arguments.Add('/v')
    }
    if ($DownloadTo) {
        [void]$arguments.Add('/oc')
        [void]$arguments.Add($DownloadTo)
    }
    & $SymChkExecutable @arguments
}
