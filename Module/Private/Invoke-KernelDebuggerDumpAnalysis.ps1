function Invoke-KernelDebuggerDumpAnalysis {
<#

.SYNOPSIS
Runs the kernel debugger against a dump with a standard !analyze command.

.DESCRIPTION
Starts the debugger executable with -z pointing at the dump file and -c running !analyze -v. AnalyzeThenQuit adds q so the debugger exits after analysis; AnalyzeStayOpen omits q so the session stays open. Used by Get-DumpAnalysis and Open-DumpAnalysis. This command is not exported from the module.

.PARAMETER DebuggerExecutable
Full path to kd.exe or a compatible debugger.

.PARAMETER DumpFile
Full path to the crash dump file.

.PARAMETER InitialCommandMode
AnalyzeThenQuit or AnalyzeStayOpen.

#>
    param(
        [Parameter(Mandatory)]
        [string]$DebuggerExecutable,
        [Parameter(Mandatory)]
        [string]$DumpFile,
        [Parameter(Mandatory)]
        [ValidateSet('AnalyzeThenQuit', 'AnalyzeStayOpen')]
        [string]$InitialCommandMode
    )
    if ($InitialCommandMode -eq 'AnalyzeThenQuit') {
        & $DebuggerExecutable -c '!analyze -v;q' -z $DumpFile
    } else {
        & $DebuggerExecutable -c '!analyze -v;' -z $DumpFile
    }
}
