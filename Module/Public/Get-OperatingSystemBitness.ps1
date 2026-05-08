function Get-OperatingSystemBitness {
<#

.SYNOPSIS
Gets the processor architecture class of the installed Windows OS.

.DESCRIPTION
Returns a one-row DataTable with column Type set to one of arm64, arm, x64, or x86, matching the Windows Kits Debuggers subdirectory naming convention. Detection prefers System.Runtime.InteropServices.RuntimeInformation.OSArchitecture so it works on ARM64 Windows; it falls back to Environment.Is64BitOperatingSystem when the runtime API is unavailable. Other functions use this to pick matching debugger or symchk binaries.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-OperatingSystemBitness

Type
----
x64  

#>
    $Table = New-Object System.Data.DataTable "Bitness"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Type, ([string])))

    $Row = $Table.NewRow()
    $resolved = $null
    try {
        $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
        switch ($arch) {
            'Arm64' { $resolved = 'arm64' }
            'Arm'   { $resolved = 'arm' }
            'X64'   { $resolved = 'x64' }
            'X86'   { $resolved = 'x86' }
        }
    } catch {
        $resolved = $null
    }
    if (-not $resolved) {
        if ([Environment]::Is64BitOperatingSystem) {
            $resolved = 'x64'
        } else {
            $resolved = 'x86'
        }
    }
    $Row.Type = $resolved
    [void]$Table.Rows.Add($Row)

    return ,$Table
}
