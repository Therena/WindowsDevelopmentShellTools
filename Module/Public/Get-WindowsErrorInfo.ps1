function Get-WindowsErrorInfo {
<#

.SYNOPSIS
Interprets a raw 32-bit Windows error value as Win32, HRESULT, and NTSTATUS in parallel.

.DESCRIPTION
Takes one or more integer or hexadecimal codes (for example from logs or APIs) and returns a DataTable row per input with best-effort text for each interpretation, plus derived cross-conversions where applicable:
- Raw value as a Win32 system error (FormatMessage from system).
- Raw value as an HRESULT (Marshal.GetExceptionForHR message when available).
- Raw value as an NTSTATUS (FormatMessage from ntdll).
- DerivedFromWin32_HResult: HRESULT_FROM_WIN32(low 16 bits of the input).
- DerivedFromWin32_NtStatus: NTSTATUS candidates for the Win32 low 16 bits (ntdll RtlDosErrorToNtStatus when exported, plus gist-based ntdll table reconstruction filtered with RtlNtStatusToDosError).
- DerivedFromNtStatus_Win32: RtlNtStatusToDosError when the input is treated as an NTSTATUS.

Messages depend on installed language packs; unknown codes return a short placeholder instead of failing.

.PARAMETER Code
One or more 32-bit values: integers, unsigned integers, or strings such as 0xC0000005 or -2147024891.

.INPUTS
System.Object
You can pipe integers or numeric strings.

.OUTPUTS
System.Data.DataTable

.EXAMPLE
Get-WindowsErrorInfo -Code 5

.EXAMPLE
Get-WindowsErrorInfo -Code 0x80070005, 0xC0000005

.EXAMPLE
0xC0000005 | Get-WindowsErrorInfo

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Value')]
        [object[]]$Code
    )

    begin {
        $codeList = [System.Collections.Generic.List[object]]::new()
    }
    process {
        if ($null -eq $Code) {
            return
        }
        foreach ($c in $Code) {
            if ($null -ne $c) {
                [void]$codeList.Add($c)
            }
        }
    }
    end {
        if ($codeList.Count -eq 0) {
            throw 'No values were supplied to Get-WindowsErrorInfo.'
        }

        $Table = New-Object System.Data.DataTable 'WindowsErrorInfo'
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn InputCode, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn InputCodeHex, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn Win32Interpretation, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn Win32Description, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn HResultInterpretation, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn HResultDescription, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn NtStatusInterpretation, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn NtStatusDescription, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn DerivedFromWin32_HResult, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn DerivedFromWin32_NtStatus, ([string])))
        [void]$Table.Columns.Add($(New-Object System.Data.DataColumn DerivedFromNtStatus_Win32, ([string])))

        foreach ($raw in $codeList) {
            $u = $null
            if ($raw -is [uint32]) {
                $u = $raw
            }
            elseif ($raw -is [uint64]) {
                $u = [Therena.WindowsDevelopmentShellTools.WindowsErrorInteropWds4]::Low32BitsFromUnsignedValue([uint64]$raw)
            }
            elseif ($raw -is [uint16]) {
                $u = [uint32]$raw
            }
            elseif ($raw -is [byte]) {
                $u = [uint32]$raw
            }
            elseif ($raw -is [int] -or $raw -is [int32] -or $raw -is [long] -or $raw -is [int64] -or
                $raw -is [int16] -or $raw -is [short] -or $raw -is [sbyte]) {
                $u = [Therena.WindowsDevelopmentShellTools.WindowsErrorInteropWds4]::Low32BitsFromSignedValue([int64]$raw)
            }
            elseif ($raw -is [string]) {
                $s = $raw.Trim()
                if ([string]::IsNullOrWhiteSpace($s)) {
                    throw "Get-WindowsErrorInfo: empty string is not a valid code."
                }
                $parsed = $null
                $parsed64 = $null
                if ($s.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
                    if (-not [uint32]::TryParse($s.Substring(2), [System.Globalization.NumberStyles]::AllowHexSpecifier, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
                        throw "Get-WindowsErrorInfo: could not parse hex string '$s'."
                    }
                    $u = $parsed
                }
                else {
                    if (-not [int64]::TryParse($s, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed64)) {
                        throw "Get-WindowsErrorInfo: could not parse string '$s'."
                    }
                    $u = [Therena.WindowsDevelopmentShellTools.WindowsErrorInteropWds4]::Low32BitsFromSignedValue($parsed64)
                }
            }
            else {
                throw "Get-WindowsErrorInfo: unsupported type '$($raw.GetType().FullName)'. Use integer or string."
            }

            $interop = [Therena.WindowsDevelopmentShellTools.WindowsErrorInteropWds4]
            $i = $interop::AsSignedInt32([uint32]$u)
            $low16 = $interop::Low16OfUInt32($u)

            $win32Desc = $interop::TryFormatWin32($u)
            if ([string]::IsNullOrWhiteSpace($win32Desc)) {
                $win32Desc = $interop::TryFormatWin32($low16)
            }
            if ([string]::IsNullOrWhiteSpace($win32Desc)) {
                $win32Desc = '(no Win32 system message for this value)'
            }

            $hrDesc = $interop::TryGetHResultMessage($i)
            if ([string]::IsNullOrWhiteSpace($hrDesc)) {
                $hrSys = $interop::TryFormatWin32($u)
                if (-not [string]::IsNullOrWhiteSpace($hrSys)) {
                    $hrDesc = $hrSys
                }
                else {
                    $hrDesc = '(no HRESULT message for this value)'
                }
            }

            $ntDesc = $interop::TryFormatNtStatus($u)
            if ([string]::IsNullOrWhiteSpace($ntDesc)) {
                $ntDesc = '(no NTSTATUS message in ntdll for this value)'
            }

            $hrFromWin32 = $interop::HRESULT_FROM_WIN32($low16)
            $win32FromNt = $interop::RtlNtStatusToDosErrorUInt($i)
            $hrFromWin32Signed = $interop::AsSignedInt32([uint32]$hrFromWin32)
            $derivedNtFromWin32Text = $interop::FormatDosErrorToNtStatusBestEffort($low16)

            $Row = $Table.NewRow()
            $Row.InputCode = $u.ToString([System.Globalization.CultureInfo]::InvariantCulture)
            $Row.InputCodeHex = ('0x{0:X8}' -f $u)
            $Row.Win32Interpretation = ('Win32 {0} ({1})' -f $u, ('0x{0:X8}' -f $u))
            $Row.Win32Description = $win32Desc
            $Row.HResultInterpretation = ('HRESULT 0x{0:X8} (signed: {1})' -f $u, $i)
            $Row.HResultDescription = $hrDesc
            $Row.NtStatusInterpretation = ('NTSTATUS 0x{0:X8} (signed: {1})' -f $u, $i)
            $Row.NtStatusDescription = $ntDesc
            $Row.DerivedFromWin32_HResult = ('0x{0:X8} ({1})' -f $hrFromWin32, $hrFromWin32Signed)
            $Row.DerivedFromWin32_NtStatus = $derivedNtFromWin32Text
            $Row.DerivedFromNtStatus_Win32 = ('{0} (0x{1:X8})' -f $win32FromNt, $win32FromNt)
            [void]$Table.Rows.Add($Row)
        }

        return ,$Table
    }
}
