. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-WindowsErrorInfo' -Skip:(-not $script:IsWindowsOs) {
    It 'returns a DataTable with the documented columns' {
        $table = Get-ModuleDataTableResult -Name 'Get-WindowsErrorInfo' -Parameters @{ Code = @(5) }
        $expected = @(
            'InputCode', 'InputCodeHex', 'Win32Interpretation', 'Win32Description',
            'HResultInterpretation', 'HResultDescription', 'NtStatusInterpretation', 'NtStatusDescription',
            'DerivedFromWin32_HResult', 'DerivedFromWin32_NtStatus', 'DerivedFromNtStatus_Win32'
        )
        foreach ($col in $expected) {
            $table.Columns[$col].ColumnName | Should -Be $col
        }
    }

    It 'maps Win32 5 to HRESULT_FROM_WIN32 0x80070005 in the derived column' {
        $table = Get-ModuleDataTableResult -Name 'Get-WindowsErrorInfo' -Parameters @{ Code = @(5) }
        $table.Rows.Count | Should -Be 1
        $table.Rows[0]['InputCodeHex'] | Should -Be '0x00000005'
        $table.Rows[0]['DerivedFromWin32_HResult'] | Should -Be '0x80070005 (-2147024891)'
    }

    It 'parses hex strings the same as integers' {
        $tInt = Get-ModuleDataTableResult -Name 'Get-WindowsErrorInfo' -Parameters @{ Code = @(5) }
        $tHex = Get-ModuleDataTableResult -Name 'Get-WindowsErrorInfo' -Parameters @{ Code = @('0x5') }
        $tInt.Rows[0]['InputCodeHex'] | Should -Be $tHex.Rows[0]['InputCodeHex']
    }

    It 'returns one row per code and fills deterministic placeholders for unknown values' {
        $table = Get-ModuleDataTableResult -Name 'Get-WindowsErrorInfo' -Parameters @{ Code = @(0x12345678) }
        $table.Rows.Count | Should -Be 1
        $table.Rows[0]['Win32Description'] | Should -Not -BeNullOrEmpty
        $table.Rows[0]['HResultDescription'] | Should -Not -BeNullOrEmpty
        $table.Rows[0]['NtStatusDescription'] | Should -Not -BeNullOrEmpty
        $table.Rows[0]['DerivedFromWin32_HResult'] | Should -Match '0x80075678'
    }

    It 'accepts pipeline input for multiple codes' {
        $cmd = Get-Command -Name 'Get-WindowsErrorInfo' -Module Windows-Development-Shell-Tools -ErrorAction Stop
        $table = @(5, 0x80070005) | & $cmd
        ,$table | Should -BeOfType [System.Data.DataTable]
        $table.Rows.Count | Should -Be 2
    }

    It 'lists RtlNtStatusToDosError-validated NTSTATUS candidate(s) for Win32 5' {
        $table = Get-ModuleDataTableResult -Name 'Get-WindowsErrorInfo' -Parameters @{ Code = @(5) }
        $cell = [string]$table.Rows[0]['DerivedFromWin32_NtStatus']
        $cell | Should -Match '0x[0-9A-F]{8} \(-?\d+\)'
        $cell | Should -Not -Match 'no NTSTATUS mapping found'
    }
}


