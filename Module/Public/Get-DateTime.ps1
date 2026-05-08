function Get-DateTime {
<#

.SYNOPSIS
Returns the current date and time in several string formats.

.DESCRIPTION
Outputs a DataTable with four rows: local time, Unix seconds, Windows file time, and ISO 8601 (sortable invariant string). 

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-DateTime

Format    Time
------    ----
Time      13.11.2018 21:02:58
Unix Time 1542142978
File Time 131866129788272588
ISO Date  2018-11-13T21:02:58

#>
    [CmdletBinding()]
    param ()
    
    $Table = New-Object System.Data.DataTable "Time"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Format, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Time, ([string])))

    $Time = [System.DateTime]::Now
    $Time1970 = New-Object System.DateTime 1970, 1, 1

    $Row = $Table.NewRow()
    $Row.Format = "Time"
    $Row.Time = $Time
    [void]$Table.Rows.Add($Row)

    $Row = $Table.NewRow()
    $Row.Format = "Unix Time"
    $Row.Time = [System.Math]::Floor(($Time - $Time1970).TotalSeconds)
    [void]$Table.Rows.Add($Row)
    
    $Row = $Table.NewRow()
    $Row.Format = "File Time"
    $Row.Time = $Time.ToFileTime()
    [void]$Table.Rows.Add($Row)
    
    $Row = $Table.NewRow()
    $Row.Format = "ISO Date"
    $Row.Time = $Time.ToString("s", [System.Globalization.CultureInfo]::InvariantCulture);
    [void]$Table.Rows.Add($Row)

    return ,$Table
}
