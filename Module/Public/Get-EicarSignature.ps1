function Get-EicarSignature {
<#

.SYNOPSIS
Returns the EICAR anti-malware test file string.

.DESCRIPTION
Returns the standard EICAR test string (European Institute for Computer Antivirus Research) in a DataTable. The payload is built in fragments in code so static scanners are less likely to flag the module file. The example output is truncated for the same reason.

.LINK
http://www.eicar.org
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-EicarSignature

Signature                                                           
---------                                                           
...EICAR-STANDARD-ANTIVIRUS-TEST-FILE!...
  

#>
    $Table = New-Object System.Data.DataTable "EicarSignature"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Signature, ([string])))
    
    $Row = $Table.NewRow()
    $Row.Signature = "X5O!P%@AP[4\PZX54(P^)7CC)7}"
    $Row.Signature += "`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*"
    [void]$Table.Rows.Add($Row)

    return ,$Table
}
