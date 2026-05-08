function Get-GlobalAssemblyCache {
<#

.SYNOPSIS
Lists GAC-related assembly entries from the Fusion registry view.

.DESCRIPTION
Reads value names under HKLM:\SOFTWARE\Microsoft\Fusion\GACChangeNotification\Default, parses comma-separated assembly identity strings, and returns a DataTable with assembly name, version, and processor architecture when the string has enough fields.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-GlobalAssemblyCache

Assembly                                                                         Version      ProcessorArchitecture
--------                                                                         -------      ---------------------
System.Runtime                                                                   4.0.0.0      MSIL
System.IdentityModel.Selectors                                                   4.0.0.0      MSIL
System.AddIn.Contract                                                            4.0.0.0      MSIL
PresentationFramework-SystemDrawing                                              4.0.0.0      MSIL
System.Runtime.Extensions                                                        4.0.0.0      MSIL
System.Linq                                                                      4.0.0.0      MSIL

#>
    [CmdletBinding()]
    param ()
    
    $Table = New-Object System.Data.DataTable "Global Assembly Cache"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Assembly, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Version, ([System.Version])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn ProcessorArchitecture, ([string])))

    $GlobalAssemblyCache = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Fusion\GACChangeNotification\Default"
    $GlobalAssemblyCache = $GlobalAssemblyCache.PSObject.Properties.Name;

    foreach($AssemblyDescription in $GlobalAssemblyCache) {
        $Row = $Table.NewRow()

        $AssemblyDescriptionParts = $AssemblyDescription.Split(',');
    
        if($AssemblyDescriptionParts.Length -gt 4) {
        
            $Row.Assembly = $AssemblyDescriptionParts[0]
            $Row.Version = [System.Version]$AssemblyDescriptionParts[1]
            $Row.ProcessorArchitecture = $AssemblyDescriptionParts[4].ToUpper()

            [void]$Table.Rows.Add($Row)
        }
    }

    return ,$Table
}
