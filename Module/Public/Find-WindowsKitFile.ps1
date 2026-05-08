function Find-WindowsKitFile {
<#

.SYNOPSIS
Gets the full path to a file under installed Windows Kits.

.DESCRIPTION
Searches the default Windows Kits installation directory (for example, under Program Files (x86)) for a file name you specify. Returns a DataTable with Path, WDK version folder, and debugger architecture (Bitness). Install at least one Windows SDK or WDK before using this function.

.PARAMETER File
The file name which has to be located within the Windows Kit installations

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

.EXAMPLE
Find-WindowsKitFile -File windbg.exe

Path                                                            WDK Bitness
----                                                            --- -------
C:\Program Files (x86)\Windows Kits\10\Debuggers\arm\windbg.exe 10  arm    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe 10  x64    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe 10  x86 

.EXAMPLE
Find-WindowsKitFile -File kd.exe  

Path                                                        WDK Bitness
----                                                        --- -------
C:\Program Files (x86)\Windows Kits\10\Debuggers\arm\kd.exe 10  arm    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe 10  x64    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\kd.exe 10  x86    

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [string]$File      
    )
    
    $Table = New-Object System.Data.DataTable "WindowsKit"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Path, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn WDK, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Bitness, ([string])))

    $FoundFiles = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits" -Filter $File -File -Recurse

    foreach($FileEntry in $FoundFiles) {
        $Row = $Table.NewRow()
        
        $Row.Path = $FileEntry.FullName
        $Row.WDK = $FileEntry.Directory.Parent.Parent.Name
        $Row.Bitness = $FileEntry.Directory.Name
        
        [void]$Table.Rows.Add($Row)
    }

    return ,$Table
}
