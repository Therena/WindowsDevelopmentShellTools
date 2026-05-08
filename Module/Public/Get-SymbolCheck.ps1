function Get-SymbolCheck {
<#

.SYNOPSIS
Gets paths to symchk.exe from installed Windows Kits.

.DESCRIPTION
Returns the same table shape as Find-WindowsKitFile for symchk.exe. Requires a Windows SDK or WDK installation.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

.EXAMPLE
Get-SymbolCheck    

#>
    return Find-WindowsKitFile -File "symchk.exe"
}
