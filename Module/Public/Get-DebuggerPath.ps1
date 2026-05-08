function Get-DebuggerPath {
<#

.SYNOPSIS
Gets paths to WinDbg executables from installed Windows Kits.

.DESCRIPTION
Returns the same table shape as Find-WindowsKitFile for windbg.exe. Requires a Windows SDK or WDK installation.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

.EXAMPLE
Get-DebuggerPath

Path                                                            WDK Bitness
----                                                            --- -------
C:\Program Files (x86)\Windows Kits\10\Debuggers\arm\windbg.exe 10  arm    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe 10  x64    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe 10  x86   

#>
    return Find-WindowsKitFile -File "windbg.exe"
}
