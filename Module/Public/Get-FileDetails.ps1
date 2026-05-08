function Get-FileDetails {
<#

.SYNOPSIS
Reads file version metadata from PE files.

.DESCRIPTION
Enumerates files with Get-ChildItem, then fills a DataTable from System.Diagnostics.FileVersionInfo (version strings, company, description, and related fields).

.PARAMETER File
File or directory to scan.

.PARAMETER Filter
Get-ChildItem -Filter pattern when enumerating under a directory (default *.*).

.PARAMETER Recursive
When set, includes subdirectories when File is a folder.

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools

.EXAMPLE
Get-FileDetails C:\Windows\regedit.exe


File            : C:\Windows\regedit.exe
FileVersion     : 10.0.17134.346 (WinBuild.160101.0800)
ProductVersion  : 10.0.17134.346
FileDescription : Registrierungs-Editor
CompanyName     : Microsoft Corporation
InternalName    : REGEDIT
LegalCopyright  : ï¿½ Microsoft Corporation. Alle Rechte vorbehalten.
ProductName     : Betriebssystem Microsoftï¿½ Windowsï¿½

.EXAMPLE
Get-FileDetails C:\Windows | Format-Table

File                            FileVersion                           ProductVersion FileDescription                                       CompanyName                InternalName   
----                            -----------                           -------------- ---------------                                       -----------                ------------   
C:\Windows\bfsvc.exe            10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Startdatei-Wartungshilfsprogramm                      Microsoft Corporation      bfsvc.exe      
C:\Windows\bootstat.dat                                                                                                                                                              
C:\Windows\comsetup.log                                                                                                                                                              
C:\Windows\diagerr.xml                                                                                                                                                               
C:\Windows\diagwrn.xml                                                                                                                                                               
C:\Windows\DtcInstall.log                                                                                                                                                            
C:\Windows\explorer.exe         10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Windows-Explorer                                      Microsoft Corporation      explorer       
C:\Windows\HelpPane.exe         10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Microsoft-Hilfe und Support                           Microsoft Corporation      HelpPane.exe   
C:\Windows\hh.exe               10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Ausfï¿½hrbare Microsoftï¿½-HTML-Hilfsdatei                Microsoft Corporation      HH 1.41        
C:\Windows\mib.bin                                                                                                                                                                   
C:\Windows\notepad.exe          10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Editor                                                Microsoft Corporation      Notepad        
C:\Windows\PFRO.log                                                                                                                                                                  
C:\Windows\Professional.xml                                                                                                                                                          
C:\Windows\py.exe               3.6.6                                 3.6.6          Python                                                Python Software Foundation Python Launcher
C:\Windows\pyshellext.amd64.dll 3.6.6                                 3.6.6          Python                                                Python Software Foundation Python Launc...
C:\Windows\pyw.exe              3.6.6                                 3.6.6          Python                                                Python Software Foundation Python Launcher
C:\Windows\regedit.exe          10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Registrierungs-Editor                                 Microsoft Corporation      REGEDIT        
C:\Windows\setupact.log                                                                                                                                                              
C:\Windows\setuperr.log                                                                                                                                                              
C:\Windows\splwow64.exe         10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Print driver host for applications                    Microsoft Corporation      splwow64.exe   
C:\Windows\system.ini                                                                                                                                                                
C:\Windows\twain_32.dll         1,7,1,3                               1,7,1,0        Twain_32 Source-Manager (Image Acquisition Interface) Twain Working Group        DSM            
C:\Windows\win.ini                                                                                                                                                                   
C:\Windows\WindowsUpdate.log                                                                                                                                                         
C:\Windows\winhlp32.exe         10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Windows Winhlp32-Stub                                 Microsoft Corporation      WINHSTB        
C:\Windows\WMSysPr9.prx                                                                                                                                                              
C:\Windows\write.exe            10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Windows Write                                         Microsoft Corporation      write  

.EXAMPLE
Get-FileDetails C:\Windows -Filter *.exe | Format-Table

File                    FileVersion                           ProductVersion FileDescription                        CompanyName                InternalName    LegalCopyright        
----                    -----------                           -------------- ---------------                        -----------                ------------    --------------        
C:\Windows\bfsvc.exe    10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Startdatei-Wartungshilfsprogramm       Microsoft Corporation      bfsvc.exe       ï¿½ Microsoft Corpora...
C:\Windows\explorer.exe 10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Windows-Explorer                       Microsoft Corporation      explorer        ï¿½ Microsoft Corpora...
C:\Windows\HelpPane.exe 10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Microsoft-Hilfe und Support            Microsoft Corporation      HelpPane.exe    ï¿½ Microsoft Corpora...
C:\Windows\hh.exe       10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Ausfï¿½hrbare Microsoftï¿½-HTML-Hilfsdatei Microsoft Corporation      HH 1.41         ï¿½ Microsoft Corpora...
C:\Windows\notepad.exe  10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Editor                                 Microsoft Corporation      Notepad         ï¿½ Microsoft Corpora...
C:\Windows\py.exe       3.6.6                                 3.6.6          Python                                 Python Software Foundation Python Launcher Copyright ï¿½ 2001-20...
C:\Windows\pyw.exe      3.6.6                                 3.6.6          Python                                 Python Software Foundation Python Launcher Copyright ï¿½ 2001-20...
C:\Windows\regedit.exe  10.0.17134.346 (WinBuild.160101.0800) 10.0.17134.346 Registrierungs-Editor                  Microsoft Corporation      REGEDIT         ï¿½ Microsoft Corpora...
C:\Windows\splwow64.exe 10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Print driver host for applications     Microsoft Corporation      splwow64.exe    ï¿½ Microsoft Corpora...
C:\Windows\winhlp32.exe 10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Windows Winhlp32-Stub                  Microsoft Corporation      WINHSTB         ï¿½ Microsoft Corpora...
C:\Windows\write.exe    10.0.17134.1 (WinBuild.160101.0800)   10.0.17134.1   Windows Write                          Microsoft Corporation      write           ï¿½ Microsoft Corpora...

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [string]$File,

        [string]$Filter = "*.*",
        
        [switch]$Recursive    
    )
    
    $Table = New-Object System.Data.DataTable "File Details"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn File, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn FileVersion, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn ProductVersion, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn FileDescription, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn CompanyName, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn InternalName, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn LegalCopyright, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn ProductName, ([string])))
     
    if ($Recursive) {
        $FoundFiles = Get-ChildItem -Path $File -File -Filter $Filter -Recurse
    } else {
        $FoundFiles = Get-ChildItem -Path $File -File -Filter $Filter
    }

    foreach($FileEntry in $FoundFiles) {
        $VersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FileEntry.FullName)

        $Row = $Table.NewRow()
    
        $Row.File = $FileEntry.FullName
        $Row.FileVersion = $VersionInfo.FileVersion
        $Row.ProductVersion = $VersionInfo.ProductVersion
        $Row.FileDescription = $VersionInfo.FileDescription
        $Row.CompanyName = $VersionInfo.CompanyName
        $Row.InternalName = $VersionInfo.InternalName
        $Row.LegalCopyright = $VersionInfo.LegalCopyright
        $Row.ProductName = $VersionInfo.ProductName

        [void]$Table.Rows.Add($Row)
    }

    return ,$Table
}
