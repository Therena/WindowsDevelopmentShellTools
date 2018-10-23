<#

.SYNOPSIS

Powershell module with helper function for my daily software development

.DESCRIPTION

All the tooling which is needed for my daily software develpment work.
There is everything from debugging, dump analysis to coding etc.

.LINK

https://github.com/Therena/PowerShellTools

.LICENSE

Copyright 2018 David Roller 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

#>

function Find-WindowsKitFile {
<#

.SYNOPSIS
Get the full path to a file in the installed Windows kits 

.DESCRIPTION
This function searches for the files in the installed windows kit (SDK, WDK).
Please install at least one Windows kit (SDK, WDK) version before using this function.

.LINK

https://github.com/Therena/PowerShellTools
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
        [parameter(Mandatory=$true)]
        [string]$File      
    )
    PROCESS {
        $FileEntryList = New-Object System.Collections.ArrayList
        $FoundFiles = Get-ChildItem -Path 'C:\Program Files (x86)\Windows Kits' -Filter $File -File -Recurse

        foreach($FileEntry in $FoundFiles) {
            $obj = new-object psobject -Property @{ 
                Bitness = $FileEntry.Directory.Name
                WDK = $FileEntry.Directory.Parent.Parent.Name
                Path = $FileEntry.FullName }
            [void] $fileEntryList.Add($obj)
        }

        $FileEntryList | Format-Table
    }
}

function Get-DebuggerPath {
<#

.SYNOPSIS
Get the paths to the Windows Debug (WinDBG) executables in the installed Windows kits 

.DESCRIPTION
This function searches for the Windows Debug executable files in the installed windows kit (SDK, WDK).
Please install at least one Windows kit (SDK, WDK) version before using this function.

.LINK

https://github.com/Therena/PowerShellTools
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
    PROCESS {
        Find-WindowsKitFile -File 'windbg.exe'
    }
}

function Get-KernelDebuggerPath {
<#

.SYNOPSIS
Get the paths to the Windows Kernel Debug (kd) executables in the installed Windows kits 

.DESCRIPTION
This function searches for the Windows Kernel Debug executable files in the installed windows kit (SDK, WDK).
Please install at least one Windows kit (SDK, WDK) version before using this function.

.LINK

https://github.com/Therena/PowerShellTools
https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk
https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

.EXAMPLE
Get-KernelDebuggerPath

Path                                                        WDK Bitness
----                                                        --- -------
C:\Program Files (x86)\Windows Kits\10\Debuggers\arm\kd.exe 10  arm    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe 10  x64    
C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\kd.exe 10  x86     

#>
    PROCESS {
        Find-WindowsKitFile -File 'kd.exe'
    }
}

function Get-OperatingSystemBitness {
<#

.SYNOPSIS
Get bitness of the installed Windows operating system

.DESCRIPTION
This function optains the bitness of the current installed Microsoft Windows operating system

.LINK

https://github.com/Therena/PowerShellTools

.EXAMPLE
Get-OperatingSystemBitness

Type
----
x64  

#>
    PROCESS {
        if ([Environment]::Is64BitProcess -ne [Environment]::Is64BitOperatingSystem) {
            $obj = new-object psobject -Property @{ Type = 'x86' }
        } else {
            $obj = new-object psobject -Property @{ Type = 'x64' }
        }
        $obj | Format-Table
    }
}

function Connect-KernelDebugger {
<#

.SYNOPSIS


.DESCRIPTION


.LINK

https://github.com/Therena/PowerShellTools

.EXAMPLE
Connect-KernelDebugger

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$Host,

        [parameter(Mandatory=$true)]
        [string]$Port        
    )
    PROCESS {
        $WindbgFile = Get-DebuggerPath
        Write-Host -n -k com:pipe,port=\\$Host\pipe\$Port,resets=0,reconnect
        #& $windbgFile -n -k com:pipe,port=\\$host\pipe\$port,resets=0,reconnect
    }
}

#
# Export the members of the module
#
Export-ModuleMember -Function Get-OperatingSystemBitness
Export-ModuleMember -Function Get-DebuggerPath
Export-ModuleMember -Function Get-KernelDebuggerPath
Export-ModuleMember -Function Find-WindowsKitFile
Export-ModuleMember -Function Connect-KernelDebugger