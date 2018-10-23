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
        $windbgList = New-Object System.Collections.ArrayList
        $files = Get-ChildItem -Path 'C:\Program Files (x86)\Windows Kits' -Filter 'windbg.exe' -File -Recurse -ErrorAction SilentlyContinue -Force

        foreach($windbg in $files) {
            $obj = new-object psobject -Property @{ 
                Bitness = $windbg.Directory.Name
                WDK = $windbg.Directory.Parent.Parent.Name
                Path = $windbg.FullName }
            [void] $windbgList.Add($obj)
        }

        $windbgList | Format-Table
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
        [string]$host,

        [parameter(Mandatory=$true)]
        [string]$port        
    )
    PROCESS {
        $windbgFile = Get-DebuggerPath
        Write-Host -n -k com:pipe,port=\\$host\pipe\$port,resets=0,reconnect
        #& $windbgFile -n -k com:pipe,port=\\$host\pipe\$port,resets=0,reconnect
    }
}

Export-ModuleMember -Function Get-OperatingSystemBitness
Export-ModuleMember -Function Get-DebuggerPath
Export-ModuleMember -Function Connect-KernelDebugger