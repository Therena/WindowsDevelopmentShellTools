function Get-DebuggerPath {
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
    PROCESS {
        if ([Environment]::Is64BitProcess -ne [Environment]::Is64BitOperatingSystem) {
            $obj = new-object psobject -Property @{ Type = 'x86' }
        } else {
            $obj = new-object psobject -Property @{ Type = 'x64' }
        }
        $obj | Format-Table
    }
}

function Connect-Debugger {
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
Export-ModuleMember -Function Connect-Debugger