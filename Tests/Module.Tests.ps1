. (Join-Path $PSScriptRoot 'TestSetup.ps1')

Describe 'Windows-Development-Shell-Tools manifest' {
    It 'passes Test-ModuleManifest' {
        { Test-ModuleManifest $script:ModuleManifest -ErrorAction Stop } | Should -Not -Throw
    }
}


Describe 'Exported commands' {
    It 'exports every function listed in FunctionsToExport' {
        $data = Import-PowerShellDataFile $script:ModuleManifest
        $exported = @((Get-Module Windows-Development-Shell-Tools).ExportedFunctions.Keys)
        foreach ($name in $data.FunctionsToExport) {
            $exported | Should -Contain $name
        }
    }
}

