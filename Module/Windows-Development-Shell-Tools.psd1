#
# Windows-Development-Shell-Tools module manifest (see LICENSE in repo root for full license text).
#

@{
    RootModule              = 'Windows-Development-Shell-Tools.psm1'
    ModuleVersion           = '1.0.0.0'
    GUID                    = '33c4f980-d38b-4e07-a4b9-c127e4fd61bb'
    Author                  = 'David Roller'
    CompanyName             = 'Therena'
    Copyright               = 'Copyright (c) 2026 David Roller. All rights reserved.'
    Description             = 'PowerShell cmdlets for software development on Microsoft Windows.'
    PowerShellVersion       = '5.0'
    DotNetFrameworkVersion  = '4.5'
    CLRVersion              = '4.0'

    FunctionsToExport = @(
        'Get-OperatingSystemBitness',
        'Get-DebuggerPath',
        'Get-KernelDebuggerPath',
        'Find-WindowsKitFile',
        'Connect-KernelDebugger',
        'Get-DumpAnalysis',
        'Open-DumpAnalysis',
        'Get-LinesOfCode',
        'Get-EicarSignature',
        'Get-SymbolCheck',
        'Find-Symbols',
        'Get-FileDetails',
        'Get-AuthenticodeDetails',
        'Get-HexDump',
        'Get-GlobalAssemblyCache',
        'Get-DateTime'
    )

    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @()

    FileList = @(
        'Windows-Development-Shell-Tools.psm1',
        'Windows-Development-Shell-Tools.psd1'
    )

    PrivateData = @{
        PSData = @{
            Tags = @(
                'powershell',
                'development',
                'development-tools'
            )
            LicenseUri = 'https://github.com/Therena/WindowsDevelopmentShellTools/blob/master/LICENSE'
            ProjectUri = 'https://github.com/Therena'
        }
    }

    HelpInfoURI = 'https://github.com/Therena/WindowsDevelopmentShellTools'
}