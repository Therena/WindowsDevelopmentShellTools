#
# Windows-Development-Shell-Tools module manifest (see LICENSE in repo root for full license text).
#

@{
    RootModule              = 'Windows-Development-Shell-Tools.psm1'
    ModuleVersion           = '2.0.1.0'
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
        'Get-HlkxDigitalSignature',
        'Expand-Zip',
        'Get-GlobalAssemblyCache',
        'Get-DateTime',
        'Get-WindowsErrorInfo'
    )

    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @()

    FileList = @(
        'Windows-Development-Shell-Tools.psm1',
        'Windows-Development-Shell-Tools.psd1',
        'Module/Public/Connect-KernelDebugger.ps1',
        'Module/Public/Expand-Zip.ps1',
        'Module/Public/Find-Symbols.ps1',
        'Module/Public/Find-WindowsKitFile.ps1',
        'Module/Public/Get-AuthenticodeDetails.ps1',
        'Module/Public/Get-DateTime.ps1',
        'Module/Public/Get-DebuggerPath.ps1',
        'Module/Public/Get-DumpAnalysis.ps1',
        'Module/Public/Get-EicarSignature.ps1',
        'Module/Public/Get-FileDetails.ps1',
        'Module/Public/Get-GlobalAssemblyCache.ps1',
        'Module/Public/Get-HexDump.ps1',
        'Module/Public/Get-HlkxDigitalSignature.ps1',
        'Module/Public/Get-KernelDebuggerPath.ps1',
        'Module/Public/Get-LinesOfCode.ps1',
        'Module/Public/Get-OperatingSystemBitness.ps1',
        'Module/Public/Get-SymbolCheck.ps1',
        'Module/Public/Get-WindowsErrorInfo.ps1',
        'Module/Public/Open-DumpAnalysis.ps1',
        'Module/Private/00-Initialize-Types.ps1',
        'Module/Private/Get-AuthenticodeSignerInfosForFile.ps1',
        'Module/Private/Get-NestedAuthenticodeDetails.ps1',
        'Module/Private/Invoke-KernelDebuggerDumpAnalysis.ps1',
        'Module/Private/Invoke-SymChkArguments.ps1',
        'Module/Private/Invoke-WinDbgKernelRemotePipe.ps1',
        'Module/Private/Invoke-ZipExpansion.ps1',
        'Module/Private/Select-WindowsKitFileForOs.ps1'
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
