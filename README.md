# Windows Development Shell Tools

For fast and effective development of software for the Microsoft Windows operating system a bunch of tools are quite helpful.
Having them accessable from the Powershell gives the advantage to make them very easy to use and avalible for everywhere in Windows.

In case the development is done using Microsoft Visual Studio there is a plugin to include ConEmu which allows you to use the 
Powershell and therefor also this module directly in your IDE.
For details please see the readme of the project: https://github.com/Therena/ConEmuIntegration 


## Commandlets included in the module

Please also see the detailed description of the commandlets itself in the code or after importing 
the module by calling Get-Help for the specific commandlet.

| Function  | Description  |
|-----------|--------------|
| Get-OperatingSystemBitness | Get bitness of the installed Windows operating system |
| Get-DebuggerPath | Get the paths to the Windows Debug (WinDBG) executables in the installed Windows kits |
| Get-KernelDebuggerPath | Get the paths to the Windows Kernel Debug (kd) executables in the installed Windows kits |
| Find-WindowsKitFile | Get the full path to a file in the installed Windows kits |
| Connect-KernelDebugger | Connect the kernel debugger (windbg) to the given host system |
| Get-DumpAnalysis | Runs and prints an analysis of a crash dump file |
| Open-DumpAnalysis | Opens an analysis of a crash dump file |
| Get-LinesOfCode | Count the lines of code in all the selected files |
| Get-EicarSignature | Prints the eicar (European Expert Group for IT-Security) signature |
| Get-SymbolCheck | Get the paths to the symbol check (symchk) executables in the installed Windows kits |
| Find-Symbols | Find the symbols (PDBs) for the given path |
| Get-FileDetails | Obtain the details of the given file(s) or directory |
| Get-AuthenticodeDetails | Read the certificates from the given file |
| Get-HexDump | Get the content of the file in hexadecimal format |
| Get-GlobalAssemblyCache | Read the entries of the global assembly cache from the registry |
| Get-DateTime | Get the date and time in different formats |

## Usage of the powershell module

### Manual import

The module just needs to be imported into PowerShell be e.g. calling the following command

```powershell
Import-Module .\Windows-Development-Shell-Tools .psd1
```

### Installation

1) Create the folder

```powershell
New-Item -ItemType directory -Path $Home\Documents\WindowsPowerShell\Modules\Windows-Development-Shell-Tools 
```

2) Copy or clone the content of the repository to that folder

```powershell
cd $Home\Documents\WindowsPowerShell\Modules\Windows-Development-Shell-Tools
git clone https://github.com/Therena/WindowsDevelopmentShellTools.git
```

3) The module will be loaded automatically in powershell

Please also see for more details:
[Microsoft Docs - Installing a PowerShell Module](https://docs.microsoft.com/en-us/powershell/developer/module/installing-a-powershell-module)

### Calling commandlets and explore help

After the module is imported or installed into the powershell all the commandlets from the module are available.
For example the "Get-DateTime" commandlet:
```powershell
PS C:\>Get-DateTime

    Format    Time
    ------    ----
    Time      13.11.2018 21:02:58
    Unix Time 1542142978
    File Time 131866129788272588
    ISO Date  2018-11-13T21:02:58
```

In case you want to have some more details about a commandlet, there is a detailed help included for each single commandlet.
To get this help displayed please use the "Get-Help" commandlet:
```powershell
Get-Help Get-DateTime
```

The "Detailed" flag causes that the examples are shown as well:
```powershell
Get-Help Get-DateTime -Detailed
```

## License

[Apache 2.0](https://github.com/Therena/WindowsDevelopmentShellTools/blob/master/LICENSE)
