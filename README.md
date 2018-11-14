# Windows-Development-Shell-Tools 

Powershells module with helper function for my daily software development work

## Usage

### Manual import
The module just needs to be imported into PowerShell be e.g. calling the following command
```powershell
Import-Module .\Windows-Development-Shell-Tools .psd1
```

### Installation

1) Create the folder
```powershell
New-Item -ItemType directory -Path $Hom\Documents\WindowsPowerShell\Modules\PowerShellTools\Windows-Development-Shell-Tools 
```
2) Copy or clone the content of the repository to that folder
3) The module will be loaded automatically in powershell

Please also see for more details: 
https://docs.microsoft.com/en-us/powershell/developer/module/installing-a-powershell-module

## Functions

Please also see the detailed description of the functions itself in the code or after importing 
the module by calling Get-Help for the specific function.

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

## License

[Apache 2.0](https://github.com/Therena/Windows-Development-Shell-Tools/blob/master/LICENSE)
