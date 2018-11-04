# PowerShellTools

Powershell module with helper function for my daily software development work

## Usage

The module just needs to be imported into PowerShell be e.g. calling the following command
Import-Module .\TherenaModule.psm1 -Force

## Functions

Please also see the detailed description of the functions itself in the code or after importing 
the module by calling Get-Help for the specific function.

#### Get-OperatingSystemBitness
Get bitness of the installed Windows operating system

#### Get-DebuggerPath
Get the paths to the Windows Debug (WinDBG) executables in the installed Windows kits 

#### Get-KernelDebuggerPath
Get the paths to the Windows Kernel Debug (kd) executables in the installed Windows kits

#### Find-WindowsKitFile
Get the full path to a file in the installed Windows kits

#### Connect-KernelDebugger
Connect the kernel debugger (windbg) to the given host system

#### Get-DumpAnalysis
Runs and prints an analysis of a crash dump file

#### Open-DumpAnalysis
Opens an analysis of a crash dump file

#### Get-LinesOfCode
Count the lines of code in all the selected files

#### Get-EicarSignature
Prints the eicar (European Expert Group for IT-Security) signature

#### Get-SymbolCheck
Get the paths to the symbol check (symchk) executables in the installed Windows kits

#### Find-Symbols
Find the symbols (PDBs) for the given path

#### Get-FileDetails
Obtain the details of the given file(s) or directory

## License

[Apache 2.0](https://github.com/Therena/PowerShellTools/blob/master/LICENSE)
