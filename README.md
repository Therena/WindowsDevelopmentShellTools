# Windows Development Shell Tools

> *PowerShell cmdlets that put common Windows debugging, signing, and kit workflows one pipeline away.*

**Windows Development Shell Tools** is a PowerShell module for day-to-day work on Microsoft Windows: locating Windows SDK / WDK tools, inspecting dumps and binaries, counting lines of code, reading Authenticode chains, and more. Commands are documented with comment-based help and typically return **`System.Data.DataTable`** objects so results stay structured and easy to filter.

| | |
|:---|:---|
| **Module name** | `Windows-Development-Shell-Tools` |
| **Current version** | See `ModuleVersion` in [`Module/Windows-Development-Shell-Tools.psd1`](Module/Windows-Development-Shell-Tools.psd1) |
| **PowerShell** | Windows PowerShell **5.1** and **PowerShell 7+** (`pwsh`) on Windows |
| **License** | [Apache 2.0](https://github.com/Therena/WindowsDevelopmentShellTools/blob/master/LICENSE) |

---

## Requirements

- **OS:** Windows (cmdlets rely on Windows APIs, registry, and typical developer tool layouts).
- **PowerShell:** 5.1 or later ([`#Requires -Version 5.1`](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_requires) is used in repo scripts).
- **Optional:** Windows SDK and/or WDK installed for commands that resolve kit binaries (WinDbg, `symchk`, kernel debugger paths, etc.).

---

## Installation

### Recommended: install to your profile (both hosts)

From a clone of this repository, run the installer at the repo root. It copies the [`Module`](Module) folder into the **per-user** module paths for **Windows PowerShell** and **PowerShell 7+** so either `powershell.exe` or `pwsh.exe` can load the same version.

```powershell
cd C:\path\to\WindowsDevelopmentShellTools
.\Install-DevelopmentShellTools.ps1
```

| Switch | Purpose |
|:-------|:--------|
| `-Force` | Replace an existing install of the **same** manifest version. |
| `-SkipWindowsPowerShell` | Only install under `Documents\PowerShell\Modules` (pwsh). |
| `-SkipPowerShellCore` | Only install under `Documents\WindowsPowerShell\Modules` (5.1). |
| `-WhatIf` | Show what would be copied without changing disk. |

Then start a new session and import:

```powershell
Import-Module Windows-Development-Shell-Tools
```

### Manual import (no install)

If you prefer to run straight from a clone:

```powershell
Import-Module 'C:\path\to\WindowsDevelopmentShellTools\Module\Windows-Development-Shell-Tools.psd1'
```

Validate the manifest anytime:

```powershell
Test-ModuleManifest .\Module\Windows-Development-Shell-Tools.psd1
```

Background reading: [Installing a PowerShell module](https://learn.microsoft.com/powershell/scripting/developer/module/installing-a-powershell-module).

---

## Commands at a glance

Full syntax, parameters, and examples live in the module—use **`Get-Help`** after import (see below).

| Command | What it does |
|:--------|:---------------|
| `Get-OperatingSystemBitness` | Reports whether the OS is treated as 64-bit or 32-bit for tool paths. |
| `Get-DebuggerPath` | Resolves WinDbg-related executables from installed Windows kits. |
| `Get-KernelDebuggerPath` | Resolves kernel debugger (`kd`) paths from kits. |
| `Find-WindowsKitFile` | Locates a file under installed kit roots. |
| `Connect-KernelDebugger` | Connects the kernel debugger to a target (e.g. named pipe). |
| `Get-DumpAnalysis` | Runs dump analysis and returns tabular output. |
| `Open-DumpAnalysis` | Opens interactive dump analysis in the debugger. |
| `Get-LinesOfCode` | Counts lines of code across selected files. |
| `Get-EicarSignature` | Returns the **EICAR** test antivirus string (safe test payload). |
| `Get-SymbolCheck` | Resolves `symchk` from installed kits. |
| `Find-Symbols` | Locates symbols (PDBs) for a given path. |
| `Get-FileDetails` | File or directory metadata in tabular form. |
| `Get-AuthenticodeDetails` | Authenticode / PKCS signer and certificate details for a file. |
| `Get-HexDump` | Hexadecimal view of file content. |
| `Get-GlobalAssemblyCache` | Reads GAC-related Fusion registry entries into a table. |
| `Get-DateTime` | Current time in several common formats (Unix, ISO, file time, etc.). |

---

## Documentation in the shell

After the module is loaded:

```powershell
Get-Help Get-DateTime
Get-Help Get-DumpAnalysis -Detailed
Get-Help Find-Symbols -Examples
```

Comment-based help in [`Module/Windows-Development-Shell-Tools.psm1`](Module/Windows-Development-Shell-Tools.psm1) is the source of truth for behavior and parameters.

---

## Developing and testing

| Script | Role |
|:-------|:-----|
| [`Run-Tests.ps1`](Run-Tests.ps1) | Runs the Pester suite under `Tests\`. |

**Pester 5** is required:

```powershell
Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0.0 -Force
.\Run-Tests.ps1
```

Tests assume Windows where the module uses OS-specific APIs; CI-style flags are handled inside the test script.

---

## Visual Studio and ConEmu

If you use **Visual Studio**, the [ConEmu Integration](https://github.com/Therena/ConEmuIntegration) project can host a PowerShell session (and thus this module) inside the IDE for a tighter edit–run loop.

---

## Repository

- **Project / issues:** [Therena/WindowsDevelopmentShellTools](https://github.com/Therena/WindowsDevelopmentShellTools) on GitHub.

---

## License

Distributed under the [Apache License 2.0](https://github.com/Therena/WindowsDevelopmentShellTools/blob/master/LICENSE).
