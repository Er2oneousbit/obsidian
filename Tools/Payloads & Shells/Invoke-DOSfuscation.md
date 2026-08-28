# Invoke-DOSfuscation

**Tags:** #InvokeDOSfuscation #Obfuscation #Evasion #CommandInjection #CMD #Windows #PowerShell #Payloads

`Invoke-DOSfuscation` is Daniel Bohannon's obfuscation framework for Windows **`cmd.exe`** command lines (the CMD counterpart to his `Invoke-Obfuscation` for PowerShell). It rewrites a command using CMD's own parsing quirks — caret escapes, environment-variable substring extraction, `FOR /F` token reassembly, and encoding layers — producing a string that survives keyword blacklists and command-line-based detections. Useful against filters on a Windows [[Class notes/HTB Academy/CPTS v2 (claude)/Command Injection|command injection]] point, and for [[Techniques/AV & EDR Evasion|AV & EDR Evasion]] work where the command line itself is what gets flagged.

**Source:** https://github.com/danielbohannon/Invoke-DOSfuscation
**Install:** `git clone https://github.com/danielbohannon/Invoke-DOSfuscation` — no dependencies beyond PowerShell

```powershell
# Load the module and enter the interactive menu
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation

# Inside the menu:
SET COMMAND whoami
encoding
1                    # pick an encoding type — output is the obfuscated command
```

```powershell
# Non-interactive — obfuscate in one call (useful for scripting payload generation)
Invoke-DOSfuscation -Command "whoami" -Encoding 1
```

> [!note] Targets `cmd.exe` syntax specifically — the output will not run under PowerShell. For PowerShell payloads use `Invoke-Obfuscation` or the UTF-16LE `-EncodedCommand` route instead.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Command Injection|Command Injection]] — Windows CMD payload obfuscation against keyword filters. Linux counterpart is [[Tools/Payloads & Shells/Bashfuscator|Bashfuscator]].

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
