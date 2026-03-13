# Seatbelt

**Tags:** `#seatbelt` `#enumeration` `#windows` `#postexploit` `#privesc`

C# Windows host enumeration tool from GhostPack. Collects a comprehensive snapshot of the host's security posture — credentials, tokens, installed software, antivirus, browser data, scheduled tasks, and more. Broader than PowerUp — focuses on situational awareness rather than just privesc.

**Source:** https://github.com/GhostPack/Seatbelt
**Install:** Compile from source or use a precompiled binary. No pre-install on Kali.

```cmd
Seatbelt.exe -group=all
```

> [!note]
> Must be compiled before use (Visual Studio or msbuild). Run `-group=all` for full sweep. Use `execute-assembly` in Cobalt Strike or Evil-WinRM to run in memory. Outputs color-coded sections — yellow = noteworthy.

---

## Compilation

```bash
# Clone and compile on Windows (Visual Studio / msbuild)
git clone https://github.com/GhostPack/Seatbelt.git
# Open Seatbelt.sln in Visual Studio → Build → Release → Seatbelt.exe

# Alternatively use a pre-built binary from trusted repo
```

---

## Execution

```cmd
# Full sweep — all checks
Seatbelt.exe -group=all

# System checks only
Seatbelt.exe -group=system

# User checks only
Seatbelt.exe -group=user

# Specific check
Seatbelt.exe TokenPrivileges
Seatbelt.exe CredGuard
Seatbelt.exe WindowsCredentialFiles

# Run as another user
Seatbelt.exe -group=all -username=DOMAIN\user -password=pass

# Output to file
Seatbelt.exe -group=all > seatbelt_output.txt
```

---

## Check Groups

| Group | Focus |
|-------|-------|
| `system` | OS info, AV, patches, firewall, UAC, LSA protection |
| `user` | User info, tokens, credentials, browser data |
| `misc` | Scheduled tasks, services, autoruns |
| `remote` | Remote access config, WinRM, RDP |
| `chrome` | Chrome browser creds, history, cookies |
| `slack` | Slack config/tokens |
| `all` | Everything |

---

## Key Individual Checks

```cmd
# Credential-related
Seatbelt.exe WindowsCredentialFiles   # Windows Credential Manager
Seatbelt.exe CredGuard                # Credential Guard status
Seatbelt.exe TokenPrivileges          # current token privileges
Seatbelt.exe LogonSessions            # active logon sessions + cached creds

# Privesc relevant
Seatbelt.exe UACSystemPolicies        # UAC config
Seatbelt.exe PowerShellHistory        # PS command history
Seatbelt.exe ProcessCreationEvents    # recent process creation (4688 events)
Seatbelt.exe ScheduledTasks           # scheduled tasks + paths

# Defense evasion intel
Seatbelt.exe AntiVirus                # AV products installed
Seatbelt.exe WindowsDefender          # Defender exclusions/settings
Seatbelt.exe FirewallRules            # firewall rules
Seatbelt.exe LSASettings              # LSA protection, credential guard

# Network / lateral movement
Seatbelt.exe NetworkConnections       # current connections
Seatbelt.exe NetworkShares            # shares
Seatbelt.exe ARPTable                 # ARP cache
```

---

## In-Memory Execution

```powershell
# Via Evil-WinRM
*Evil-WinRM* PS> Invoke-Binary /local/path/Seatbelt.exe -group=all

# Via Cobalt Strike
beacon> execute-assembly /path/to/Seatbelt.exe -group=all

# Via PowerShell reflection (if you have the .NET assembly)
$bytes = [System.IO.File]::ReadAllBytes("C:\Temp\Seatbelt.exe")
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, @([string[]]@("-group=all")))
```

---

## OPSEC

- Binary on disk — rename and timestamp-match to blend in
- In-memory execution via `execute-assembly` preferred
- Known Seatbelt output patterns may trigger EDR behavioral rules
- Avoid running `-group=all` on highly monitored hosts — run targeted checks instead

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
