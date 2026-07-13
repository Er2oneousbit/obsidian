#SNMP #SimpleNetworkManagementProtocol #networkmanagement

## What is SNMP?
Simple Network Management Protocol — monitors and controls network devices (routers, switches, printers, servers). Stores device metadata and configuration in a structured database (MIB).

- Port **UDP 161** — SNMP agent (receive queries/commands)
- Port **UDP 162** — SNMP trap receiver (agent sends events to manager)
- Community strings act as passwords for access control
- Common targets: routers, switches, IoT devices, Windows/Linux servers

---

## SNMP Versions

| Version | Auth | Encryption | Notes |
|---|---|---|---|
| SNMPv1 | Community string | None | Plaintext everything; no auth validation |
| SNMPv2c | Community string | None | Adds 64-bit counters and bulk operations; still plaintext |
| SNMPv3 | Username + password | Yes (AES/DES) | Authentication + encryption via pre-shared key |

---

## Key Concepts

### MIB (Management Information Base)
- ASCII text database containing OIDs and device metadata
- Stored locally on manager; describes what each OID means
- Common MIB files in `/usr/share/snmp/mibs/`

### OID (Object Identifier)
- Hierarchical namespace for SNMP objects
- Dot-separated integers: `1.3.6.1.2.1.1.1.0` = sysDescr
- Each managed object has a unique OID

### Community Strings
- SNMPv1/v2c access control — like a plaintext password
- `public` = read-only (default, often unchanged)
- `private` = read-write (default, often unchanged)
- Passed in cleartext — sniffable

---

## Configuration Files

| File | Description |
|---|---|
| `/etc/snmp/snmpd.conf` | Linux SNMP daemon config |
| `/etc/snmp/snmptrapd.conf` | Trap receiver config |
| `C:\WINDOWS\system32\snmp.dll` | Windows SNMP service |

### Dangerous Settings

| Setting | Risk |
|---|---|
| `rwuser noauth` | Full OID tree access without authentication |
| `rwcommunity public <IP>` | Read-write with default string |
| `rwcommunity6 <string> <IPv6>` | Same, IPv6 |
| `rocommunity public default` | Read access from anywhere with default string |
| SNMPv1/v2c only | No encryption, community strings in cleartext |
| `write` community string exposed | Can modify device configuration |

---

## Enumeration

### snmpwalk

```bash
# Walk entire OID tree (v1, public community)
snmpwalk -v 1 -c public <target>

# Walk with v2c
snmpwalk -v 2c -c public <target>

# Walk specific OID
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.1  # System info

# Walk with MIB translation (readable output)
snmpwalk -v 2c -c public -m ALL <target>

# Common useful OIDs to walk:
# 1.3.6.1.2.1.1       - sysDescr, system info
# 1.3.6.1.2.1.25.1.6  - running processes
# 1.3.6.1.2.1.25.4.2  - installed software
# 1.3.6.1.2.1.25.6    - installed packages
# 1.3.6.1.4.1.77.1.2  - Windows user accounts (Microsoft MIB)
# 1.3.6.1.2.1.6       - TCP connections table
# 1.3.6.1.2.1.4       - IP routing table
```

### onesixtyone (Community String Brute Force)

```bash
# Single target, default wordlist
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <target>

# Multiple targets
onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/snmp.txt -i targets.txt

# Custom community strings file
onesixtyone -c community_strings.txt <target>
```

### braa (Mass SNMP Scanner)

```bash
# Scan single target
braa public@<target>:.1.3.6.*

# Multiple targets
braa public@<target1>:.1.3.6.* public@<target2>:.1.3.6.*

# Get specific OID
braa community@<target>:1.3.6.1.2.1.1.1.0
```

### Nmap

```bash
nmap -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-processes,snmp-netstat -sV <target>
nmap -sU -p 161 --script snmp-brute <target>
nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=/path/to/communities.txt <target>
```

### Metasploit

```bash
use auxiliary/scanner/snmp/snmp_login     # brute force community strings
use auxiliary/scanner/snmp/snmp_enum      # enumerate after auth
use auxiliary/scanner/snmp/snmp_enumusers
use auxiliary/scanner/snmp/snmp_enumshares
```

---

## Attack Vectors

### Enumerate Windows via SNMP

```bash
# Users (if Windows SNMP with Microsoft MIB)
snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.77.1.2.25

# Running processes
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2

# Installed software
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.25.6.3.1.2

# TCP connections
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.6.13.1.3

# Network interfaces
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.2.2.1
```

### Modify Device Config via Read-Write Community

```bash
# Set a value (if rwcommunity is found)
snmpset -v 2c -c private <target> <OID> <type> <value>

# Example: change sysContact
snmpset -v 2c -c private <target> 1.3.6.1.2.1.1.4.0 s "admin@attacker.com"

# Cisco: change routing, enable interfaces, etc. via SNMP write
```

### SNMPv3 Credential Attack

```bash
# If SNMPv3 username known — brute force auth password
use auxiliary/scanner/snmp/snmp_login
# Or snmp-check / nmap with user/pass lists
```

---

## Quick Reference

| Goal | Command |
|---|---|
| Walk OID tree | `snmpwalk -v 2c -c public host` |
| Brute community string | `onesixtyone -c communities.txt host` |
| Mass scan | `braa public@host:.1.3.6.*` |
| Nmap scan | `nmap -sU -p 161 --script snmp-info host` |
| Enum users (Windows) | `snmpwalk -v 2c -c public host 1.3.6.1.4.1.77.1.2.25` |
| Enum processes | `snmpwalk -v 2c -c public host 1.3.6.1.2.1.25.4.2.1.2` |
| MSF community brute | MSF `auxiliary/scanner/snmp/snmp_login` |
