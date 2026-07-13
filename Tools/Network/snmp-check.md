# snmp-check

**Tags:** `#snmpcheck` `#snmp` `#snmpattack` `#enumeration`

SNMP enumeration tool that outputs system information in a clean, human-readable format. Parses common OIDs automatically — system info, network interfaces, processes, users, shares, and installed software — without requiring manual OID knowledge.

**Source:** http://www.nothink.org/codes/snmpcheck/index.php
**Install:** `sudo apt install snmp-check`

```bash
snmp-check 10.129.14.128 -c public
```

> [!note]
> Best used after `onesixtyone` identifies a valid community string. Provides cleaner output than raw `snmpwalk` — good for quickly reading system details without OID lookup tables.

---

## Usage

```bash
# Basic enum with community string
snmp-check 10.129.14.128 -c public

# Specify SNMP version (default v1)
snmp-check 10.129.14.128 -c public -v 2c

# Specify port (default 161)
snmp-check 10.129.14.128 -c public -p 161

# Write output to file
snmp-check 10.129.14.128 -c public > snmp-results.txt
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-c <string>` | Community string |
| `-v <1\|2c>` | SNMP version (default: 1) |
| `-p <port>` | UDP port (default: 161) |
| `-t <sec>` | Timeout (default: 5) |
| `-r <retries>` | Retries (default: 1) |
| `-d` | Disable TCP/UDP port listing |
| `-w` | Enable write check (test write access) |

---

## What It Enumerates

- System info: hostname, OS, uptime, contact, location
- Network interfaces and IP addresses
- Routing table
- ARP cache
- Open TCP/UDP ports
- Running processes (name, PID, path)
- Installed software
- User accounts (Windows MIB)
- Network shares (Windows MIB)
- Storage devices / disk usage

---

## SNMP Attack Chain

```bash
# 1. Find community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

# 2. Structured enum with snmp-check
snmp-check 10.129.14.128 -c public -v 2c

# 3. Raw MIB walk for additional data
snmpwalk -v2c -c public 10.129.14.128

# 4. Mass OID sweep (multi-host)
braa public@10.129.14.128:.1.3.6.*
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
