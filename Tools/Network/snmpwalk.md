# snmpwalk

**Tags:** `#snmpwalk` `#snmp` `#snmpattack` `#enumeration`

SNMP MIB tree walker — queries a target starting at a given OID and recursively walks through all sub-OIDs, printing raw values. Standard tool for detailed SNMP enumeration after a valid community string is found.

**Source:** Built-in (`net-snmp` package)
**Install:** `sudo apt install snmp snmp-mibs-downloader`

```bash
snmpwalk -v2c -c public 10.129.14.128
```

> [!note]
> Output is raw OID data by default. Install `snmp-mibs-downloader` and add `mibs +ALL` to `/etc/snmp/snmp.conf` to translate OIDs to human-readable names. Use `snmp-check` for pre-parsed output.

---

## Setup (Human-Readable OIDs)

```bash
# Install MIB translations
sudo apt install snmp-mibs-downloader
sudo download-mibs

# Enable all MIBs
echo "mibs +ALL" | sudo tee -a /etc/snmp/snmp.conf
```

---

## Usage

```bash
# Full walk (v2c, community string "public")
snmpwalk -v2c -c public 10.129.14.128

# Walk specific OID subtree
snmpwalk -v2c -c public 10.129.14.128 .1.3.6.1.2.1.1      # system info
snmpwalk -v2c -c public 10.129.14.128 .1.3.6.1.2.1.25.4   # running processes
snmpwalk -v2c -c public 10.129.14.128 .1.3.6.1.2.1.25.6   # installed software
snmpwalk -v2c -c public 10.129.14.128 .1.3.6.1.2.1.6.13   # TCP connections

# SNMP v1
snmpwalk -v1 -c public 10.129.14.128

# SNMPv3 (auth)
snmpwalk -v3 -l authPriv -u snmpuser -a SHA -A password -x AES -X enckey 10.129.14.128

# Get single OID (snmpget)
snmpget -v2c -c public 10.129.14.128 sysDescr.0
```

---

## Useful OIDs

| OID | Description |
|-----|-------------|
| `.1.3.6.1.2.1.1` | System description, hostname, uptime |
| `.1.3.6.1.2.1.25.4.2.1.2` | Running process names |
| `.1.3.6.1.2.1.25.4.2.1.4` | Running process paths |
| `.1.3.6.1.2.1.25.6.3.1.2` | Installed software |
| `.1.3.6.1.2.1.6.13.1.3` | Open TCP ports |
| `.1.3.6.1.2.1.4.34.1.3` | Network interfaces |
| `.1.3.6.1.4.1.77.1.2.25` | Windows user accounts |
| `.1.3.6.1.4.1.77.1.2.3.1.1` | Windows running services |
| `.1.3.6.1.4.1.77.1.2.27` | Windows network shares |

---

## Parse Output

```bash
# Walk and grep for useful strings
snmpwalk -v2c -c public 10.129.14.128 | grep -i "user\|pass\|login\|admin\|cred"

# Save full walk
snmpwalk -v2c -c public 10.129.14.128 > snmpwalk-output.txt

# Extract process list cleanly
snmpwalk -v2c -c public 10.129.14.128 .1.3.6.1.2.1.25.4.2.1.2 | awk -F'"' '{print $2}'
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
