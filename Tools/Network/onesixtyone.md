# onesixtyone

**Tags:** `#onesixtyone` `#snmp` `#snmpattack` `#enumeration`

Fast SNMP community string brute forcer. Named after UDP port 161 (SNMP). Sends requests to many hosts quickly — the standard first step in SNMP attack chains to identify valid community strings before using snmpwalk/braa.

**Source:** https://github.com/trailofbits/onesixtyone
**Install:** `sudo apt install onesixtyone`

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```

> [!note]
> Step 1 of the SNMP attack chain. Community string = password for SNMPv1/v2c. Once you have a valid string, use `snmpwalk` for structured enumeration or `braa` for mass OID sweeping.

---

## Usage

```bash
# Single host — wordlist attack
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

# Subnet sweep with wordlist
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt -i hosts.txt

# Generate host list for subnet then sweep
seq 1 254 | awk '{print "10.129.14."$1}' > hosts.txt
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt -i hosts.txt

# Specify timeout and delay
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.14.128 -t 150 -w 100
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-c <file>` | Community string wordlist |
| `-i <file>` | Host list file |
| `-t <ms>` | Timeout in ms (default 10) |
| `-w <ms>` | Wait between packets in ms |
| `-d` | Debug output |

---

## Community String Wordlists

```bash
# Built-in SecLists paths
/usr/share/seclists/Discovery/SNMP/snmp.txt
/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt

# Quick manual test — most common defaults
echo -e "public\nprivate\ncommunity\nmanager\nmonitor" > community.txt
onesixtyone -c community.txt 10.129.14.128
```

---

## SNMP Attack Chain

```bash
# 1. Find community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

# 2. Walk the MIB tree with found string
snmpwalk -v2c -c public 10.129.14.128

# 3. Mass OID sweep (faster)
braa public@10.129.14.128:.1.3.6.*

# 4. Targeted deep enum
snmp-check 10.129.14.128 -c public
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
