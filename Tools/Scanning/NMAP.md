# nmap

**Tags:** `#nmap` `#scanning` `#enumeration` `#portscan` `#nse`

Industry-standard port scanner. Discovers open ports, service versions, OS fingerprints, and runs NSE scripts for deeper enumeration. Essential first step on every target.

**Source:** https://nmap.org
**Install:** Pre-installed on Kali

```bash
nmap -sV --open -oA initial_scan 10.129.200.170
```

> [!note]
> Run as root for SYN scan (`-sS`) — faster and more reliable than connect scan (`-sT`). Always save output with `-oA` for all three formats (nmap, xml, gnmap). Use `-Pn` when ICMP is blocked.

---

## Standard Scan Workflow

```bash
# 1. Quick top-port scan + version detection
nmap -sV --open -oA initial_scan 10.129.200.170

# 2. Full TCP port scan
nmap -p- --open -oA full_tcp_scan 10.129.200.170

# 3. Script scan on discovered ports
nmap -sC -sV -p 22,80,443 -oA script_scan 10.129.200.170

# 4. UDP scan (top ports — slow)
sudo nmap -sU --top-ports 20 10.129.200.170
```

---

## Host Discovery

```bash
# Ping sweep (no port scan)
sudo nmap -sn 10.129.14.0/24 -oA host_discovery

# Extract live hosts from ping sweep
sudo nmap 10.129.14.0/24 -sn -oA tnet | grep "for" | cut -d" " -f5

# Disable ping (treat host as up)
nmap -Pn 10.129.200.170

# ARP scan (local network)
sudo nmap -PR -sn 10.129.14.0/24
```

---

## Scan Types

| Flag | Scan Type | Notes |
|------|-----------|-------|
| `-sS` | SYN (stealth) | Default with root — fastest |
| `-sT` | TCP connect | No root needed, noisier |
| `-sU` | UDP | Slow — use `--top-ports` |
| `-sA` | ACK | Maps firewall rules |
| `-sV` | Version detection | Probes open ports |
| `-sC` | Default scripts | Runs NSE default category |
| `-O` | OS detection | Needs root |
| `-A` | Aggressive | `-sV -sC -O --traceroute` |

---

## Port Specification

```bash
nmap -p 22,80,443 10.129.200.170        # specific ports
nmap -p 1-1000 10.129.200.170           # port range
nmap -p- 10.129.200.170                 # all 65535 ports
nmap --top-ports 100 10.129.200.170     # top N most common
nmap --open 10.129.200.170              # show only open ports
```

---

## NSE Scripts

```bash
# Run default scripts
nmap -sC 10.129.200.170

# Specific script
nmap --script smb-vuln-ms17-010 10.129.200.170

# Multiple scripts
nmap --script smb-enum-shares,smb-enum-users 10.129.200.170

# Script category
nmap --script vuln 10.129.200.170
nmap --script discovery 10.129.200.170
nmap --script auth 10.129.200.170

# Script with args
nmap --script http-brute --script-args userdb=users.txt,passdb=pass.txt \
  -p 80 10.129.200.170

# Update script DB
sudo nmap --script-updatedb

# Find scripts for a service
ls /usr/share/nmap/scripts/ | grep smb
```

NSE categories: `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`

---

## Timing & Performance

```bash
# Timing templates (T0=paranoid → T5=insane)
nmap -T4 10.129.200.170     # fast, good default
nmap -T1 10.129.200.170     # slow/evasive

# Manual tuning
nmap --min-rate 5000 --max-retries 1 -p- 10.129.200.170  # very fast full scan
nmap --initial-rtt-timeout 50ms --max-rtt-timeout 100ms 10.129.200.170
```

---

## Evasion / Firewall Bypass

```bash
# SYN vs ACK scan (map firewall rules)
sudo nmap -sA -p 80,443 10.129.200.170

# Decoys (mix fake IPs into scan)
sudo nmap -D RND:5 10.129.200.170

# Spoof source IP
sudo nmap -S 10.10.10.1 10.129.200.170

# Source port (bypass port-based filters)
sudo nmap --source-port 53 10.129.200.170

# Fragment packets
sudo nmap -f 10.129.200.170

# Use victim's internal DNS
nmap --dns-server 172.16.5.5 10.129.200.170

# Disable ARP ping + DNS
nmap -Pn -n --disable-arp-ping 10.129.200.170
```

---

## Output Formats

```bash
# All formats simultaneously (recommended)
nmap -oA scan_results 10.129.200.170
# Creates: scan_results.nmap, scan_results.xml, scan_results.gnmap

# Individual formats
nmap -oN output.txt 10.129.200.170      # normal
nmap -oX output.xml 10.129.200.170      # XML
nmap -oG output.gnmap 10.129.200.170    # grepable

# Convert XML to HTML report
xsltproc scan_results.xml -o scan_results.html

# Parse open ports from .nmap file into comma list
cat scan.nmap | awk -F/ '/open/ {b=b","$1} END {print substr(b,2)}'
```

---

## Useful One-Liners

```bash
# Fast full scan with version + scripts on discovered ports
ports=$(nmap -p- --min-rate 5000 -Pn -n 10.129.200.170 | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//') && nmap -sC -sV -p$ports 10.129.200.170 -oA targeted

# Subnet sweep then scan live hosts
sudo nmap -sn 10.129.14.0/24 | grep "for" | cut -d" " -f5 > hosts.txt && nmap -iL hosts.txt -sV --open -oA subnet_scan
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
