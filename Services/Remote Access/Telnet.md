# Telnet

#Telnet #remoteaccess #cleartext #legacy

## What is Telnet?
Legacy network protocol for bidirectional text communication. Predecessor to SSH. No encryption — all data (including credentials) transmitted in plaintext. Still found on network devices (routers, switches, IoT), embedded systems, and old servers.

- Port: **TCP 23** (default)
- Alternate ports: 2323, 8023, etc. (sometimes on non-standard ports)
- No encryption — vulnerable to sniffing

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | `telnet-ntlm-info`, `banner`, `telnet-brute` NSE |
| [[Tools/Remote Access/Netcat\|Netcat]] | Banner grab / raw session on 23 |
| [[Tools/Auth/Hydra\|Hydra]] | Credential brute (`telnet://`) |
| [[Tools/Auth/Medusa\|Medusa]] | Credential brute (`-M telnet`) |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `telnet_version` / `telnet_login` scanners |
| [[Tools/Network/tcpdump\|tcpdump]] | Capture cleartext credentials on 23 |
| [[Tools/Network/PCredz\|PCredz]] | Auto-extract telnet creds from a live capture / pcap |

---

## Enumeration

```bash
# Nmap
nmap -p 23 --script telnet-ntlm-info,banner -sV <target>
nmap -p 23 --script telnet-brute --script-args userdb=users.txt,passdb=passwords.txt <target>

# Banner grab
nc -nv <target> 23
telnet <target>

# Check for alternate telnet ports
nmap -p 2323,8023 -sV <target>

# Metasploit
use auxiliary/scanner/telnet/telnet_version
use auxiliary/scanner/telnet/telnet_login
```

---

## Connect / Access

```bash
# Connect
telnet <target>
telnet <target> 23
telnet <target> 2323   # alternate port

# If telnet not installed
nc -nv <target> 23

# From Windows
telnet <target>        # requires Telnet Client feature enabled
```

---

## Attack Vectors

### Banner Grabbing / Fingerprinting

```bash
# Grab banner to identify device/OS/version
nc -nv <target> 23
telnet <target>

# Nmap script
nmap -p 23 --script banner -sV <target>
nmap -p 23 --script telnet-ntlm-info <target>
```

### Credential Brute Force

```bash
hydra -L users.txt -P passwords.txt telnet://<target>
hydra -l admin -P passwords.txt telnet://<target>

# Medusa
medusa -h <target> -U users.txt -P passwords.txt -M telnet

# Nmap
nmap -p 23 --script telnet-brute --script-args userdb=users.txt,passdb=passwords.txt <target>

# Metasploit
use auxiliary/scanner/telnet/telnet_login
set RHOSTS <target>
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

### Credential Sniffing (No Encryption)

```bash
# Telnet is cleartext — capture with tcpdump/Wireshark
sudo tcpdump -i eth0 -nn port 23 -A
sudo tcpdump -i tun0 port 23 -w telnet_capture.pcap

# Extract from pcap in Wireshark:
# Follow TCP Stream → see full session including credentials
```

### Default Credentials (Network Devices)

```
# Common telnet default creds for network devices:
Cisco:     admin/cisco, cisco/cisco, enable/<blank>
Juniper:   root/<blank>
Netgear:   admin/password
D-Link:    admin/<blank>
Linksys:   admin/admin
MikroTik:  admin/<blank>
```

> Telnet on a router/switch/IoT device is a network-gear engagement — pair this with [[Techniques/Network Device Pentesting|Network Device Pentesting]] (config looting, Type-7/5 credential cracking) once you have the CLI.

---

## Detection & Artefacts

- **Everything is plaintext on 23** — the login and the whole session are recoverable from a single on-path capture; `PCredz` pulls the credentials automatically. This is also the strongest detection signal: any TCP/23 traffic on a modern network is an IOC, and the auth is trivially sniffed.
- **Brute force** = a burst of connection/disconnect cycles to 23 from one source; device-side syslog shows repeated failed logins (if the device logs at all — many embedded devices don't).
- **`telnet-ntlm-info`** against a Windows Telnet Server leaks the hostname/domain/NetBIOS name pre-auth — an info-disclosure finding on its own.
- **The finding is that it exists** — recommend disabling Telnet and moving to SSH; on network gear, `transport input ssh` (Cisco) removes the Telnet VTY.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Telnet enabled on internet-facing device | Credential exposure, brute force |
| Default credentials | Immediate access |
| No IP-based access control | Open brute force |
| No session timeout | Hijacking open sessions |
| Unencrypted channel | Full session sniffing |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect | `telnet host` or `nc -nv host 23` |
| Banner grab | `nc -nv host 23` |
| Brute force | `hydra -L users.txt -P pass.txt telnet://host` |
| Sniff session | `tcpdump -i eth0 port 23 -A` |
| Nmap | `nmap -p 23 --script banner,telnet-brute host` |

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
