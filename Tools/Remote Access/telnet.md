# telnet

**Tags:** `#telnet` `#remoteaccess` `#enumeration` `#banngrabbing`

Cleartext remote access protocol (TCP 23). Rarely used for actual administration anymore, but still useful during pentests for banner grabbing, manual service interaction, and testing open ports — especially when nc isn't available.

**Source:** Built-in on Linux/Windows
**Install:** `sudo apt install telnet`

```bash
telnet 10.129.14.128 23
```

> [!note]
> Telnet sends everything in cleartext — credentials, commands, all traffic. If you find an open telnet service, capture credentials with Wireshark/tcpdump. For connecting to non-telnet services (HTTP, SMTP, FTP), use `nc` instead — telnet adds IAC negotiation bytes that can corrupt raw protocol interaction.

---

## Basic Usage

```bash
# Connect to telnet service
telnet 10.129.14.128
telnet 10.129.14.128 23

# Connect to other services (banner grabbing)
telnet 10.129.14.128 80
telnet 10.129.14.128 25
telnet 10.129.14.128 21
telnet 10.129.14.128 110
```

---

## Banner Grabbing

```bash
# Web server banner
telnet 10.129.14.128 80
HEAD / HTTP/1.0
[Enter twice]

# SMTP banner + user enum
telnet 10.129.14.128 25
EHLO test
VRFY root
VRFY admin

# FTP banner
telnet 10.129.14.128 21

# POP3
telnet 10.129.14.128 110
USER admin
PASS password
LIST
```

---

## Finding Telnet Services

```bash
# nmap — detect telnet
nmap -sV -p 23 10.129.14.128
nmap -sV -p 23 10.129.14.0/24 --open

# Check for non-standard ports
nmap -sV --version-intensity 5 10.129.14.128
```

---

## Attacking Telnet

```bash
# Brute force
hydra -l root -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt \
  telnet://10.129.14.128

medusa -h 10.129.14.128 -u admin -P rockyou.txt -M telnet

# Credential sniffing (network capture)
sudo tcpdump -i tun0 host 10.129.14.128 and port 23 -A
sudo wireshark   # filter: telnet
```

---

## Windows Telnet Client

```cmd
# Enable telnet client (may be disabled by default)
dism /online /Enable-Feature /FeatureName:TelnetClient

# Use
telnet 10.129.14.128
telnet 10.129.14.128 80
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
