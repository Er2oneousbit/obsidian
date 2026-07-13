# Proxychains

**Tags:** `#proxychains` `#proxy` `#pivoting` `#socks5` `#tunnel`

Forces TCP connections from any application through a proxy chain (SOCKS4/SOCKS5/HTTP). Used to route tool traffic through pivot hosts — pair with Chisel, SSH SOCKS, Metasploit routes, or ligolo-ng SOCKS listeners.

**Source:** https://github.com/haad/proxychains
**Install:** Pre-installed on Kali (`proxychains4`)

```bash
proxychains nmap -sT -Pn -p 445,3389 172.16.5.10
```

> [!note]
> Only works with TCP — UDP and ICMP are not proxied. This means `-sS` (SYN scan) won't work through proxychains; use `-sT` (connect scan) with nmap. Prepend `proxychains` to any command.

---

## Configuration

```bash
# Config file
/etc/proxychains4.conf
~/.proxychains/proxychains.conf     # user-level override

# Key settings
cat /etc/proxychains4.conf
```

**Minimal config:**
```ini
# /etc/proxychains4.conf

# Chain type (pick one)
dynamic_chain       # skip dead proxies — recommended
#strict_chain       # all proxies must work
#random_chain       # random order

proxy_dns           # proxy DNS lookups too

[ProxyList]
socks5  127.0.0.1  1080    # Chisel / SSH SOCKS
# socks4  127.0.0.1  1080
# http    127.0.0.1  8080
```

---

## Common Proxy Sources

| Tool | Setup | Default Port |
|------|-------|-------------|
| Chisel | `chisel server --reverse --socks5` | 1080 |
| SSH SOCKS | `ssh -D 1080 user@pivot` | 1080 |
| Metasploit | `use auxiliary/server/socks_proxy` | 1080 |
| ligolo-ng | Not needed — uses TUN routing | — |

---

## Usage

```bash
# Prefix any command
proxychains nmap -sT -Pn -p 22,80,443,445,3389 172.16.5.10
proxychains evil-winrm -i 172.16.5.10 -u admin -p Password123
proxychains smbclient -L //172.16.5.10 -U admin
proxychains ssh user@172.16.5.10
proxychains curl http://172.16.5.10/
proxychains crackmapexec smb 172.16.5.0/24
```

---

## SSH SOCKS Proxy Setup

```bash
# Create SOCKS5 proxy through SSH pivot host
ssh -D 1080 -N -f user@10.129.14.128

# Dynamic port forward + keep alive
ssh -D 1080 -N -f -o ServerAliveInterval=60 user@10.129.14.128

# Add to proxychains.conf:
# socks5 127.0.0.1 1080
```

---

## Double Pivot (Chaining Proxies)

```bash
# /etc/proxychains4.conf
dynamic_chain
proxy_dns

[ProxyList]
socks5 127.0.0.1 1080    # first hop (attacker → pivot1)
socks5 127.0.0.1 1081    # second hop (pivot1 → pivot2)
```

---

## Quiet Mode (Suppress Output)

```bash
# -q flag suppresses proxychains banner lines
proxychains -q nmap -sT -Pn 172.16.5.10
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
