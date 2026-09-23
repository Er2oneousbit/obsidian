# POP3

#POP3 #PostOfficeProtocol #email

## What is POP3?

Post Office Protocol v3 — retrieves email and (by default) **deletes it from the server** after download. Simpler than IMAP: no folders, no server-side search, one session at a time. On an engagement it's a thinner target than IMAP — brute/spray, read whatever mail is still on the server, and capture cleartext creds — but it's still a foothold into a user's mail and a spray surface.

- Port **TCP 110** — POP3 (plaintext / STARTTLS)
- Port **TCP 995** — POP3S (SSL/TLS wrapped)
- One session at a time — no concurrent access
- Because mail is usually pulled and deleted, an active mailbox may be near-empty; the value is often the **credential** (reused elsewhere) as much as the contents.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | Capabilities, NTLM info leak, brute (`pop3-capabilities`/`pop3-ntlm-info`/`pop3-brute`) |
| [[Tools/Auth/Hydra\|Hydra]] | Online password brute / spray (`pop3://`) |
| [[Tools/Payloads & Shells/metasploit\|Metasploit]] | `auxiliary/scanner/pop3/pop3_login` |
| [[Tools/File Transfer/cURL\|cURL]] | Scripted message listing / retrieval over `pop3(s)://` |
| [[Tools/Web/openssl\|openssl]] | `s_client` for POP3S / STARTTLS, and cert inspection |
| [[Tools/Remote Access/telnet\|telnet]] / [[Tools/Remote Access/Netcat\|Netcat]] | Raw plaintext session on 110 |

---

## Enumeration

```bash
# Capabilities (auth mechanisms, STARTTLS/APOP), NTLM info leak, and brute
nmap -p 110,995 --script pop3-capabilities,pop3-ntlm-info,pop3-brute -sV <target>
```

| Script | What it gives |
|---|---|
| `pop3-capabilities` | Advertised capabilities: `STLS` (STARTTLS), `SASL` mechanisms, `USER`, `UIDL`, `APOP` |
| `pop3-ntlm-info` | **Pre-auth leak** — NetBIOS name, DNS domain, FQDN, OS build from the NTLM challenge when `AUTH NTLM` is offered |
| `pop3-brute` | Credential guessing over the wire |

---

## Connect / Access

```bash
# Plaintext (110)
telnet <target> 110
nc -nv <target> 110

# TLS (POP3S, 995)
openssl s_client -connect <target>:995

# STARTTLS upgrade on 110
openssl s_client -starttls pop3 -connect <target>:110
```

### Session workflow

```
USER john
+OK
PASS Password123
+OK Logged in

STAT            # message count + total size  -> "+OK 3 8712"
LIST            # list all messages with sizes
RETR 1          # download message 1 (full content)
TOP 1 5         # headers + first 5 lines (peek without full download)
DELE 2          # mark message 2 for deletion
QUIT            # commits deletes, closes
```

### Scripted with cURL

```bash
curl "pop3://<target>" --user user:pass        # list messages
curl "pop3://<target>/1" --user user:pass      # retrieve message 1
curl -k "pop3s://<target>/1" --user user:pass  # over TLS
```

### POP3 command reference

| Command | Description |
|---|---|
| `USER <name>` / `PASS <pw>` | Two-step plaintext auth |
| `APOP <name> <digest>` | MD5 challenge-response auth (if offered) |
| `STAT` | Message count + total size |
| `LIST [id]` | Message sizes |
| `RETR <id>` | Download a message |
| `TOP <id> <n>` | Headers + first n lines (peek) |
| `UIDL [id]` | Unique message IDs |
| `DELE <id>` / `RSET` | Mark delete / undo pending deletes |
| `CAPA` | Server capabilities |
| `QUIT` | Commit deletes and close |

---

## Attack Vectors

### Brute force / password spray

```bash
hydra -l user@domain.com -P /usr/share/wordlists/rockyou.txt pop3://<target>
hydra -l user@domain.com -P passwords.txt -s 995 -S pop3://<target>   # SSL
```

Spray one password across many accounts to dodge lockout. As with IMAP, basic-auth POP3 was a legacy-auth MFA bypass on **Microsoft 365** before Microsoft disabled it — see [[Services/Active Directory/Entra ID|Entra ID]].

### NTLM info leak (pre-auth)

If `AUTH NTLM` is offered, the NTLM type-2 challenge leaks internal **NetBIOS name, AD domain, FQDN and OS build** with no credentials — `nmap --script pop3-ntlm-info` automates it, same disclosure class as `smtp-ntlm-info`.

### Plaintext credential capture

`USER`/`PASS` on port 110 without `STLS` is fully cleartext; a MITM or STARTTLS-strip captures the password directly. `APOP` (MD5 digest of a server timestamp + secret) avoids sending the plaintext password but is offline-crackable if you capture the challenge and response — and is rarely enabled.

### Mail looting once authenticated

```
STAT          # is there anything left on the server?
LIST
RETR 1        # pull each message; TOP <id> 0 to peek headers first
```

Mail is often already deleted client-side, so treat the **credential** as the primary loot — test it for reuse against SSH/SMB/webmail/VPN.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Plaintext `USER`/`PASS` on 110 without `STLS` | Credentials in cleartext |
| `AUTH NTLM` offered | Pre-auth internal name/domain disclosure |
| Weak/default/reused credentials | Mail access + password-reuse pivot |
| Legacy/basic auth enabled on a cloud tenant | MFA bypass via POP3 |
| Mail retained server-side (no auto-delete) | Data exposure on account compromise |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (plaintext) | `telnet host 110` |
| Connect (TLS) | `openssl s_client -connect host:995` |
| Capabilities + NTLM leak | `nmap -p 110,995 --script pop3-capabilities,pop3-ntlm-info host` |
| Check messages | `STAT` |
| List messages | `LIST` |
| Read message | `RETR 1` |
| Peek headers | `TOP 1 0` |
| Retrieve with cURL | `curl "pop3://host/1" --user user:pass` |
| Brute / spray | `hydra -l user -P rockyou.txt pop3://host` |

---

> [!note] **See also** — mail-family siblings [[Services/Email/IMAP|IMAP]] (leave-on-server retrieval, folders/search) and [[Services/Email/SMTP|SMTP]] (send side, user enum, relay); MTAs in [[Services/Email/Haraka|Haraka]]; M365 legacy-auth/spray context in [[Services/Active Directory/Entra ID|Entra ID]].

---

*Created: 2026-07-13*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
