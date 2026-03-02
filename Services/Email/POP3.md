#POP3 #PostOfficeProtocol #email

## What is POP3?
Post Office Protocol v3 — retrieves email from a server. Downloads and (typically) deletes mail from the server. Simpler than IMAP — no folder support, no server-side sync.

- Port **TCP 110** — POP3 (plaintext)
- Port **TCP 995** — POP3S (SSL/TLS)
- One session at a time — no concurrent access

---

## POP3 Commands

| Command | Description |
|---|---|
| `USER <username>` | Identify user |
| `PASS <password>` | Authenticate with password |
| `STAT` | Number of messages and total size |
| `LIST` | List all messages with sizes |
| `LIST <id>` | List specific message size |
| `RETR <id>` | Download message by ID |
| `DELE <id>` | Mark message for deletion |
| `RSET` | Unmark all pending deletes |
| `CAPA` | List server capabilities |
| `TOP <id> <n>` | Fetch headers + first n lines of message |
| `UIDL` | Unique IDs for all messages |
| `UIDL <id>` | Unique ID for specific message |
| `QUIT` | Commit deletes and close connection |

---

## Connect / Access

```bash
# Plaintext
telnet <target> 110
nc -nv <target> 110

# TLS (POP3S)
openssl s_client -connect <target>:995

# STARTTLS upgrade
openssl s_client -starttls pop3 -connect <target>:110
```

### Session Workflow

```
# Connect and authenticate
USER john
+OK

PASS Password123
+OK Logged in

# Check mailbox status
STAT
+OK 3 8712      # 3 messages, 8712 bytes total

# List all messages
LIST
+OK 3 messages
1 2936
2 3452
3 2324

# Read message 1
RETR 1
+OK
<full email content>

# Read just headers + 5 lines
TOP 1 5

# Delete message 2
DELE 2

# Quit (commits deletes)
QUIT
```

---

## Enumeration

```bash
# Nmap
nmap -p 110,995 --script pop3-capabilities,pop3-brute -sV <target>

# Metasploit brute force
use auxiliary/scanner/pop3/pop3_login

# Hydra brute force
hydra -l user@domain.com -P /usr/share/wordlists/rockyou.txt pop3://<target>
hydra -l user@domain.com -P passwords.txt -s 995 -S pop3://<target>  # SSL
```

---

## curl POP3 Access

```bash
# List messages
curl "pop3://<target>" --user user:pass

# Retrieve message 1
curl "pop3://<target>/1" --user user:pass

# TLS
curl -k "pop3s://<target>/1" --user user:pass
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Plaintext on port 110 without TLS | Credentials in cleartext |
| Weak/default credentials | Email access |
| No IP restrictions | Accessible from internet |
| Emails contain sensitive data | Data exposure |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (plaintext) | `telnet host 110` |
| Connect (TLS) | `openssl s_client -connect host:995` |
| Check messages | `STAT` |
| List messages | `LIST` |
| Read message | `RETR 1` |
| Retrieve with curl | `curl "pop3://host/1" --user user:pass` |
| Brute force | `hydra -l user -P rockyou.txt pop3://host` |
| Nmap enum | `nmap -p 110,995 --script pop3-capabilities,pop3-brute` |
