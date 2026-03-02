#SMTP #SimpleMailTransferProtocol #email

## What is SMTP?
Simple Mail Transfer Protocol — used to send email between mail servers and from clients to servers. Plaintext by default; STARTTLS or SMTPS add encryption.

- Port **TCP 25** — server-to-server (MTA), often blocked on consumer ISPs
- Port **TCP 587** — authenticated client submission (STARTTLS)
- Port **TCP 465** — SMTPS (SSL/TLS wrapped, older standard)
- MUAs (mail clients) use 587; MTAs relay on 25
- Can be used for user enumeration and phishing/relay abuse

---

## SMTP Commands

| Command | Description |
|---|---|
| `HELO <hostname>` | Identify client to server (basic) |
| `EHLO <hostname>` | Extended HELLO — list supported extensions |
| `AUTH PLAIN` | Authenticate client (base64 encoded) |
| `MAIL FROM:<addr>` | Specify sender |
| `RCPT TO:<addr>` | Specify recipient |
| `DATA` | Begin message body (end with `.` on its own line) |
| `VRFY <user>` | Check if mailbox exists (often disabled) |
| `EXPN <list>` | Expand mailing list to member addresses |
| `RSET` | Abort current transmission, keep connection |
| `NOOP` | Keep-alive / check connection |
| `QUIT` | End session |

---

## Enumeration

### Banner Grab

```bash
nc -nv <target> 25
telnet <target> 25
```

### User Enumeration via VRFY

```bash
telnet 10.10.110.20 25
EHLO test
VRFY root
# 252 = exists, 550 = doesn't exist
```

### User Enumeration via EXPN

```bash
EXPN john
# 250 = exists + shows real address
EXPN support-team
# may expand a list to multiple addresses
```

### User Enumeration via RCPT TO

```bash
MAIL FROM:test@test.com
RCPT TO:john
# 250 = exists, 550 = unknown user
```

### Automated User Enumeration

```bash
# smtp-user-enum
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <target>
smtp-user-enum -M RCPT -U users.txt -D domain.com -t <target>

# o365spray (Office 365)
python3 o365spray.py --enum -U users.txt --domain target.com

# Metasploit
use auxiliary/scanner/smtp/smtp_enum
```

### NMAP

```bash
nmap -p 25,465,587 --script smtp-commands,smtp-enum-users,smtp-open-relay -sV <target>

# NTLM info disclosure — leaks domain name, hostname, DNS info from NTLM challenge
nmap -p 25 --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=domain.com <target>
```

### NTLM Auth Info Disclosure

When a server supports NTLM authentication, it discloses internal info without credentials.

```bash
# Manual — trigger NTLM challenge via AUTH NTLM
telnet <target> 25
EHLO test
AUTH NTLM
TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=
# Server returns base64 NTLM challenge — decode to reveal:
# - NetBIOS domain name
# - NetBIOS computer name
# - DNS domain name
# - DNS hostname

# Decode NTLM challenge
echo "TlRMTVNTUAAC..." | base64 -d | strings
```

---

## Send Email / Phishing with swaks

```bash
# Basic send (test relay / phishing)
swaks --from notifications@inlanefreight.com \
      --to employees@inlanefreight.com \
      --header 'Subject: Company Notification' \
      --body 'Click here: http://phishing.com/' \
      --server 10.10.11.213

# With auth
swaks --from attacker@domain.com \
      --to target@domain.com \
      --server mail.target.com \
      --port 587 \
      --auth LOGIN \
      --auth-user user@domain.com \
      --auth-password 'Password123' \
      --tls \
      --header 'Subject: Test' \
      --body 'Body text'

# With attachment
swaks --to target@domain.com \
      --from attacker@domain.com \
      --server 10.10.110.20 \
      --attach @/path/to/file.pdf \
      --header 'Subject: Invoice'
```

---

## Open Relay Testing

```bash
# Test if server will relay for external domains
nmap -p 25 --script smtp-open-relay -v <target>

# Manual test
telnet <target> 25
EHLO test
MAIL FROM:<external@gmail.com>
RCPT TO:<target@gmail.com>  # if 250, it's an open relay
DATA
.
QUIT
```

---

## Connect with TLS

```bash
# STARTTLS upgrade
openssl s_client -starttls smtp -connect <target>:587
openssl s_client -starttls smtp -connect <target>:25

# Direct TLS (SMTPS)
openssl s_client -connect <target>:465
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Open relay (`mynetworks` too broad) | Spam/phishing vector |
| `VRFY` / `EXPN` enabled | User enumeration |
| Plaintext auth on port 25 | Credential interception |
| No SPF/DKIM/DMARC records | Email spoofing |
| Auth not required for relay | Spam abuse |

---

## Quick Reference

| Goal | Command |
|---|---|
| Banner grab | `nc -nv host 25` |
| User enum (VRFY) | `smtp-user-enum -M VRFY -U users.txt -t host` |
| User enum (RCPT) | `smtp-user-enum -M RCPT -U users.txt -D domain -t host` |
| Send phishing email | `swaks --from x --to y --server host --body 'url'` |
| Open relay check | `nmap -p 25 --script smtp-open-relay host` |
| TLS connect | `openssl s_client -starttls smtp -connect host:587` |
| Nmap enum | `nmap -p 25,587 --script smtp-commands,smtp-enum-users` |
