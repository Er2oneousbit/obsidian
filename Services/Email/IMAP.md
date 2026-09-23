# IMAP

#IMAP #InternetMessageAccessProtocol #email

## What is IMAP?

Internet Message Access Protocol — the retrieval protocol for reading email **on** the server (unlike POP3, which downloads and deletes). Supports folders, flags, server-side search, and multi-client sync, so a compromised mailbox is a live, searchable copy of everything the user has — password-reset links, internal docs, VPN configs, org-chart intel.

- Port **TCP 143** — IMAP (plaintext / STARTTLS)
- Port **TCP 993** — IMAPS (SSL/TLS wrapped)
- Commands are prefixed with a client **tag** (e.g. `1`, `A1`, `TAG1`) for request/response matching
- On an engagement it's three things: a **brute/spray** target, a **mail-reading** endpoint once you hold creds, and — via NTLM auth — a **pre-auth internal-name leak**.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | Capabilities, NTLM info leak, brute (`imap-capabilities`/`imap-ntlm-info`/`imap-brute`) |
| [[Tools/Auth/Hydra\|Hydra]] | Online password brute / spray (`imap://`) |
| [[Tools/Payloads & Shells/metasploit\|Metasploit]] | `auxiliary/scanner/imap/imap_login` |
| [[Tools/File Transfer/cURL\|cURL]] | Scripted mailbox listing / message fetch over `imap(s)://` |
| [[Tools/Web/openssl\|openssl]] | `s_client` for IMAPS / STARTTLS, and cert inspection |
| [[Tools/Remote Access/telnet\|telnet]] / [[Tools/Remote Access/Netcat\|Netcat]] | Raw plaintext session on 143 |

---

## Enumeration

```bash
# Capabilities (auth mechanisms, STARTTLS support), NTLM info leak, and brute
nmap -p 143,993 --script imap-capabilities,imap-ntlm-info,imap-brute -sV <target>
```

| Script | What it gives |
|---|---|
| `imap-capabilities` | Advertised `AUTH=` mechanisms + whether `STARTTLS`/`LOGINDISABLED` is set |
| `imap-ntlm-info` | **Pre-auth leak** — NetBIOS name, DNS domain, FQDN, OS build from the NTLM type-2 challenge when `AUTH NTLM` is offered |
| `imap-brute` | Credential guessing over the wire |

```bash
# Manual capability check (mechanisms drive your attack: PLAIN/LOGIN = crackable)
openssl s_client -connect <target>:993 -quiet
a CAPABILITY
```

---

## Connect / Access

```bash
# Plaintext (143)
telnet <target> 143
nc -nv <target> 143

# TLS (IMAPS, 993)
openssl s_client -connect <target>:993

# STARTTLS upgrade on 143
openssl s_client -starttls imap -connect <target>:143
```

### Session workflow

```
1 LOGIN john Password123      # authenticate
1 LIST "" *                   # list folders
1 SELECT INBOX                # open inbox (enables message access)
1 FETCH 1 RFC822              # full raw message
1 FETCH 1:* ENVELOPE          # all headers at once
1 FETCH 3 BODY[]              # one message body
1 SEARCH UNSEEN              # unread
1 LOGOUT
```

### Scripted with cURL

```bash
curl -k "imaps://<target>/" --user user:pass              # list mailboxes
curl -k "imaps://<target>/INBOX" --user user:pass         # list INBOX
curl -k "imaps://<target>/INBOX;UID=1" --user user:pass   # fetch a message
```

### IMAP command reference

| Command | Description |
|---|---|
| `1 LOGIN user pass` | Authenticate |
| `1 LIST "" *` | List all mailboxes/folders |
| `1 LSUB "" *` | List subscribed folders |
| `1 SELECT INBOX` | Open a mailbox for access |
| `1 FETCH <id> RFC822` | Fetch full raw message |
| `1 FETCH <id> BODY[]` | Fetch message body |
| `1 FETCH <id> ENVELOPE` | Headers only |
| `1 SEARCH <criteria>` | e.g. `UNSEEN`, `FROM "x"`, `SUBJECT "vpn"` |
| `1 STORE <id> +FLAGS (\Deleted)` | Mark for deletion |
| `1 CLOSE` / `1 LOGOUT` | Expunge+close / end session |

---

## Attack Vectors

### Brute force / password spray

```bash
hydra -l user@domain.com -P /usr/share/wordlists/rockyou.txt imap://<target>
hydra -l user@domain.com -P passwords.txt -s 993 -S imap://<target>   # SSL
```

IMAP is a classic **spray** target: one password across many mailboxes. Historically the go-to legacy-auth bypass of MFA on **Microsoft 365** — basic-auth IMAP ignored Conditional Access until Microsoft disabled legacy auth. See [[Services/Active Directory/Entra ID|Entra ID]] for the M365 legacy-auth angle.

### NTLM info leak (pre-auth)

If the server offers `AUTH NTLM`, sending an NTLM type-1 returns a type-2 challenge that leaks the internal **NetBIOS name, AD domain, FQDN and OS build** — no credentials needed. `nmap --script imap-ntlm-info` automates it; it's the same disclosure as `smtp-ntlm-info`/`http-ntlm-info` and feeds domain enumeration.

### Plaintext / STARTTLS-strip credential capture

Port 143 `LOGIN` without STARTTLS puts `user`/`pass` on the wire in cleartext — a MITM (or a stripped STARTTLS) hands you the credentials directly. Check `imap-capabilities` for `LOGINDISABLED` (absent = plaintext login allowed).

### Mail looting once authenticated

With creds, the mailbox itself is the loot. Search rather than scroll:

```
1 SELECT INBOX
1 SEARCH SUBJECT "password"
1 SEARCH BODY "vpn"
1 SEARCH FROM "it-support"
```

> [!warning] **Modern IMAP is often OAuth-only.** M365 and Gmail have largely killed basic-auth IMAP — `LOGIN user pass` fails even with valid creds, requiring `AUTHENTICATE XOAUTH2` with a token, or an **app password** if the account still allows one. If password auth is rejected on a cloud tenant, pivot to token/app-password abuse, not more spraying.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Plaintext login on 143 without STARTTLS (`LOGINDISABLED` absent) | Credential interception |
| `AUTH NTLM` offered | Pre-auth internal name/domain disclosure |
| Weak/default/reused credentials | Full mailbox read; spray target |
| Legacy/basic auth enabled on a cloud tenant | MFA bypass via IMAP |
| Sensitive mail retained server-side | Whole-history exposure on account compromise |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (TLS) | `openssl s_client -connect host:993` |
| Capabilities + NTLM leak | `nmap -p 143,993 --script imap-capabilities,imap-ntlm-info host` |
| Login | `1 LOGIN user pass` |
| List folders | `1 LIST "" *` |
| Open inbox | `1 SELECT INBOX` |
| Read message | `1 FETCH 1 RFC822` |
| Search mailbox | `1 SEARCH BODY "password"` |
| List with cURL | `curl -k "imaps://host/" --user user:pass` |
| Brute / spray | `hydra -l user -P rockyou.txt imap://host` |

---

> [!note] **See also** — mail-family siblings [[Services/Email/POP3|POP3]] (download-and-delete retrieval) and [[Services/Email/SMTP|SMTP]] (the send side, user enum, relay); Haraka and other MTAs in [[Services/Email/Haraka|Haraka]]; M365 legacy-auth/spray context in [[Services/Active Directory/Entra ID|Entra ID]].

---

*Created: 2026-07-13*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
