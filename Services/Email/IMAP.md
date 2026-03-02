#IMAP #InternetMessageAccessProtocol #email

## What is IMAP?
Internet Message Access Protocol — retrieval protocol for accessing email on a server. Leaves mail on the server (unlike POP3). Supports folders, flags, and multiple client synchronization.

- Port **TCP 143** — IMAP (plaintext / STARTTLS)
- Port **TCP 993** — IMAPS (SSL/TLS wrapped)
- Commands are prefixed with a tag (e.g., `1`, `A1`, `TAG1`) for request/response matching

---

## IMAP Commands

| Command | Description |
|---|---|
| `1 LOGIN username password` | Authenticate |
| `1 LIST "" *` | List all mailboxes/folders |
| `1 SELECT INBOX` | Open INBOX (enables message access) |
| `1 UNSELECT INBOX` | Close selected mailbox |
| `1 LSUB "" *` | List subscribed/active folders |
| `1 CREATE "FolderName"` | Create new mailbox |
| `1 DELETE "FolderName"` | Delete mailbox |
| `1 RENAME "OldName" "NewName"` | Rename mailbox |
| `1 FETCH <id> all` | Fetch all data for message |
| `1 FETCH <id> RFC822` | Fetch full raw message |
| `1 FETCH <id> BODY[]` | Fetch message body |
| `1 FETCH <id> ENVELOPE` | Fetch message headers only |
| `1 SEARCH UNSEEN` | Search for unread messages |
| `1 STORE <id> +FLAGS (\Deleted)` | Mark message for deletion |
| `1 CLOSE` | Expunge deleted messages and close |
| `1 LOGOUT` | End session |

---

## Connect / Access

```bash
# Plaintext
telnet <target> 143
nc -nv <target> 143

# TLS (IMAPS)
openssl s_client -connect <target>:993

# STARTTLS upgrade on 143
openssl s_client -starttls imap -connect <target>:143
```

### Session Workflow

```
# Connect and log in
1 LOGIN john Password123

# List folders
1 LIST "" *

# Select inbox
1 SELECT INBOX

# Fetch message 1 (full raw message)
1 FETCH 1 RFC822

# Fetch all messages (headers)
1 FETCH 1:* ENVELOPE

# Fetch specific message body
1 FETCH 3 BODY[]

# Search unread
1 SEARCH UNSEEN

# Logout
1 LOGOUT
```

---

## Enumeration

```bash
# Nmap
nmap -p 143,993 --script imap-capabilities,imap-brute -sV <target>

# Metasploit brute force
use auxiliary/scanner/imap/imap_login

# Hydra brute force
hydra -l user@domain.com -P /usr/share/wordlists/rockyou.txt imap://<target>
hydra -l user@domain.com -P passwords.txt -s 993 -S imap://<target>  # SSL
```

---

## curl IMAP Access

```bash
# List mailboxes
curl -k "imaps://<target>/" --user user:pass

# List INBOX messages
curl -k "imaps://<target>/INBOX" --user user:pass

# Fetch specific message
curl -k "imaps://<target>/INBOX;UID=1" --user user:pass

# Fetch with plaintext
curl "imap://<target>/INBOX" --user user:pass
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Plaintext login on port 143 without STARTTLS | Credential interception |
| Weak or default credentials | Unauthorized mail access |
| No authentication required (anonymous) | Open mail access |
| Sensitive emails left on server | Data exposure if account compromised |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (TLS) | `openssl s_client -connect host:993` |
| Login | `1 LOGIN user pass` |
| List folders | `1 LIST "" *` |
| Open inbox | `1 SELECT INBOX` |
| Read message | `1 FETCH 1 RFC822` |
| List with curl | `curl -k "imaps://host/" --user user:pass` |
| Brute force | `hydra -l user -P rockyou.txt imap://host` |
| Nmap enum | `nmap -p 143,993 --script imap-capabilities,imap-brute` |
