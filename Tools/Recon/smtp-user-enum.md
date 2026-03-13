# smtp-user-enum

**Tags:** `#smtp-user-enum` `#smtp` `#smtpattack` `#enumeration` `#userenum`

SMTP user enumeration tool. Uses VRFY, EXPN, and RCPT TO commands to identify valid users on an SMTP server. Effective against older mail servers and misconfigured relays that respond differently to valid vs. invalid users.

**Source:** http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum
**Install:** `sudo apt install smtp-user-enum`

```bash
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 10.129.14.128
```

> [!note]
> Try all three methods (VRFY, EXPN, RCPT) — server behavior varies. RCPT TO is most universally supported. Verify results manually with `telnet` or `nc` to confirm the server responds differently for valid vs. invalid users.

---

## Enumeration Methods

| Method | Command | Description |
|--------|---------|-------------|
| `VRFY` | `VRFY user` | Directly verify if user exists |
| `EXPN` | `EXPN alias` | Expand mailing list/alias |
| `RCPT` | `RCPT TO:<user@domain>` | Test recipient — most reliable |

---

## Usage

```bash
# VRFY method
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 10.129.14.128

# EXPN method
smtp-user-enum -M EXPN -U /usr/share/seclists/Usernames/Names/names.txt -t 10.129.14.128

# RCPT method (specify domain)
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt \
  -t 10.129.14.128 -D inlanefreight.htb

# Single username test
smtp-user-enum -M VRFY -u admin -t 10.129.14.128

# Custom port
smtp-user-enum -M VRFY -U users.txt -t 10.129.14.128 -p 587

# Increase threads
smtp-user-enum -M VRFY -U users.txt -t 10.129.14.128 -T 20
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-M <method>` | VRFY, EXPN, or RCPT |
| `-U <file>` | Username wordlist |
| `-u <user>` | Single username |
| `-t <IP>` | Target host |
| `-p <port>` | SMTP port (default 25) |
| `-D <domain>` | Domain for RCPT method |
| `-T <n>` | Threads (default 5) |
| `-v` | Verbose |

---

## Manual Verification

```bash
# Test VRFY manually
nc -nv 10.129.14.128 25

HELO test
VRFY root           # valid user → "250 root@hostname"
VRFY fakeuser       # invalid → "550 User unknown"
EXPN postmaster
```

---

## Wordlists

```bash
/usr/share/seclists/Usernames/Names/names.txt
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
