# John the Ripper

**Tags:** `#john` `#jtr` `#johntheripper` `#passwordcracking` `#hashcracking` `#auth`

Offline password cracker supporting hundreds of hash types. Best used for cracking hashes obtained from target systems — `/etc/shadow`, SAM dumps, captured NTLMs, protected files. Jumbo version (standard on Kali) includes all community patches and format support.

**Source:** https://www.openwall.com/john/
**Formats reference:** https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats
**Install:** pre-installed on Kali (`john`) — use `john --list=formats` to see all supported formats

> [!note] **JTR vs Hashcat** — Use JTR for the 2john file extraction workflow (SSH keys, ZIP, KeePass, Office docs, etc.) and quick single/wordlist runs. Use hashcat when you need GPU acceleration for bulk cracking — hashcat is significantly faster on large hash dumps. Both tools are complementary, not interchangeable.

---

## Common Wordlist Paths (Kali)

```
/usr/share/wordlists/rockyou.txt          # standard starting point
/usr/share/wordlists/fasttrack.txt        # smaller, common passwords
/usr/share/seclists/Passwords/            # SecLists password collections
/usr/share/seclists/Passwords/Leaked-Databases/
/usr/share/john/password.lst              # JTR built-in wordlist
```

---

## Cracking Modes

### Single Crack Mode

JTR's fastest mode — derives candidates from the username, GECOS field, and home directory in the hash file. Run this first before touching a wordlist. Often cracks weak/default passwords in seconds.

```bash
john --single hashes.txt
john --single --format=NT hashes.txt
```

> [!tip] For this to work well, the hash file must include the username. Format: `username:hash`. Secretsdump and unshadow output already include this.

### Wordlist Mode

```bash
# Basic wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Wordlist + rules (mutates entries on the fly — significantly increases coverage)
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=jumbo hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=KoreLogic hashes.txt

# List available rulesets
john --list=rules

# Pipe a custom wordlist from stdin
cat custom.txt | john --pipe --rules hashes.txt
```

### Incremental (Brute Force) Mode

```bash
john --incremental hashes.txt            # default character set
john --incremental=alpha hashes.txt      # letters only
john --incremental=digits hashes.txt     # digits only
john --incremental=alnum hashes.txt      # alphanumeric
```

### Loopback Mode

Uses the pot file (previously cracked passwords) as a wordlist against new hashes. Essential mid-engagement — when you crack creds from one dump, try them immediately against others.

```bash
john --loopback hashes.txt
john --loopback --rules hashes.txt       # also apply rules to pot entries
```

---

## Basic Commands

```bash
# Auto-detect format and crack
john hashes.txt

# Specify format explicitly (more reliable than auto-detect)
john --format=NT hashes.txt

# Show cracked passwords
john --show hashes.txt
john --show --format=NT hashes.txt       # specify format if auto-detect fails

# Multi-core — fork across CPU cores
john --fork=4 --wordlist=rockyou.txt hashes.txt

# Check status mid-run (or press Enter while running)
john --status

# Use a per-engagement pot file (keeps client results separate)
john --pot=./client.pot --wordlist=rockyou.txt hashes.txt
john --show --pot=./client.pot hashes.txt
```

> [!note] Results saved to `~/.john/john.pot` by default. Already-cracked hashes are skipped on re-run — use `--show` to view them. Clear with `> ~/.john/john.pot` to re-crack.

---

## Session Management

```bash
# Start a named session (survives interruption)
john --session=client1 --wordlist=rockyou.txt hashes.txt

# Restore a session
john --restore=client1

# List active/saved sessions
ls ~/.john/*.rec
```

---

## File-to-Hash Extraction (2john Tools)

Convert protected files into a crackable hash before running john.

```bash
# SSH private key
ssh2john id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash

# ZIP archive
zip2john archive.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash

# RAR archive
rar2john archive.rar > rar.hash
john --wordlist=/usr/share/wordlists/rockyou.txt rar.hash

# PDF
pdf2john document.pdf > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pdf.hash

# Office documents (Word, Excel, PowerPoint 2007+)
office2john Protected.docx > office.hash
john --wordlist=/usr/share/wordlists/rockyou.txt office.hash

# KeePass database
keepass2john Database.kdbx > keepass.hash
john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash

# PuTTY private key
putty2john private.ppk > putty.hash
john --wordlist=/usr/share/wordlists/rockyou.txt putty.hash

# PFX / PKCS#12 certificate
pfx2john cert.pfx > pfx.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pfx.hash

# TrueCrypt volume
truecrypt_volume2john volume.tc > tc.hash

# WPA/WPA2 handshake
hccap2john capture.hccap > wpa.hash

# VNC captured auth (PCAP)
vncpcap2john capture.pcap > vnc.hash

# OS X keychain
keychain2john login.keychain > keychain.hash

# MS Cache (domain cached credentials DCC2)
mscash2john cache.txt > mscash.hash
```

---

## Common Pentest Scenarios

### Linux Shadow File

```bash
# Combine passwd + shadow, then crack
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --single unshadowed.txt                                         # try single mode first
john --wordlist=/usr/share/wordlists/rockyou.txt --rules unshadowed.txt
```

### Windows NTLM Hashes

```bash
# Hashes from secretsdump, mimikatz, hashdump — format: user:RID:LM:NT:::
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
john --format=NT --rules --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
```

### NTLMv2 (Responder / Inveigh Captures)

```bash
john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt ntlmv2.txt
```

### Kerberos Hashes

```bash
# Kerberoasting (TGS-REP hashes from GetUserSPNs / Rubeus)
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt spn_hashes.txt

# ASREPRoasting (AS-REP hashes from GetNPUsers / Rubeus)
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt
```

### MS Domain Cached Credentials (DCC2)

```bash
# Cached domain creds stored locally on Windows — very slow to crack
john --format=mscash2 --wordlist=/usr/share/wordlists/rockyou.txt dcc2.txt
```

### Database Hashes

```bash
john --format=mssql hashes.txt
john --format=mssql05 hashes.txt
john --format=mysql-sha1 hashes.txt
john --format=oracle11 hashes.txt
```

---

## Format Reference

| Format | Hash Type |
|---|---|
| `NT` | Windows NTLM |
| `netntlmv2` | NTLMv2 (Responder captures) |
| `netntlm` | NTLMv1 |
| `krb5tgs` | Kerberoasting (TGS-REP) |
| `krb5asrep` | ASREPRoasting (AS-REP) |
| `mscash2` | MS Domain Cached Credentials v2 |
| `sha512crypt` | Linux SHA-512 (`$6$`) |
| `sha256crypt` | Linux SHA-256 (`$5$`) |
| `md5crypt` | Linux MD5 (`$1$`) |
| `bcrypt` | bcrypt (`$2a$`, `$2b$`) |
| `raw-md5` | Unsalted MD5 |
| `raw-sha1` | Unsalted SHA1 |
| `raw-sha256` | Unsalted SHA256 |
| `raw-sha512` | Unsalted SHA512 |
| `mssql` | MS SQL Server |
| `mssql05` | MS SQL Server 2005 |
| `mysql-sha1` | MySQL |
| `oracle11` | Oracle 11g |
| `LM` | LAN Manager (legacy Windows) |
| `mschapv2` | MS-CHAPv2 |
| `pdf` | PDF password |
| `zip` | ZIP password |
| `rar` | RAR password |
| `ssh` | SSH private key passphrase |
| `office` | MS Office 2007+ |
| `keepass` | KeePass database |
| `vncpcap` | VNC captured auth |
| `pfx` | PKCS#12 / PFX certificate |

```bash
# List all supported formats
john --list=formats

# Search formats by keyword
john --list=formats | grep -i kerberos
john --list=formats | grep -i sha
```

---

## Recommended Attack Order

```
1. john --single                          # fast — try username-derived passwords first
2. john --wordlist=rockyou.txt            # straight wordlist
3. john --wordlist=rockyou.txt --rules    # wordlist + mutations
4. john --loopback --rules                # try already-cracked passwords + mutations
5. john --wordlist=<bigger list> --rules  # escalate to larger wordlists (SecLists)
6. john --incremental                     # last resort brute force
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
