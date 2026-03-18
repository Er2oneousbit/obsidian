# Wordlist Selection Guide

**Tags:** `#wordlists` `#seclists` `#bruteforce` `#fuzzing` `#reference`

Reference for picking the right wordlist for a given task. Most wordlists live in `/usr/share/seclists/` (install: `sudo apt install seclists`) or `/usr/share/wordlists/`. Paths below assume SecLists installation.

**Install SecLists:** `sudo apt install seclists`
**GitHub:** https://github.com/danielmiessler/SecLists

---

## Web — Directory & File Brute Force

| Objective | Wordlist | Notes |
|---|---|---|
| Quick general-purpose | `Discovery/Web-Content/common.txt` | ~4k words, fast |
| Standard directory enum | `Discovery/Web-Content/directory-list-2.3-medium.txt` | ~220k, good balance |
| Thorough directory enum | `Discovery/Web-Content/directory-list-2.3-big.txt` | ~1.2M, slow |
| Directories + extensions | `Discovery/Web-Content/raft-medium-directories.txt` | no extensions, clean |
| Files with extensions | `Discovery/Web-Content/raft-medium-files.txt` | includes extensions |
| Small/fast recon | `Discovery/Web-Content/directory-list-lowercase-2.3-small.txt` | ~87k |
| CMS-agnostic content | `Discovery/Web-Content/big.txt` | 20k balanced |
| Backup/sensitive files | `Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt` | PHP backdoors |
| API endpoints (v1, v2) | `Discovery/Web-Content/api/api-endpoints.txt` | REST paths |
| API objects/endpoints | `Discovery/Web-Content/api/objects.txt` | noun resources |

```bash
# Standard starting point
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -u http://target.com/FUZZ -mc 200,301,302,403

# With extensions
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -u http://target.com/FUZZ.php -mc 200,301
```

---

## Web — Subdomain & DNS Brute Force

| Objective | Wordlist | Notes |
|---|---|---|
| Fast subdomain enum | `Discovery/DNS/subdomains-top1million-5000.txt` | 5k, quick |
| Standard subdomain enum | `Discovery/DNS/subdomains-top1million-20000.txt` | 20k |
| Thorough subdomain enum | `Discovery/DNS/subdomains-top1million-110000.txt` | 110k |
| All possible subdomains | `Discovery/DNS/bitquark-subdomains-top100000.txt` | 100k |
| vHost enumeration | `Discovery/DNS/subdomains-top1million-5000.txt` | same list, Host header |

```bash
# DNS brute force with gobuster
gobuster dns -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# vHost fuzzing with ffuf
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.target.com" -u http://target.com/ -fs 1234
```

---

## Web — Parameter Discovery

| Objective | Wordlist | Notes |
|---|---|---|
| Hidden GET/POST params | `Discovery/Web-Content/burp-parameter-names.txt` | ~6k Burp-sourced |
| Broad parameter fuzzing | `Discovery/Web-Content/raft-large-words.txt` | general words |

```bash
arjun -u http://target.com/api -w \
  /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

---

## Web — Fuzzing / Payload Lists

| Objective | Wordlist | Notes |
|---|---|---|
| XSS payloads | `Fuzzing/XSS/XSS-Jhaddix.txt` | comprehensive XSS list |
| XSS bypass | `Fuzzing/XSS/XSS-bypass-strings.txt` | filter bypass focused |
| SQLi payloads | `Fuzzing/SQLi/Generic-SQLi.txt` | generic SQLi |
| SQLi (Polyglot) | `Fuzzing/SQLi/quick-SQLi.txt` | fast polyglots |
| LFI payloads | `Fuzzing/LFI/LFI-Jhaddix.txt` | comprehensive LFI |
| LFI (Linux files) | `Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` | Linux file targets |
| LFI (Windows files) | `Fuzzing/LFI/LFI-gracefulsecurity-windows.txt` | Windows file targets |
| SSTI payloads | `Fuzzing/template-engines-special-vars.txt` | template injection |
| Open redirect | `Fuzzing/redirect.txt` | redirect payloads |
| General fuzzing | `Fuzzing/fuzz-Bo0oM.txt` | broad multi-purpose |
| Special characters | `Fuzzing/special-chars.txt` | chars for injection |

```bash
# LFI fuzzing with ffuf
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -u "http://target.com/page?file=FUZZ" -fc 200 -fs 1234

# SQLi fuzzing
ffuf -w /usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt \
  -u "http://target.com/search?q=FUZZ" -mr "error|sql|syntax"
```

---

## Passwords — Hash Cracking & Offline Attacks

| Objective | Wordlist | Notes |
|---|---|---|
| General cracking | `/usr/share/wordlists/rockyou.txt` | 14M, the standard |
| Top 10k passwords | `Passwords/Common-Credentials/10k-most-common.txt` | quick wins |
| Top 100k passwords | `Passwords/Common-Credentials/100k-most-common.txt` | broader |
| Default passwords | `Passwords/Default-Credentials/default-passwords.txt` | vendor defaults |
| Leaked passwords | `Passwords/Leaked-Databases/` | breach data (various) |
| Common weak patterns | `Passwords/darkweb2017-top10000.txt` | darkweb leak top 10k |
| Password mutations | Use hashcat rules with rockyou | see below |

```bash
# Standard hash crack
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# With rules (generates variants: Password1, P@ssw0rd, etc.)
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# Quick win — top passwords first
hashcat -m 0 hashes.txt \
  /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
```

---

## Passwords — Online / Login Brute Force

| Objective | Wordlist | Notes |
|---|---|---|
| Web login spray | `Passwords/Common-Credentials/best15.txt` | 15 most common |
| Web login spray | `Passwords/Common-Credentials/top-20-common-SSH-passwords.txt` | SSH-focused |
| SMB / domain spray | `Passwords/Common-Credentials/common-corporate-passwords.txt` | corporate patterns |
| SSH brute force | `Passwords/Common-Credentials/top-20-common-SSH-passwords.txt` | |
| Service passwords | `Passwords/Default-Credentials/` | device-specific |

```bash
# SMB password spray (one password at a time to avoid lockout)
crackmapexec smb targets.txt -u usernames.txt \
  -p /usr/share/seclists/Passwords/Common-Credentials/common-corporate-passwords.txt \
  --continue-on-success
```

---

## Usernames

| Objective | Wordlist | Notes |
|---|---|---|
| Generic usernames | `Usernames/Names/names.txt` | 10k first names |
| Common usernames | `Usernames/top-usernames-shortlist.txt` | 17 most common |
| Unix usernames | `Usernames/cirt-default-usernames.txt` | service accounts |
| Male names | `Usernames/Names/malenames-usa-top1000.txt` | |
| Female names | `Usernames/Names/femalenames-usa-top1000.txt` | |

```bash
# Username enumeration (e.g., SSH, SMTP VRFY)
smtp-user-enum -M VRFY -U \
  /usr/share/seclists/Usernames/Names/names.txt \
  -t target.com
```

---

## Default Credentials

| Objective | Wordlist | Notes |
|---|---|---|
| Web app defaults | `Passwords/Default-Credentials/default-passwords.txt` | |
| Router defaults | `Passwords/Default-Credentials/router-default-passwords.txt` | |
| SSH/Telnet defaults | `Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt` | |
| MSSQL defaults | `Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt` | |
| MySQL defaults | `Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt` | |
| FTP defaults | `Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt` | |
| Tomcat defaults | `Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt` | |
| Combo lists (user:pass) | `Passwords/Default-Credentials/` | many are user:pass format |

```bash
# Hydra with credential combo list
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt \
  ftp://target.com
```

---

## Network Services

| Objective | Wordlist | Notes |
|---|---|---|
| SNMP community strings | `Discovery/SNMP/snmp-onesixtyone.txt` | common communities |
| SNMP community strings | `Discovery/SNMP/common-snmp-community-strings.txt` | broader |
| SNMP (Metasploit style) | `Discovery/SNMP/snmp.txt` | |

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt \
  -i hosts.txt
```

---

## Active Directory / Kerberos

| Objective | Wordlist | Notes |
|---|---|---|
| Username format patterns | `Usernames/Names/names.txt` + script to generate variants | |
| AD password spray | `Passwords/Common-Credentials/common-corporate-passwords.txt` | corp patterns |
| Kerberoasting crack | `/usr/share/wordlists/rockyou.txt` + hashcat rules | |
| AS-REP crack | Same as Kerberoasting | |
| Weak AD passwords | `Passwords/darkweb2017-top10000.txt` | |

```bash
# Kerberoast crack
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# Generate AD username formats from name list
# (firstlast, first.last, flast, f.last)
# Use username-anarchy or custom script
```

---

## Miscellaneous

| Objective | Wordlist | Notes |
|---|---|---|
| Email formats | `Miscellaneous/lang-english.txt` | English words |
| Web extensions | `Discovery/Web-Content/web-extensions.txt` | .php, .asp, .jsp... |
| User agents | `Miscellaneous/User-Agents/` | UA strings |
| File extensions | `Fuzzing/extensions-most-common.fuzz.txt` | |
| HTTP methods | `Fuzzing/http-request-methods.txt` | |
| JWT secrets | `Passwords/Common-Credentials/10k-most-common.txt` | JWT weak secrets |

---

## Quick Reference — Common Paths

```bash
# SecLists root
/usr/share/seclists/

# Key subdirectories
/usr/share/seclists/Discovery/Web-Content/     # web dirs/files
/usr/share/seclists/Discovery/DNS/             # subdomains
/usr/share/seclists/Fuzzing/                   # payloads (SQLi, XSS, LFI)
/usr/share/seclists/Passwords/                 # password lists
/usr/share/seclists/Usernames/                 # username lists
/usr/share/seclists/Discovery/SNMP/            # SNMP communities

# Other key wordlists (non-SecLists)
/usr/share/wordlists/rockyou.txt               # gold standard for cracking
/usr/share/wordlists/rockyou.txt.gz            # compressed version
gunzip /usr/share/wordlists/rockyou.txt.gz

# Custom generated
CeWL → domain-specific wordlists from websites
crunch → pattern/charset-based generation
cupp → targeted personal info wordlists
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
