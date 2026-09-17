# Patator

**Tags:** `#patator` `#bruteforce` `#passwordattack` `#auth` `#spray` `#multiprotocol` `#userenum` `#credentialstuffing` `#ridcycling` `#offlinecracking`

Multi-purpose brute-forcer with a modular, flexible design. The main advantage over Hydra/Medusa is granular control over request logic and response filtering — you define exactly what counts as a hit or miss using regex on the response. Excellent for HTTP forms, custom applications, and any case where simple success/fail matching is too crude.

**Source:** https://github.com/lanjelot/patator
**Install:** `sudo apt install patator` — pre-installed on Kali

```bash
# List all available modules
patator --help

# Get help for a specific module
patator ssh_login --help
patator http_fuzz --help
```

> [!note] **Patator vs Hydra/Medusa** — Use Patator when you need fine-grained response filtering (regex match/ignore on body, headers, status codes) or when Hydra/Medusa mishandle a target's responses. It's more verbose to set up but much more reliable against custom login forms and anti-brute-force responses.

---

## Core Syntax

Patator uses `FILE0`, `FILE1`, etc. as positional placeholders that map to `0=wordlist.txt` arguments.

```bash
patator <module> <module_options> 0=<wordlist> -x ignore:<filter>
```

**Common ignore filters:**

| Filter | Meaning |
|---|---|
| `-x ignore:code=200` | Ignore HTTP 200 responses (fail = 200, success = redirect) |
| `-x ignore:mesg='Login failed'` | Ignore responses containing this string |
| `-x ignore:fgrep='Invalid password'` | Fast string match (no regex) |
| `-x ignore:size=1234` | Ignore responses of this byte size |
| `-x ignore:egrep='(failed\|error\|invalid)'` | Regex match |

> [!tip] **Calibrate before you filter.** Run patator once with **no `-x`** and read the results table — every attempt prints its `code` and `size`. The failures all share one code/size; that's what you feed to `-x ignore:`. The hit is the row that breaks the pattern. Getting the filter right is the whole skill with patator — don't guess it, observe it. Combine conditions within one action with a comma (**both** must match): `-x ignore:code=302,fgrep='Location: /home.html'`; use multiple `-x` for OR: `-x ignore:code=200 -x ignore:fgrep='CSRF'`. To **terminate the whole run** on the first hit use `-x quit:code=302`; `-x free=user:code=302` instead stops testing more passwords **for that one user** (per-value early-exit, like Hydra's `-f`) and moves on. Valid conditions: `code`, `size`, `time`, `mesg`, `fgrep`, `egrep` — **`time`** matches response latency (`time=3-`), the lever for timing-based user enumeration when the body is identical on hit and miss.

---

## Payload Sets — More Than Wordlists

The `0=`, `1=`, … arguments aren't only files. This is patator's real edge over Hydra/Medusa — the payload **keyword** decides how each set is *generated*, and every attempt is one point in the **product of all sets** (so the `--start`/`--stop` offsets below index across all of them):

| Keyword | `N=` source | Generates | Reach for it when |
|---|---|---|---|
| `FILE0` | `0=words.txt` (glob ok) | lines of a file | ordinary wordlists |
| `COMBO00:COMBO01` | `0=creds.txt` | `user:pass` per line (`-C` sets the delimiter) | cred-stuffing / harvested creds |
| `RANGE0` | `0=int:500-2000` | numeric / `hex:` / letter ranges — **no file** | RID cycling, PINs, OTPs, numeric IDs |
| `NET0` | `0=10.0.0.0/24` | every host in a CIDR | turning patator into a *host* sweeper |
| `PROG0` | `0='crunch 4 4 0123456789'` | stdout of an external generator | masks (crunch / maskprocessor), on-the-fly candidates |
| `MOD0` | `0=TLD` | module-provided list | module-specific payloads (e.g. dns TLDs) |

```bash
# RID cycling over SMB/LSA — the canonical RANGE example (verified in patator's own source)
patator smb_lookupsid host=10.10.10.10 sid=S-1-5-21-1234567890-1234567890-1234567890 \
  rid=RANGE0 0=int:500-2000 -x ignore:code=1

# Numeric brute (PIN / OTP / sequential token) — no wordlist on disk
patator http_fuzz url=http://t/verify method=POST body='code=RANGE0' 0=int:000000-999999 \
  -x ignore:fgrep='Invalid'

# Host sweep — the target host IS the payload (CIDR expands to every address)
patator ssh_login host=NET0 0=10.10.10.0/24 user=root password=Winter2026 \
  -x ignore:mesg='Authentication failed'

# Mask-based candidates piped from a generator (no giant wordlist file)
patator ssh_login host=10.10.10.10 user=admin password=PROG0 0='crunch 6 6 -t Pass@%' \
  -x ignore:mesg='Authentication failed'

# Cred-stuffing from a user:pass dump
patator ssh_login host=10.10.10.10 user=COMBO00 password=COMBO01 0=creds.txt        # ':' default
patator ssh_login host=10.10.10.10 user=COMBO00 password=COMBO01 0=creds.txt -C '|'
```

> [!tip] `RANGE`/`NET`/`PROG` mean patator often needs **no wordlist on disk at all** — generate the space inline and stream it. Ideal for numeric/masked spaces (a rockyou-sized file would be pointless) and for turning a login brute-forcer into a subnet sweeper.

---

## SSH

```bash
# Username + password list
patator ssh_login host=10.10.10.10 user=root password=FILE0 0=/usr/share/wordlists/rockyou.txt \
  -x ignore:mesg='Authentication failed'

# User list + password list
patator ssh_login host=10.10.10.10 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt \
  -x ignore:mesg='Authentication failed'

# Non-standard port
patator ssh_login host=10.10.10.10 port=2222 user=admin password=FILE0 0=passwords.txt \
  -x ignore:mesg='Authentication failed'
```

---

## FTP

```bash
patator ftp_login host=10.10.10.10 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt \
  -x ignore:mesg='Login incorrect'
```

---

## HTTP Form (POST)

```bash
# Basic login form — ignore responses containing the failure string
patator http_fuzz url=http://10.10.10.10/login.php method=POST \
  body='username=FILE0&password=FILE1' \
  0=users.txt 1=passwords.txt \
  -x ignore:fgrep='Invalid credentials'

# Ignore by HTTP status code (success = 302 redirect, fail = 200)
patator http_fuzz url=http://10.10.10.10/login.php method=POST \
  body='user=FILE0&pass=FILE1' \
  0=users.txt 1=passwords.txt \
  -x ignore:code=200

# Per-request CSRF token — a STATIC token will not work (it rotates each load).
# Let patator fetch the form first (before_urls), scrape the token (before_egrep),
# substitute it into a marker, and carry the session cookie (accept_cookie=1):
patator http_fuzz url=http://10.10.10.10/login method=POST \
  body='username=FILE0&password=FILE1&csrf_token=_CSRF_' \
  before_urls=http://10.10.10.10/login \
  before_egrep='_CSRF_:name="csrf_token" value="([^"]+)"' \
  accept_cookie=1 \
  0=users.txt 1=passwords.txt \
  -x ignore:fgrep='Wrong password'
# before_egrep syntax = MARKER:regex — group(1) of the regex replaces MARKER in
# the body/header/query. Chain multiple with '|'. follow=1 chases redirects.
```

---

## HTTP Basic Auth

```bash
patator http_fuzz url=http://10.10.10.10/admin/ \
  user_pass=FILE0:FILE1 \
  0=users.txt 1=passwords.txt \
  -x ignore:code=401
```

---

## SMB

```bash
patator smb_login host=10.10.10.10 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt \
  -x ignore:mesg='STATUS_LOGON_FAILURE'
```

---

## MySQL / MSSQL

```bash
# MySQL
patator mysql_login host=10.10.10.10 user=root password=FILE0 0=passwords.txt \
  -x ignore:fgrep='Access denied'

# MSSQL
patator mssql_login host=10.10.10.10 user=sa password=FILE0 0=passwords.txt \
  -x ignore:fgrep='Login failed'
```

---

## DNS Subdomain Enumeration

```bash
patator dns_forward domain=FILE0.target.com 0=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -x ignore:code=NXDOMAIN
```

---

## Useful Options

```bash
# Threads (default: 10)
patator ssh_login ... -t 4                      # or --threads=4

# Delay between attempts — helps avoid lockouts. --rate-limit is in SECONDS (float), not ms
patator ssh_login ... --rate-limit=0.5          # ~0.5s between each attempt

# Give up on a payload after N connection errors/retries (default 4; -1 = unlimited)
patator ssh_login ... --max-retries=2

# Stop after the first hit — there is NO --max-hits; use a quit action
patator ssh_login ... -x quit:mesg='Authentication succeeded'

# Save output / results (logging is a DIR/FILE, not --log-file):
patator ssh_login ... -l /tmp/patator_ssh       # -l DIR    → dir of output + full response data
patator ssh_login ... -L run1                   # -L SFX    → auto DIR/yyyy-mm-dd/hh:mm:ss_SFX
patator ssh_login ... -R results.txt            # -R FILE   → save console output to one file
patator ssh_login ... --hits=creds.txt          # --hits    → just the FOUND candidates (what you want)
patator ssh_login ... --csv=out.csv             # --csv / --xml → structured results for parsing
patator ssh_login ... --auto-progress=30        # print progress + resume offsets every 30s
```

> [!warning] **Fabricated-flag check (corrected here):** `--sleep`, `--tries`, `--max-hits`, and `--log-file` are **not** patator options. Verified against `patator ssh_login --help` on Kali — the real ones are `--rate-limit` (seconds), `--max-retries`, `-x quit:`, and `-l`/`-L`/`-R`/`--hits`/`--csv`/`--xml`.

### Resume a long / interrupted run

Every attempt is an offset into the product of all payload sets, so you can checkpoint and restart without redoing work:

```bash
patator ssh_login ... --start=5000               # skip the first 5000 combinations
patator ssh_login ... --stop=10000               # stop at offset 10000 (window a run)
patator ssh_login ... --resume=1000,2000,3000    # resume: per-thread offsets printed at ^C
```

Patator prints the resume offsets when interrupted (`^C`) — paste them straight into `--resume`.

### Payload encoding (`-e`)

Transform a payload inline — for apps that expect a hashed/encoded value, not the raw password. Encode everything between two tags (`_@@_`, `T@G`, any unique string); encodings: `hex`, `unhex`, `b64`, `md5`, `sha1`, `url`:

```bash
# a form that posts md5(password): wrap the payload in tags, then -e tag:encoding
patator http_fuzz url=... body='user=FILE0&pass=_@@_FILE1_@@_' -e _@@_:md5 0=u.txt 1=p.txt
# -e _@@_:b64 for Base-64, -e _@@_:url for percent-encoding, etc.
```

(Combo files for cred-stuffing use the `COMBO00:COMBO01` keyword — see **Payload Sets** above.)

### User enumeration (not just brute-force)

Patator has dedicated **enumeration** modules that confirm valid usernames from a target's differential responses — reach for these *before* spraying:

```bash
patator smtp_vrfy host=10.10.10.10 user=FILE0 0=users.txt -x ignore:fgrep='User unknown'   # SMTP VRFY
patator smtp_rcpt host=10.10.10.10 user=FILE0@target.com 0=users.txt helo='ehlo x' \
  -x ignore:code=550                                                                        # SMTP RCPT TO
patator finger_lookup host=10.10.10.10 user=FILE0 0=users.txt -x ignore:mesg='no such user' # Finger
```

Beyond the modules shown above, `patator` also ships network brute modules `telnet_login`, `pop_login`, `imap_login`, `ldap_login`, `rdp_login`/`rdp_gateway`, `vnc_login`, `oracle_login`, `pgsql_login`, `snmp_login`, `dcom_login`, and `ike_enum` — same `FILE0/FILE1` + `-x ignore:` pattern throughout.

> [!note] **Offline crackers too — no network needed.** `unzip_pass`, `keystore_pass`, and `sqlcipher_pass` brute the password of a captured **zip / Java keystore / SQLCipher DB** locally. Handy on loot when you don't want to `*2john` → hashcat, and the natural follow-up to a password-protected archive pulled during pillaging (see [[Tools/File Transfer/7-Zip|7-Zip]] for `.7z`/`.zip` cracking via `7z2john -m 11600` — patator's `unzip_pass` is the zip-only, no-GPU alternative).

```bash
# brute a password-protected zip found in loot
patator unzip_pass zipfile=secret.zip password=FILE0 0=rockyou.txt -x ignore:mesg='incorrect'
```

---

> [!note] **See also** — faster to set up but cruder on filtering: [[Tools/Auth/Hydra|Hydra]] and [[Tools/Auth/Medusa|Medusa]]; for SMB/WinRM/MSSQL spraying at scale prefer [[Tools/Lateral Movement/NetExec|NetExec]]. Reach for patator when those mishandle a target's responses. Technique context: [[Class notes/HTB Academy/CPTS v2 (claude)/Password Attacks|Password Attacks]] and [[Class notes/HTB Academy/CPTS v2 (claude)/Login Brute Forcing|Login Brute Forcing]] (patator is the tool of choice there for CSRF-token forms Hydra/Medusa can't handle).

---

*Created: 2026-03-06*
*Updated: 2026-09-01*
*Model: claude-opus-5*
