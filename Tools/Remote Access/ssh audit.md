# ssh-audit

**Tags:** `#ssh-audit` `#ssh` `#sshaudit` `#sshenum` `#enumeration`

SSH server and client security auditing tool. Checks banner, key exchange algorithms, encryption ciphers, MACs, compression, and host key types against known-weak configurations and CVEs. Useful for identifying downgrade attack vectors and misconfigured SSH servers.

**Source:** https://github.com/jtesta/ssh-audit
**Install:** `sudo apt install ssh-audit` or `pip install ssh-audit`

```bash
ssh-audit 10.129.14.128
```

> [!note]
> Use during recon to identify weak algorithms that allow downgrade attacks (e.g., diffie-hellman-group1-sha1 for logjam). Also useful for confirming whether a server is vulnerable to specific CVEs before attempting exploitation.

---

## Basic Usage

```bash
# Audit SSH server (default port 22)
ssh-audit 10.129.14.128

# Custom port
ssh-audit -p 2222 10.129.14.128

# Audit SSH client config
ssh-audit -c             # test local client

# Output to JSON
ssh-audit --json 10.129.14.128

# Verbose
ssh-audit -v 10.129.14.128
```

---

## What It Checks

| Category | Examples |
|----------|---------|
| Banner | Version string, OS disclosure |
| Key Exchange | diffie-hellman-group1-sha1 (weak), curve25519 (good) |
| Ciphers | arcfour (broken), aes256-gcm (good), 3des-cbc (weak) |
| MACs | hmac-md5 (weak), hmac-sha2-256 (good) |
| Host Keys | RSA 1024-bit (weak), ED25519 (good) |
| Compression | zlib (timing oracle risk) |
| CVEs | Lists applicable CVEs by version |

---

## Reading Output

```
# Color coding:
# Green  → secure / recommended
# Yellow → legacy / info only
# Red    → weak / deprecated — attack surface

# Key fields to note:
(rec)  → recommended to enable
(dep)  → deprecated, should be disabled
(warn) → weak, upgrade if possible
(fail) → broken, must be disabled
```

---

## Identifying Attack Vectors

```bash
# Check for weak key exchange (downgrade / logjam)
ssh-audit 10.129.14.128 | grep -i "diffie\|kex\|fail\|warn"

# Check cipher weaknesses
ssh-audit 10.129.14.128 | grep -i "cipher\|enc\|fail"

# Extract CVE list
ssh-audit --json 10.129.14.128 | jq '.cves[]'

# Check version banner for known vulns
ssh-audit 10.129.14.128 | grep -i "banner\|openssh"
```

---

## Brute Force / Auth (not ssh-audit — use these instead)

```bash
# Hydra SSH brute force
hydra -l root -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt \
  ssh://10.129.14.128

# Medusa
medusa -h 10.129.14.128 -u root -P rockyou.txt -M ssh

# Kerbrute (for AD accounts via SSH)
# Use crackmapexec / netexec for SMB-based user validation
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
