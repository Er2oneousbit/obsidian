# openssl (CLI)

**Tags:** `#openssl` `#ssl` `#tls` `#certificates` `#web` `#crypto`

OpenSSL command-line tool for SSL/TLS inspection, certificate analysis, encrypted connections, and cryptographic operations. Used in pentesting to inspect certificates for information disclosure, test for weak ciphers/protocols, establish encrypted connections, and generate certificates/keys for shells and payloads.

**Install:** Pre-installed on Kali — `openssl version`

```bash
openssl s_client -connect target.com:443
```

> [!note]
> For comprehensive SSL/TLS audit use testssl.sh or SSLyze — they're faster and more automated. Use openssl directly for quick certificate inspection, manual cipher testing, and generating keys/certs for payloads (socat TLS shells, self-signed certs for C2, etc.).

---

## SSL/TLS Inspection

```bash
# Connect and inspect certificate
openssl s_client -connect target.com:443

# Show only certificate info
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text

# Certificate expiry only
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -noout -dates

# Subject / issuer / SANs
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -noout -subject -issuer

# Subject Alternative Names (SANs — find additional hostnames)
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative"

# Save certificate to file
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 > cert.pem
```

---

## Protocol & Cipher Testing

```bash
# Test specific SSL/TLS version
openssl s_client -connect target.com:443 -ssl2        # SSLv2 (very old)
openssl s_client -connect target.com:443 -ssl3        # SSLv3 (POODLE)
openssl s_client -connect target.com:443 -tls1        # TLSv1.0
openssl s_client -connect target.com:443 -tls1_1      # TLSv1.1
openssl s_client -connect target.com:443 -tls1_2      # TLSv1.2
openssl s_client -connect target.com:443 -tls1_3      # TLSv1.3

# Test specific cipher
openssl s_client -connect target.com:443 -cipher RC4-MD5
openssl s_client -connect target.com:443 -cipher NULL-MD5

# List available ciphers
openssl ciphers -v 'ALL:eNULL'

# List weak/deprecated ciphers
openssl ciphers -v 'LOW:EXPORT'
```

---

## Manual HTTP over SSL

```bash
# Send HTTP request manually over SSL connection
openssl s_client -connect target.com:443 -quiet
# Type after connection:
GET / HTTP/1.0
Host: target.com
[blank line]

# Non-interactive
echo -e "GET / HTTP/1.0\r\nHost: target.com\r\n\r\n" | \
  openssl s_client -connect target.com:443 -quiet 2>/dev/null

# STARTTLS (SMTP, FTP, LDAP)
openssl s_client -connect smtp.target.com:587 -starttls smtp
openssl s_client -connect ftp.target.com:21 -starttls ftp
openssl s_client -connect ldap.target.com:389 -starttls ldap
```

---

## Certificate Operations

```bash
# View certificate file
openssl x509 -in cert.pem -noout -text
openssl x509 -in cert.pem -noout -subject -issuer -dates

# Convert DER to PEM
openssl x509 -in cert.der -inform DER -out cert.pem

# Convert PEM to DER
openssl x509 -in cert.pem -outform DER -out cert.der

# Extract cert from PKCS#12 (.pfx/.p12)
openssl pkcs12 -in cert.pfx -nokeys -out cert.pem
openssl pkcs12 -in cert.pfx -nocerts -nodes -out key.pem

# View private key
openssl rsa -in key.pem -noout -text

# Check if cert and key match
openssl x509 -in cert.pem -noout -modulus | md5sum
openssl rsa -in key.pem -noout -modulus | md5sum
# (must match)
```

---

## Generate Keys & Certificates

```bash
# Generate RSA private key
openssl genrsa -out key.pem 2048
openssl genrsa -out key.pem 4096

# Generate self-signed certificate
openssl req -new -x509 -key key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"

# One-liner: generate key + self-signed cert
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"

# For socat TLS shell (see socat.md)
openssl req -newkey rsa:2048 -nodes -keyout shell.key \
  -x509 -days 362 -out shell.crt
cat shell.key shell.crt > shell.pem
```

---

## Abusing a cert-renewal script (near-expiry cert)

A privileged cron/script that auto-renews TLS certs is a privesc vector: it runs `openssl` **as root**, only acts when the current cert is close to expiry, and frequently **parses the cert's subject/email fields** to rebuild the new one. Two things to weaponise: (1) hand it a cert that's *already* about to expire so the renewal branch fires, and (2) put a payload in a subject field it parses — see [[Class notes/HTB Academy/CPTS v2 (claude)/Command Injection|Command Injection]].

```bash
# Self-signed cert valid for exactly ONE day — reads as "expiring" immediately.
# 2048 (not 4096) so it generates instantly; -nodes so there's no passphrase prompt.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /path/to/host.key -out /path/to/host.crt -days 1 \
  -subj "/C=AT/ST=Vienna/L=Vienna/O=Org/OU=IT/CN=host.htb/emailAddress=a@host.htb"

# Confirm it registers as expiring. checkend N = "will it expire within N seconds?"
openssl x509 -in /path/to/host.crt -noout -checkend 86400; echo "exit=$?"
#   exit 1 = yes, expires within a day  →  a `[ $? -eq 0 ]` guard in the script FAILS
#                                          →  the renewal branch RUNS (this is what you want)
```

| Flag | Why it's there |
|---|---|
| `-x509` | Emit a self-signed **certificate**, not a CSR — `openssl x509` can't parse a signing request |
| `-newkey rsa:2048` | Generate the key in the same invocation; 2048 keeps it instant |
| `-nodes` | "no DES" — leave the key unencrypted, so no interactive passphrase prompt |
| `-days 1` | The point: the cert is near-expiry the moment it exists |
| `-subj "…"` | Set the whole DN non-interactively — **and** the field a renewal parser reads, i.e. where an injection payload goes |

> [!warning] **Test field-parsing on the target, not on Kali — the subject format is OpenSSL-version-dependent.** OpenSSL **3.x** prints `subject=C=AT, ST=Vienna` (no spaces around `=`); OpenSSL **1.1.1** (Debian 11) prints `C = AT, ST = Vienna` (spaces). A script that greps `'C = .{2}'` works on the box but silently matches **nothing** on a modern openssl — so field extraction that looks broken on your Kali will behave differently on-target. Check `openssl version` on the target and reproduce there, or you'll chase a phantom.

> [!note] **`-checkend <seconds>` exit codes** — returns **0** if the cert is *still valid* past that window, **1** if it *will expire* within it. A `-days 1` cert answers "expiring" to any `-checkend` ≥ ~86400. This is the branch a renewal script keys off.

> [!note] **Timing** — if the script wipes the cert dir each cycle (e.g. `rm -r .../Certs/*`), your cert must be in place *before* the next run. Watch the file to learn the interval (see it disappear), then drop the cert in during the window. Related: [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]].

---

## Encoding / Crypto Operations

```bash
# Base64 encode
echo -n "string" | openssl base64
openssl base64 -in file.bin -out file.b64

# Base64 decode
echo "c3RyaW5n" | openssl base64 -d
openssl base64 -d -in file.b64 -out file.bin

# Hash
echo -n "password" | openssl dgst -md5
echo -n "password" | openssl dgst -sha256
openssl dgst -sha256 file.bin

# Symmetric encryption (AES)
openssl enc -aes-256-cbc -in file.txt -out file.enc -k password
openssl enc -d -aes-256-cbc -in file.enc -out file.dec -k password

# Generate random bytes
openssl rand -hex 32         # 32 random bytes as hex
openssl rand -base64 32      # as base64
```

---

## OCSP / Revocation Check

```bash
# Check certificate revocation status
openssl s_client -connect target.com:443 -status </dev/null 2>/dev/null | \
  grep -A 17 'OCSP response'
```

---

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Email/SMTP|SMTP]] — `s_client -starttls smtp` for STARTTLS on 25/587 and direct TLS on 465, to reach an authenticated session or inspect the mail server's certificate; [[Services/File Xfer/FTP|FTP]] — `s_client -starttls ftp` (explicit FTPS on 21) / `-connect host:990` (implicit), to negotiate and inspect the FTPS certificate.

---

*Created: 2026-03-13*
*Updated: 2026-08-21*
*Model: claude-opus-5*
