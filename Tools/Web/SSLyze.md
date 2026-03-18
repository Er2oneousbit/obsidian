# SSLyze

**Tags:** `#sslyze` `#ssl` `#tls` `#certificates` `#web` `#compliance`

Python SSL/TLS scanner. Analyzes SSL/TLS configuration of a server — supported protocols, cipher suites, certificate chain validity, HSTS, OCSP stapling, heartbleed, robot, and other vulnerabilities. Fast, scriptable, and produces structured JSON output. Best choice when you need programmatic SSL analysis.

**Source:** https://github.com/nabla-c0d3/sslyze
**Install:** `pip install sslyze` or `sudo apt install python3-sslyze`

```bash
sslyze target.com
```

> [!note]
> SSLyze vs testssl.sh: SSLyze is Python-based, JSON output, good for scripting and CI pipelines. testssl.sh is a bash script with more human-readable output and broader checks. Both cover the same core ground — use whichever fits your workflow. For quick checks, testssl.sh is faster to read; for automation, SSLyze JSON is cleaner.

---

## Basic Usage

```bash
# Scan single target
sslyze target.com

# With explicit port
sslyze target.com:8443

# Multiple targets
sslyze target1.com target2.com

# JSON output (for scripting/reporting)
sslyze target.com --json_out results.json

# STARTTLS (SMTP, IMAP, etc.)
sslyze --starttls smtp target.com:587
sslyze --starttls imap target.com:143
sslyze --starttls ftp target.com:21
sslyze --starttls xmpp target.com:5222
sslyze --starttls postgres target.com:5432
sslyze --starttls ldap target.com:389
```

---

## Specific Scan Types

```bash
# Check for Heartbleed (CVE-2014-0160)
sslyze target.com --heartbleed

# Check for ROBOT (Return of Bleichenbacher's Oracle Threat)
sslyze target.com --robot

# Check for CCS injection (OpenSSL CVE-2014-0224)
sslyze target.com --openssl_ccs

# Check for CRIME (compression)
sslyze target.com --compression

# Session renegotiation
sslyze target.com --reneg

# Session resumption
sslyze target.com --resumption

# HSTS
sslyze target.com --http_headers

# Certificate transparency
sslyze target.com --certinfo
```

---

## Run All Checks

```bash
# Full scan (all plugins)
sslyze target.com --regular

# Equivalent to:
sslyze target.com \
  --certinfo \
  --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 \
  --heartbleed \
  --robot \
  --openssl_ccs \
  --reneg \
  --resumption \
  --compression \
  --http_headers
```

---

## Protocol-Specific Scans

```bash
# Check specific protocol support
sslyze target.com --sslv2       # SSLv2 (should be disabled)
sslyze target.com --sslv3       # SSLv3 (POODLE — should be disabled)
sslyze target.com --tlsv1       # TLSv1.0 (deprecated)
sslyze target.com --tlsv1_1     # TLSv1.1 (deprecated)
sslyze target.com --tlsv1_2     # TLSv1.2 (acceptable)
sslyze target.com --tlsv1_3     # TLSv1.3 (preferred)

# Results show accepted cipher suites for each protocol
```

---

## Python API

```python
# Programmatic scanning
import json
from sslyze import ServerNetworkLocation, Scanner, ServerScanRequest
from sslyze.plugins.scan_commands import ScanCommand

server = ServerNetworkLocation("target.com", 443)
request = ServerScanRequest(
    server_location=server,
    scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES,
                   ScanCommand.HEARTBLEED, ScanCommand.ROBOT}
)

scanner = Scanner()
scanner.queue_scans([request])
for result in scanner.get_results():
    # Process results
    if result.scan_result.heartbleed.is_vulnerable_to_heartbleed:
        print(f"HEARTBLEED: {result.server_location.hostname}")
    cert_info = result.scan_result.certificate_info
    print(cert_info.certificate_deployments[0].verified_certificate_chain[0].not_valid_after)
```

---

## Key Findings to Report

```
Vulnerable:
- SSLv2/SSLv3 supported → POODLE/DROWN
- TLSv1.0/1.1 supported → deprecated protocols
- Heartbleed → CVE-2014-0160
- ROBOT → Bleichenbacher oracle
- CCS injection → CVE-2014-0224
- NULL cipher suites → no encryption
- EXPORT cipher suites → FREAK/LOGJAM
- RC4 cipher suites → weak cipher
- Weak DH params (<2048 bit) → LOGJAM

Certificate issues:
- Expired certificate
- Self-signed certificate
- Hostname mismatch
- Weak signature algorithm (SHA-1, MD5)
- Missing HSTS header
- Short validity period
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
