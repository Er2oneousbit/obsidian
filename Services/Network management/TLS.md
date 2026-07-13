#TLS #SSL #cryptography #certificates #ciphers #protocols

## What is TLS?
Transport Layer Security — cryptographic protocol providing confidentiality, integrity, and authentication over TCP. Successor to SSL (deprecated). Relevant to almost every service: HTTPS, SMTPS, LDAPS, IMAPS, MSSQL, MySQL, RDP, etc.

- **TLS 1.3** — current standard (2018), forward secrecy mandatory
- **TLS 1.2** — widely deployed, acceptable with strong ciphers
- **TLS 1.1 / 1.0** — deprecated (RFC 8996, 2021), vulnerable to BEAST, POODLE
- **SSL 3.0 / 2.0** — broken, POODLE/DROWN attacks

Common ports using TLS:

| Port | Service |
|---|---|
| 443 | HTTPS |
| 465 | SMTPS |
| 587 | SMTP+STARTTLS |
| 636 | LDAPS |
| 993 | IMAPS |
| 995 | POP3S |
| 1433 | MSSQL (TLS) |
| 3306 | MySQL (TLS) |
| 3389 | RDP (TLS) |
| 5986 | WinRM/HTTPS |

---

## testssl.sh

Comprehensive TLS/SSL testing tool. Tests protocols, ciphers, vulnerabilities, certificates.

```bash
# Install
git clone https://github.com/drwetter/testssl.sh
cd testssl.sh

# Full scan
./testssl.sh https://<target>
./testssl.sh <target>:443

# Non-HTTP service
./testssl.sh <target>:993    # IMAPS
./testssl.sh <target>:25     # SMTP with STARTTLS
./testssl.sh --starttls smtp <target>:25
./testssl.sh --starttls ftp  <target>:21

# Specific checks
./testssl.sh --protocols <target>:443           # protocol support only
./testssl.sh --ciphers <target>:443             # cipher enumeration
./testssl.sh --vulnerable <target>:443          # vuln checks only
./testssl.sh --server-defaults <target>:443     # cert + server info
./testssl.sh --headers <target>:443             # HTTP security headers

# Output
./testssl.sh --jsonfile output.json <target>:443
./testssl.sh --htmlfile output.html <target>:443
./testssl.sh --logfile output.log <target>:443

# Pentest-relevant flags
./testssl.sh --fast <target>:443               # skip time-intensive tests
./testssl.sh --severity HIGH <target>:443      # only HIGH/CRITICAL findings
./testssl.sh -U <target>:443                   # all vulnerabilities
```

---

## sslyze

Python-based TLS scanner. Faster than testssl for targeted checks. Good for scripting/automation.

```bash
# Install
pip install sslyze
# or
apt install python3-sslyze

# Basic scan
sslyze <target>
sslyze <target>:993

# Specific plugins
sslyze --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 <target>   # protocol support
sslyze --certinfo <target>                       # certificate info
sslyze --reneg <target>                          # renegotiation
sslyze --resum <target>                          # session resumption
sslyze --robot <target>                          # ROBOT attack check
sslyze --heartbleed <target>                     # Heartbleed
sslyze --fallback <target>                       # TLS_FALLBACK_SCSV

# JSON output
sslyze --json_out output.json <target>

# Multiple targets
sslyze <target1> <target2>:8443
```

---

## openssl

Built-in SSL/TLS testing — manual and scriptable.

```bash
# Basic connection
openssl s_client -connect <target>:443
openssl s_client -connect <target>:443 </dev/null   # non-interactive

# With SNI (required for vhost-based TLS)
openssl s_client -connect <target>:443 -servername <domain>

# Force specific protocol
openssl s_client -connect <target>:443 -ssl3      # SSLv3
openssl s_client -connect <target>:443 -tls1      # TLSv1.0
openssl s_client -connect <target>:443 -tls1_1    # TLSv1.1
openssl s_client -connect <target>:443 -tls1_2    # TLSv1.2
openssl s_client -connect <target>:443 -tls1_3    # TLSv1.3

# Force specific cipher
openssl s_client -connect <target>:443 -cipher RC4-SHA
openssl s_client -connect <target>:443 -cipher NULL-SHA

# STARTTLS (non-HTTP services)
openssl s_client -connect <target>:25  -starttls smtp
openssl s_client -connect <target>:21  -starttls ftp
openssl s_client -connect <target>:143 -starttls imap
openssl s_client -connect <target>:110 -starttls pop3
openssl s_client -connect <target>:389 -starttls ldap

# Certificate info
openssl s_client -connect <target>:443 </dev/null 2>/dev/null | openssl x509 -noout -text
openssl s_client -connect <target>:443 </dev/null 2>/dev/null | openssl x509 -noout -dates
openssl s_client -connect <target>:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer

# List all supported ciphers (brute-force test)
for cipher in $(openssl ciphers 'ALL:eNULL' | tr ':' ' '); do
  result=$(echo Q | openssl s_client -cipher $cipher -connect <target>:443 2>&1)
  if echo "$result" | grep -q "Cipher is"; then
    echo "SUPPORTED: $cipher"
  fi
done

# Check cert expiry
openssl s_client -connect <target>:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -enddate

# Verify cert chain
openssl s_client -connect <target>:443 -verify 5 </dev/null 2>&1 | grep -i "verify\|depth"
```

---

## curl

Quick TLS checks without full scanner.

```bash
# Test connection + show cert
curl -vvI https://<target> 2>&1 | grep -E "SSL|TLS|cipher|cert|expire"

# Ignore cert errors (self-signed)
curl -k https://<target>

# Force TLS version
curl --tlsv1.0 --tls-max 1.0 https://<target>   # TLS 1.0 only
curl --tlsv1.1 --tls-max 1.1 https://<target>   # TLS 1.1 only
curl --tlsv1.2 https://<target>                  # TLS 1.2+
curl --tlsv1.3 https://<target>                  # TLS 1.3 only

# Force specific cipher
curl --ciphers RC4-SHA https://<target>
curl --ciphers NULL-SHA https://<target>

# Show cert details
curl -vvI https://<target> 2>&1 | grep -A 20 "Server certificate"

# Check security headers in response
curl -sI https://<target> | grep -iE "strict|x-frame|x-content|csp|hsts"
```

---

## nmap

```bash
# TLS/SSL enum scripts
nmap -p 443 --script ssl-enum-ciphers <target>
nmap -p 443 --script ssl-cert <target>
nmap -p 443 --script ssl-dh-params <target>       # weak DH params
nmap -p 443 --script ssl-heartbleed <target>       # Heartbleed
nmap -p 443 --script ssl-poodle <target>           # POODLE
nmap -p 443 --script ssl-ccs-injection <target>    # CCS injection
nmap -p 443 --script ssl-known-key <target>        # known compromised keys

# Run all SSL scripts
nmap -p 443 --script "ssl-*" <target>

# Non-standard ports
nmap -p 8443,993,995,465 --script ssl-enum-ciphers <target>
```

---

## Common Vulnerabilities

| Vuln | Affected | Tool to check |
|---|---|---|
| POODLE | SSLv3 / TLS CBC | `testssl.sh -U` / `nmap --script ssl-poodle` |
| BEAST | TLS 1.0 CBC | `testssl.sh --vulnerable` |
| CRIME | TLS compression | `testssl.sh --vulnerable` |
| BREACH | HTTP compression | `testssl.sh --breach` |
| Heartbleed | OpenSSL 1.0.1a-f | `nmap --script ssl-heartbleed` / `sslyze --heartbleed` |
| ROBOT | RSA PKCS#1 v1.5 | `sslyze --robot` / `testssl.sh -R` |
| DROWN | SSLv2 on any cert | `testssl.sh --drown` |
| FREAK | Export-grade RSA | `testssl.sh --vulnerable` |
| LOGJAM | Weak DH (<1024 bit) | `nmap --script ssl-dh-params` |
| Ticketbleed | F5 session tickets | `testssl.sh --ticketbleed` |
| Sweet32 | 64-bit block ciphers (3DES) | `testssl.sh --sweet32` |
| RC4 | RC4 cipher suites | `testssl.sh --rc4` |

---

## Certificate Checks

```bash
# Expiry
openssl s_client -connect <target>:443 </dev/null 2>/dev/null | openssl x509 -noout -enddate

# Subject Alt Names (SANs) — reveals internal hostnames, other domains
openssl s_client -connect <target>:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative"

# Wildcard certs — scope of cert
openssl s_client -connect <target>:443 </dev/null 2>/dev/null | openssl x509 -noout -subject

# Self-signed check
openssl s_client -connect <target>:443 -verify 5 </dev/null 2>&1 | grep "self signed"

# CT logs for subdomain enumeration (cert transparency)
curl -s "https://crt.sh/?q=%25.<domain>&output=json" | python3 -m json.tool | grep "name_value"
```

---

## HTTP Security Headers

```bash
curl -sI https://<target> | grep -iE "strict-transport|x-frame|x-content-type|content-security|referrer|permissions"
```

| Header | Expected Value |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | Restrictive CSP policy |
| `Referrer-Policy` | `no-referrer` or `strict-origin` |

---

## Quick Reference

| Goal | Command |
|---|---|
| Full TLS scan | `./testssl.sh host:443` |
| Vuln check only | `./testssl.sh -U host:443` |
| sslyze quick | `sslyze host` |
| openssl connect | `openssl s_client -connect host:443 -servername domain` |
| Force TLS 1.0 | `openssl s_client -connect host:443 -tls1` |
| STARTTLS SMTP | `openssl s_client -connect host:25 -starttls smtp` |
| Cert expiry | `openssl s_client -connect host:443 </dev/null 2>/dev/null \| openssl x509 -noout -enddate` |
| SANs | `openssl x509 -noout -text \| grep -A1 "Subject Alternative"` |
| Cipher enum (nmap) | `nmap -p 443 --script ssl-enum-ciphers host` |
| CT log subdomains | `curl -s "https://crt.sh/?q=%.domain&output=json"` |

---

## Windows / PowerShell

### Check TLS Protocol Support (.NET)

```powershell
# Check current .NET TLS settings
[Net.ServicePointManager]::SecurityProtocol

# Set allowed protocols (useful for testing what works)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Force connection with specific TLS version
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls   # TLS 1.0
Invoke-WebRequest -Uri https://<target>
```

### Invoke-WebRequest / Invoke-RestMethod

```powershell
# Basic HTTPS request (ignoring cert errors)
Invoke-WebRequest -Uri https://<target> -SkipCertificateCheck

# Check response headers (security headers)
$r = Invoke-WebRequest -Uri https://<target>
$r.Headers

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri https://<target>
```

### Test-NetConnection

```powershell
# Check if TLS port is open + reachable
Test-NetConnection -ComputerName <target> -Port 443
Test-NetConnection -ComputerName <target> -Port 8443

# Check multiple ports
443,8443,993,995,465 | ForEach-Object { Test-NetConnection -ComputerName <target> -Port $_ }
```

### certutil

```powershell
# Retrieve and display remote certificate
certutil -verify -urlfetch https://<target>/

# Decode a local cert file
certutil -dump cert.cer
certutil -dump cert.pem

# Check cert store
certutil -store "Root"   # Trusted Root CAs
certutil -store "My"     # Personal certs
```

### SChannel Registry (Check Enabled Protocols on Target — Post-Access)

```powershell
# View SChannel protocol settings
$base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
Get-ChildItem $base -Recurse | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($props) { Write-Host $_.PSPath; $props }
}

# Check if TLS 1.0 is enabled (Server side)
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -ErrorAction SilentlyContinue

# Check if SSLv3 is disabled
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -ErrorAction SilentlyContinue
# Disabled = Enabled DWORD = 0
```

### Check Cipher Suites (Post-Access)

```powershell
# List enabled TLS cipher suites on Windows system
Get-TlsCipherSuite | Select-Object Name, Exchange, Cipher, Hash | Format-Table

# Filter for weak ciphers
Get-TlsCipherSuite | Where-Object { $_.Cipher -match "RC4|3DES|NULL|EXPORT" }
Get-TlsCipherSuite | Where-Object { $_.Hash -match "MD5" }

# Check if a specific cipher is enabled
Get-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_SHA"
```

### PowerShell TLS Handshake Test (Manual)

```powershell
# Test TLS connection and get cert details
$tcpClient = New-Object Net.Sockets.TcpClient("<target>", 443)
$sslStream = New-Object Net.Security.SslStream($tcpClient.GetStream(), $false, { $true })
$sslStream.AuthenticateAsClient("<target>")

# Get cert info
$cert = $sslStream.RemoteCertificate
Write-Host "Subject:    $($cert.Subject)"
Write-Host "Issuer:     $($cert.Issuer)"
Write-Host "Expiry:     $($cert.GetExpirationDateString())"
Write-Host "Protocol:   $($sslStream.SslProtocol)"
Write-Host "Cipher:     $($sslStream.CipherAlgorithm)"
Write-Host "Hash:       $($sslStream.HashAlgorithm)"
Write-Host "Key Ex:     $($sslStream.KeyExchangeAlgorithm)"

$tcpClient.Close()
```

### IIS Crypto (GUI — Recommended for Auditing Windows Servers)

```
# IIS Crypto — free tool by Nartac Software
# https://www.nartac.com/Products/IISCrypto
# Shows and configures: protocols, ciphers, hashes, key exchange
# Templates: Best Practices, PCI, FIPS 140-2
# Run on the target server post-access or use as reference for misconfig findings
```

---

## PowerShell — Automated Protocol & Cipher Testing

### Protocol Version Scanner

Tests SSL2/SSL3/TLS1.0/1.1/1.2/1.3 against a remote target. Each attempt uses a dedicated `SslStream` with a forced protocol.

```powershell
function Test-TLSProtocols {
    param(
        [string]$Target,
        [int]$Port = 443
    )

    $protocols = [ordered]@{
        "SSL 2.0" = [System.Security.Authentication.SslProtocols]::Ssl2
        "SSL 3.0" = [System.Security.Authentication.SslProtocols]::Ssl3
        "TLS 1.0" = [System.Security.Authentication.SslProtocols]::Tls
        "TLS 1.1" = [System.Security.Authentication.SslProtocols]::Tls11
        "TLS 1.2" = [System.Security.Authentication.SslProtocols]::Tls12
        "TLS 1.3" = [System.Security.Authentication.SslProtocols]::Tls13
    }

    Write-Host "`n[*] Testing $Target`:$Port`n"

    foreach ($name in $protocols.Keys) {
        try {
            $tcp = New-Object Net.Sockets.TcpClient($Target, $Port)
            $ssl = New-Object Net.Security.SslStream(
                $tcp.GetStream(), $false,
                [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
            )
            $ssl.AuthenticateAsClient($Target, $null, $protocols[$name], $false)
            Write-Host "[+] $name`tSUPPORTED`t(Cipher: $($ssl.CipherAlgorithm) $($ssl.CipherStrength)-bit, Hash: $($ssl.HashAlgorithm), KeyEx: $($ssl.KeyExchangeAlgorithm))" -ForegroundColor Green
            $ssl.Close(); $tcp.Close()
        } catch {
            $reason = $_.Exception.InnerException.Message ?? $_.Exception.Message
            Write-Host "[-] $name`tNOT SUPPORTED`t($reason)" -ForegroundColor Red
        }
    }
}

# Usage
Test-TLSProtocols -Target "target.com" -Port 443
Test-TLSProtocols -Target "mail.target.com" -Port 993
```

### Full Recon — Protocols + Certificate Info

```powershell
function Invoke-TLSRecon {
    param(
        [string]$Target,
        [int]$Port = 443
    )

    # --- Certificate info via TLS 1.2 ---
    try {
        $tcp = New-Object Net.Sockets.TcpClient($Target, $Port)
        $ssl = New-Object Net.Security.SslStream(
            $tcp.GetStream(), $false,
            [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
        )
        $ssl.AuthenticateAsClient($Target, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)

        Write-Host "`n=== Certificate ===" -ForegroundColor Cyan
        Write-Host "Subject:    $($cert.Subject)"
        Write-Host "Issuer:     $($cert.Issuer)"
        Write-Host "Valid From: $($cert.NotBefore)"
        Write-Host "Valid To:   $($cert.NotAfter)"
        Write-Host "Thumbprint: $($cert.Thumbprint)"
        Write-Host "Self-Signed: $(if ($cert.Subject -eq $cert.Issuer) { 'YES' } else { 'no' })"

        # SANs — reveals internal hostnames and other domains
        $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
        if ($san) { Write-Host "SANs:       $($san.Format($false))" }

        $ssl.Close(); $tcp.Close()
    } catch {
        Write-Host "[!] Could not retrieve certificate: $_" -ForegroundColor Yellow
    }

    # --- Protocol sweep ---
    Write-Host "`n=== Protocol Support ===" -ForegroundColor Cyan
    Test-TLSProtocols -Target $Target -Port $Port

    # --- Security headers (HTTPS only) ---
    if ($Port -in @(443, 8443)) {
        Write-Host "`n=== Security Headers ===" -ForegroundColor Cyan
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $r = Invoke-WebRequest -Uri "https://$Target`:$Port/" -SkipCertificateCheck -UseBasicParsing -ErrorAction Stop
            $headers = @("Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Content-Security-Policy","Referrer-Policy")
            foreach ($h in $headers) {
                $val = $r.Headers[$h]
                if ($val) { Write-Host "[+] $h`: $val" -ForegroundColor Green }
                else       { Write-Host "[-] $h`: MISSING" -ForegroundColor Red }
            }
        } catch {
            Write-Host "[!] HTTP request failed: $_" -ForegroundColor Yellow
        }
    }
}

# Usage
Invoke-TLSRecon -Target "target.com" -Port 443
```

### Cipher Enumeration — Limitation + Workarounds

> [!note]
> .NET's `SslStream` does not let you specify which cipher to use per-connection. The OS/SChannel negotiates the cipher automatically. For remote cipher enumeration from Windows, use one of the following:

**Option 1 — nmap (works on Windows natively)**

```powershell
# nmap ssl-enum-ciphers script
nmap -p 443 --script ssl-enum-ciphers <target>
nmap -p 443,8443,993,995 --script ssl-enum-ciphers <target>
```

**Option 2 — testssl.sh via WSL**

```powershell
# Run testssl from WSL (if WSL is installed)
wsl ./testssl.sh <target>:443
wsl ./testssl.sh --ciphers <target>:443
wsl ./testssl.sh -U <target>:443   # vulnerabilities only
```

**Option 3 — openssl.exe (Windows binary)**

```powershell
# If openssl.exe is available (e.g. Git Bash, OpenSSL for Windows)
# Cipher brute-force loop via PowerShell + openssl.exe
$ciphers = & openssl.exe ciphers 'ALL:eNULL' | ForEach-Object { $_ -split ':' }
foreach ($cipher in $ciphers) {
    $result = echo Q | & openssl.exe s_client -cipher $cipher -connect "${Target}:${Port}" 2>&1
    if ($result -match "Cipher is") {
        Write-Host "[+] SUPPORTED: $cipher" -ForegroundColor Green
    }
}
```

**Option 4 — Enumerate locally configured ciphers (post-access on target)**

```powershell
# What cipher suites is THIS machine configured to offer?
Get-TlsCipherSuite | Select-Object Name, Exchange, Cipher, Hash | Format-Table -AutoSize

# Flag weak ciphers
Get-TlsCipherSuite | Where-Object {
    $_.Name -match "RC4|3DES|NULL|EXPORT|anon|MD5|DES"
} | Select-Object Name | Format-Table
```

### Scan Multiple Targets

```powershell
# Feed a list of hosts
$targets = @("host1.com","host2.com:8443","10.10.10.5:993")

foreach ($entry in $targets) {
    $parts = $entry -split ":"
    $host  = $parts[0]
    $port  = if ($parts.Count -gt 1) { [int]$parts[1] } else { 443 }
    Write-Host "`n=============================" -ForegroundColor Yellow
    Write-Host " Target: $host`:$port" -ForegroundColor Yellow
    Write-Host "=============================" -ForegroundColor Yellow
    Test-TLSProtocols -Target $host -Port $port
}
```
